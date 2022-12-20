use std::{net::SocketAddr, sync::Arc, time::SystemTime};

use super::{listener_table::PipeTable, ObfsUdpSecret};
use crate::{
    crypt::{triple_ecdh, ObfsAead, SymmetricFromAsymmetric},
    pipe::obfs_udp::{frame::HandshakeFrame, recfilter::REPLAY_FILTER, ObfsUdpPipe},
    utilities::sockets::{new_udp_socket_bind, MyUdpSocket},
    Pipe, PipeListener,
};
use async_trait::async_trait;
use bytes::Bytes;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use smol::channel::{Receiver, Sender};

/// A listener for obfuscated UDP pipes.
pub struct ObfsUdpListener {
    recv_new_pipes: Receiver<ObfsUdpPipe>,
    _task: smol::Task<()>,
}

#[async_trait]
impl PipeListener for ObfsUdpListener {
    async fn accept_pipe(&self) -> std::io::Result<Arc<dyn Pipe>> {
        let pipe = self
            .accept()
            .await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::BrokenPipe, e.to_string()))?;
        Ok(Arc::new(pipe))
    }
}

impl ObfsUdpListener {
    /// Constructor.
    pub fn bind(listen: SocketAddr, server_long_sk: ObfsUdpSecret) -> std::io::Result<Self> {
        let socket = new_udp_socket_bind(listen)?;
        let (send_new_pipes, recv_new_pipes) = smol::channel::bounded(1000);
        let task = smolscale::spawn(async move {
            if let Err(err) = listener_loop(
                socket.clone(),
                send_new_pipes,
                server_long_sk.to_public().0,
                server_long_sk.0,
            )
            .await
            {
                log::error!("Oh no! The listener loop has died with an error {:?}", err);
            }
        });
        Ok(Self {
            recv_new_pipes,

            _task: task,
        })
    }

    pub async fn accept(&self) -> anyhow::Result<ObfsUdpPipe> {
        let p = self.recv_new_pipes.recv().await?;
        log::debug!("ACCEPTED a pipe");
        Ok(p)
    }
}

async fn listener_loop(
    socket: MyUdpSocket,
    send_new_pipes: Sender<ObfsUdpPipe>,
    server_long_pk: x25519_dalek::PublicKey,
    server_long_sk: x25519_dalek::StaticSecret,
) -> anyhow::Result<()> {
    let cookie = SymmetricFromAsymmetric::new(server_long_pk);
    let init_dec = ObfsAead::new(&cookie.generate_c2s());
    let init_enc = ObfsAead::new(&cookie.generate_s2c());

    // make table and token key
    let mut table = PipeTable::new(socket.clone());
    let token_key = {
        let mut b = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut b);
        b
    };

    loop {
        let mut buf = [0u8; 2048];
        let (n, client_addr) = socket.recv_from(&mut buf).await?;
        let pkt = &buf[..n];
        log::trace!("received a pkt!");
        if let Err(err) = table.try_forward(pkt, client_addr).await {
            log::debug!("cannot forward packet from {client_addr} to an existing session ({err}), so decrypting as handshake");
            // handshake time!
            match init_dec.decrypt(pkt) {
                Ok(ptext) => {
                    log::debug!("it really was a handshake!");
                    if REPLAY_FILTER.lock().recently_seen(&ptext) {
                        log::warn!("skipping packet catched by the replay filter!");
                        continue;
                    }
                    if let Ok(msg) = stdcode::deserialize::<HandshakeFrame>(&ptext) {
                        match msg {
                            HandshakeFrame::ClientHello {
                                long_pk,
                                eph_pk,
                                version,
                                timestamp,
                            } => {
                                let current_timestamp = SystemTime::now()
                                    .duration_since(SystemTime::UNIX_EPOCH)
                                    .unwrap()
                                    .as_secs();
                                log::debug!("my time {current_timestamp}, their time {timestamp}");
                                if current_timestamp.abs_diff(timestamp) > 10 {
                                    log::warn!("time too skewed, so skipping");
                                    continue;
                                }

                                let server_eph_sk =
                                    x25519_dalek::StaticSecret::new(rand::thread_rng());

                                // make token
                                let shared_secret =
                                    triple_ecdh(&server_long_sk, &server_eph_sk, &long_pk, &eph_pk);

                                let token = TokenInfo {
                                    sess_key: Bytes::copy_from_slice(shared_secret.as_bytes()),
                                    init_time_ms: timestamp,
                                    version,
                                };
                                let encrypted_token = token.encrypt(&token_key);
                                let resp = HandshakeFrame::ServerHello {
                                    long_pk: server_long_pk,
                                    eph_pk: (&server_eph_sk).into(), // this is possible because PublicKey implements From<&E
                                    resume_token: encrypted_token,
                                };
                                socket
                                    .send_to(
                                        &init_enc.encrypt(&stdcode::serialize(&resp)?),
                                        client_addr,
                                    )
                                    .await?;
                            }
                            HandshakeFrame::ServerHello { .. } => {
                                log::warn!(
                                    "some stupid client at {} sent us a server hello",
                                    client_addr
                                );
                            }
                            HandshakeFrame::ClientResume {
                                resume_token,
                                metadata,
                            } => {
                                let fallible = async {
                                    let token_info = TokenInfo::decrypt(&token_key, &resume_token)?;
                                    let (send_upcoded, recv_upcoded) = smol::channel::bounded(1000);
                                    let (send_downcoded, recv_downcoded) =
                                        smol::channel::bounded(1000);
                                    // mix the metadata with the session key
                                    let real_session_key = blake3::keyed_hash(
                                        blake3::hash(metadata.as_bytes()).as_bytes(),
                                        &token_info.sess_key,
                                    );
                                    table.add_entry(
                                        client_addr,
                                        recv_upcoded,
                                        send_downcoded,
                                        real_session_key.as_bytes(),
                                    );
                                    log::debug!(
                                        "SERVER shared_secret: {:?}",
                                        hex::encode(token_info.sess_key)
                                    );
                                    let pipe = ObfsUdpPipe::with_custom_transport(
                                        recv_downcoded,
                                        send_upcoded,
                                        client_addr,
                                        &metadata,
                                    );
                                    anyhow::Ok(pipe)
                                };
                                match fallible.await {
                                    Ok(pipe) => {
                                        // if send_new_pipes is full (because of a stupid app that does not call listen in a loop fast enough), we drop the session rather than have everything grind to a halt.
                                        let _ = send_new_pipes.try_send(pipe);
                                    }
                                    Err(err) => {
                                        log::debug!("client {client_addr} sent a BAD resume: {err}")
                                    }
                                }
                            }
                        }
                    } else {
                        log::warn!("could not decode handshake")
                    };
                }
                Err(err) => {
                    log::warn!("oh no cannot decrypt! {:?} ({})", err, pkt.len());
                }
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TokenInfo {
    sess_key: Bytes,
    init_time_ms: u64,
    version: u64,
}

impl TokenInfo {
    fn decrypt(key: &[u8], encrypted: &[u8]) -> anyhow::Result<Self> {
        // first we decrypt
        let crypter = ObfsAead::new(key);
        let plain = crypter.decrypt(encrypted)?;
        let ctext = stdcode::deserialize::<Self>(&plain)?;
        Ok(ctext)
    }

    fn encrypt(&self, key: &[u8]) -> Bytes {
        let crypter = ObfsAead::new(key);
        crypter.encrypt(&stdcode::serialize(self).expect("must serialize"))
    }
}
