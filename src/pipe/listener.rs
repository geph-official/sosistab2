use std::net::SocketAddr;

use super::listener_table::PipeTable;
use crate::{
    crypt::{triple_ecdh, Cookie, ObfsAead},
    pipe::{frame::HandshakeFrame, pipe_struct::Pipe},
    utilities::sockets::new_udp_socket_bind,
};
use bytes::Bytes;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use smol::{
    channel::{Receiver, Sender},
    net::UdpSocket,
};

pub struct Listener {
    recv_new_pipes: Receiver<Pipe>,
    _task: smol::Task<()>,
}

impl Listener {
    /// Constructor.
    pub fn new(listen: SocketAddr, server_long_sk: x25519_dalek::StaticSecret) -> Self {
        let socket = new_udp_socket_bind(listen).unwrap();
        let (send_new_pipes, recv_new_pipes) = smol::channel::unbounded();
        let task = smolscale::spawn(async move {
            if let Err(err) = listener_loop(
                socket.clone(),
                send_new_pipes,
                (&server_long_sk).into(),
                server_long_sk,
            )
            .await
            {
                log::error!("Oh no! The listener loop has died with an error {:?}", err);
            }
        });
        Self {
            recv_new_pipes,

            _task: task,
        }
    }

    pub async fn accept(&self) -> anyhow::Result<Pipe> {
        let p = self.recv_new_pipes.recv().await?;
        Ok(p)
    }
}

async fn listener_loop(
    socket: UdpSocket,
    send_new_pipes: Sender<Pipe>,
    server_long_pk: x25519_dalek::PublicKey,
    server_long_sk: x25519_dalek::StaticSecret,
) -> anyhow::Result<()> {
    let cookie = Cookie::new(server_long_pk);
    let init_dec = ObfsAead::new(&cookie.generate_c2s());
    let init_enc = ObfsAead::new(&cookie.generate_s2c());

    // make table and token key
    let mut table = PipeTable::new(1_000_000, socket.clone());
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
            if let Ok(ptext) = init_dec.decrypt(pkt) {
                if let Ok(msg) = bincode::deserialize::<HandshakeFrame>(&ptext) {
                    match msg {
                        HandshakeFrame::ClientHello {
                            long_pk,
                            eph_pk,
                            version,
                            timestamp,
                        } => {
                            // println!("received ClientHello: {:?}", msg);
                            let server_eph_sk = x25519_dalek::StaticSecret::new(rand::thread_rng());

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
                                    &init_enc.encrypt(&bincode::serialize(&resp)?),
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
                        HandshakeFrame::ClientResume { resume_token } => {
                            let fallible = async {
                                let token_info = TokenInfo::decrypt(&token_key, &resume_token)?;
                                let (send_upcoded, recv_upcoded) = smol::channel::bounded(256);
                                let (send_downcoded, recv_downcoded) = smol::channel::bounded(256);
                                table.add_entry(
                                    client_addr,
                                    recv_upcoded,
                                    send_downcoded,
                                    &token_info.sess_key,
                                );
                                log::debug!(
                                    "SERVER shared_secret: {:?}",
                                    hex::encode(token_info.sess_key)
                                );
                                let pipe =
                                    Pipe::with_custom_transport(recv_downcoded, send_upcoded);
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
                };
            } else {
                log::warn!("oh no!");
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
        let ctext = bincode::deserialize::<Self>(&plain)?;
        Ok(ctext)
    }

    fn encrypt(&self, key: &[u8]) -> Bytes {
        let crypter = ObfsAead::new(key);
        crypter.encrypt(&bincode::serialize(self).expect("must serialize"))
    }
}
