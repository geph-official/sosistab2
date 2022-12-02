mod ack;
mod defrag;
mod fec;
mod frame;
mod listener;
mod listener_table;

use crate::{
    crypt::{triple_ecdh, Cookie, ObfsAead, CLIENT_DN_KEY, CLIENT_UP_KEY},
    utilities::{
        sockets::{new_udp_socket_bind, MyUdpSocket},
        ReplayFilter,
    },
};
use anyhow::Context;
use async_trait::async_trait;
use bytes::Bytes;
pub use listener::ObfsUdpListener;
use parking_lot::Mutex;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use smol::{
    channel::{Receiver, Sender},
    future::FutureExt,
};
use std::{
    convert::Infallible,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
/// Represents an unreliable datagram connection. Generally, this is not to be used directly, but fed into [crate::Multiplex] instances to be used as the underlying transport.
pub struct ObfsUdpPipe {
    send_upraw: Sender<Bytes>,
    recv_downraw: Receiver<Bytes>,
    stats_calculator: Arc<Mutex<StatsCalculator>>,
    _task: smol::Task<Infallible>,

    remote_addr: SocketAddr,

    peer_metadata: String,
}

const FEC_TIMEOUT_MS: u64 = 20;
use self::{
    ack::{AckRequester, AckResponder},
    defrag::Defragmenter,
    fec::{FecDecoder, FecEncoder, ParitySpaceKey},
    frame::{fragment, HandshakeFrame, PipeFrame},
};

use super::{stats::StatsCalculator, Pipe, PipeStats};
const PACKET_LIVE_TIME: Duration = Duration::from_millis(500); // placeholder
const BURST_SIZE: usize = 20;

/// A server public key for the obfuscated UDP pipe.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ObfsUdpPublic(pub(crate) x25519_dalek::PublicKey);

impl ObfsUdpPublic {
    /// Returns the bytes representation.
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    /// Convert from bytes.
    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(x25519_dalek::PublicKey::from(b))
    }
}

/// A server secret key for the obfuscated UDP pipe.
#[derive(Clone, Serialize, Deserialize)]
pub struct ObfsUdpSecret(pub(crate) x25519_dalek::StaticSecret);

impl ObfsUdpSecret {
    /// Returns the bytes representation.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Convert from bytes.
    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(x25519_dalek::StaticSecret::from(b))
    }

    /// Generate.
    pub fn generate() -> Self {
        Self(x25519_dalek::StaticSecret::new(OsRng {}))
    }

    /// Convert to a public key.
    pub fn to_public(&self) -> ObfsUdpPublic {
        ObfsUdpPublic((&self.0).into())
    }
}

impl ObfsUdpPipe {
    /// Creates a new Pipe that receives messages from `recv_downcoded` and send messages to `send_upcoded`. This should only be used if you are creating your own underlying, UDP-like transport; otherwise use the functions provided in this crate to create Pipes backed by an obfuscated, packet loss-resistant UDP transport.
    ///
    /// The caller must arrange to drain the other end of `send_upcoded` promptly; otherwise the Pipe itself will get stuck.
    pub fn with_custom_transport(
        recv_downcoded: Receiver<PipeFrame>,
        send_upcoded: Sender<PipeFrame>,
        remote_addr: SocketAddr,
        peer_metadata: &str,
    ) -> Self {
        let (send_upraw, recv_upraw) = smol::channel::bounded(10000);
        let (send_downraw, recv_downraw) = smol::channel::bounded(10000);
        let stats_calculator = Arc::new(Mutex::new(StatsCalculator::new()));

        let pipe_loop_future = pipe_loop(
            recv_upraw,
            send_upcoded,
            recv_downcoded,
            send_downraw,
            stats_calculator.clone(),
        );

        Self {
            send_upraw,
            recv_downraw,
            stats_calculator,
            _task: smolscale::spawn(pipe_loop_future),
            remote_addr,
            peer_metadata: peer_metadata.into(),
        }
    }

    /// Establishes a pipe to the server_addr, using the obfuscated UDP transport.
    pub async fn connect(
        server_addr: SocketAddr,
        server_pk: ObfsUdpPublic,
        metadata: &str,
    ) -> anyhow::Result<ObfsUdpPipe> {
        let socket =
            new_udp_socket_bind("[::]:0".parse().unwrap()).context("could not bind udp socket")?;

        // do the handshake
        // generate pk-sk pairs for encryption after the session is established
        let my_long_sk = x25519_dalek::StaticSecret::new(rand::thread_rng());
        let my_eph_sk = x25519_dalek::StaticSecret::new(rand::thread_rng());
        let cookie = Cookie::new(server_pk.0);
        // construct the ClientHello message
        let client_hello = HandshakeFrame::ClientHello {
            long_pk: (&my_long_sk).into(),
            eph_pk: (&my_eph_sk).into(),
            version: 4,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        }
        .to_bytes();
        // encrypt the ClientHello message
        let init_enc = ObfsAead::new(&cookie.generate_c2s());
        let client_hello = init_enc.encrypt(&client_hello);
        // send the ClientHello
        socket.send_to(&client_hello, server_addr).await?;

        // wait for the server's response
        let mut ctext_resp = [0u8; 2048];
        let (n, _) = socket
            .recv_from(&mut ctext_resp)
            .await
            .context("can't read response from server")?;
        let ctext_resp = &ctext_resp[..n];
        // decrypt the server's response
        let init_dec = ObfsAead::new(&cookie.generate_s2c());
        let ptext_resp = init_dec.decrypt(ctext_resp)?;
        let deser_resp = HandshakeFrame::from_bytes(&ptext_resp)?;
        if let HandshakeFrame::ServerHello {
            long_pk,
            eph_pk,
            resume_token,
        } = deser_resp
        {
            log::debug!("***** server hello received, calculating stuff ******");
            // finish off the handshake
            let client_resp = init_enc.encrypt(
                &HandshakeFrame::ClientResume {
                    resume_token,
                    metadata: metadata.into(),
                }
                .to_bytes(),
            );
            socket.send_to(&client_resp, server_addr).await?;

            // create a pipe
            let (send_upcoded, recv_upcoded) = smol::channel::unbounded();
            let (send_downcoded, recv_downcoded) = smol::channel::unbounded();
            let pipe = ObfsUdpPipe::with_custom_transport(
                recv_downcoded,
                send_upcoded,
                server_addr,
                metadata,
            );

            // start background encrypting/decrypting + forwarding task
            let shared_secret = triple_ecdh(&my_long_sk, &my_eph_sk, &long_pk, &eph_pk);
            log::debug!("CLIENT shared_secret: {:?}", shared_secret);
            let real_sess_key = blake3::keyed_hash(
                blake3::hash(metadata.as_bytes()).as_bytes(),
                shared_secret.as_bytes(),
            );
            smolscale::spawn(client_loop(
                recv_upcoded,
                send_downcoded,
                socket,
                server_addr,
                real_sess_key,
            ))
            .detach();

            Ok(pipe)
        } else {
            anyhow::bail!("server sent unrecognizable message")
        }
    }
}

async fn client_loop(
    recv_upcoded: Receiver<PipeFrame>,
    send_downcoded: Sender<PipeFrame>,
    socket: MyUdpSocket,
    server_addr: SocketAddr,
    shared_secret: blake3::Hash,
) {
    let up_key = blake3::keyed_hash(CLIENT_UP_KEY, shared_secret.as_bytes());
    let dn_key = blake3::keyed_hash(CLIENT_DN_KEY, shared_secret.as_bytes());
    let enc = ObfsAead::new(up_key.as_bytes());
    let dec = ObfsAead::new(dn_key.as_bytes());

    loop {
        let res: anyhow::Result<()> = async {
            let up_loop = async {
                loop {
                    let msg = recv_upcoded.recv().await?;
                    // log::debug!("serverbound: {:?}", msg);
                    let msg = stdcode::serialize(&msg)?;
                    let enc_msg = enc.encrypt(&msg);
                    socket.send_to(&enc_msg, server_addr).await?;
                }
            };

            up_loop
                .race(async {
                    let mut buf = [0u8; 65536];
                    loop {
                        let (n, _) = socket.recv_from(&mut buf).await?;
                        log::trace!("got {} bytes from server", n);
                        let dn_msg = &buf[..n];
                        let dec_msg = dec.decrypt(dn_msg)?;

                        let deser_msg = stdcode::deserialize(&dec_msg)?;
                        send_downcoded.send(deser_msg).await?;
                    }
                })
                .await
        }
        .await;
        if let Err(err) = res {
            log::error!("client loop error: {:?}", err);
            return;
        }
    }
}

#[async_trait]
impl Pipe for ObfsUdpPipe {
    async fn send(&self, to_send: Bytes) {
        let _ = self.send_upraw.send(to_send).await;
    }

    async fn recv(&self) -> std::io::Result<Bytes> {
        self.recv_downraw.recv().await.map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "obfsudp task somehow failed",
            )
        })
    }

    fn get_stats(&self) -> PipeStats {
        self.stats_calculator.lock().get_stats()
    }

    fn protocol(&self) -> &str {
        "obfsudp-1"
    }

    fn peer_addr(&self) -> String {
        self.remote_addr.to_string()
    }

    fn peer_metadata(&self) -> &str {
        &self.peer_metadata
    }
}

/// Main processing loop for the Pipe
async fn pipe_loop(
    recv_upraw: Receiver<Bytes>,
    send_upcoded: Sender<PipeFrame>,
    recv_downcoded: Receiver<PipeFrame>,
    send_downraw: Sender<Bytes>,
    stats_calculator: Arc<Mutex<StatsCalculator>>,
) -> Infallible {
    let mut next_seqno = 0;
    let mut ack_responder = AckResponder::new(100000);
    let mut ack_client = AckRequester::new(PACKET_LIVE_TIME);
    let mut fec_encoder = FecEncoder::new(Duration::from_millis(FEC_TIMEOUT_MS), BURST_SIZE);
    let mut fec_decoder = FecDecoder::new(100); // arbitrary size
    let mut defrag = Defragmenter::default();
    let mut replay_filter = ReplayFilter::default();
    let mut out_frag_buff = Vec::new();

    loop {
        let loss = stats_calculator.lock().get_stats().loss;
        let event = Event::unack_timeout(&mut ack_client)
            .or(Event::fec_timeout(&mut fec_encoder, loss))
            .or(Event::new_in_packet(&recv_downcoded))
            .or(Event::new_out_payload(&recv_upraw))
            .await;

        if let Ok(event) = event {
            match event {
                Event::NewOutPayload(bts) => {
                    out_frag_buff.clear();
                    fragment(bts, &mut out_frag_buff);
                    for bts in out_frag_buff.drain(..) {
                        let seqno = next_seqno;

                        next_seqno += 1;
                        fec_encoder.add_unfecked(seqno, bts.clone());
                        ack_client.add_unacked(seqno);
                        stats_calculator.lock().add_sent(seqno);

                        let msg = PipeFrame::Data {
                            frame_no: seqno,
                            body: bts,
                        };
                        let _ = send_upcoded.send(msg).await;
                    }
                }
                Event::NewInPacket(pipe_frame) => match pipe_frame {
                    PipeFrame::Data { frame_no, body } => {
                        if replay_filter.add(frame_no) {
                            ack_responder.add_ack(frame_no);
                            fec_decoder.insert_data(frame_no, body.clone());
                            if let Some(whole) = defrag.insert(frame_no, body) {
                                let _ = send_downraw.try_send(whole); // TODO why??
                            }
                        }
                    }
                    PipeFrame::Parity {
                        data_frame_first,
                        data_count,
                        parity_count,
                        parity_index,
                        pad_size,
                        body,
                    } => {
                        let parity_info = ParitySpaceKey {
                            data_frame_first,
                            data_count,
                            parity_count,
                            pad_size,
                        };
                        let reconstructed =
                            fec_decoder.insert_parity(parity_info, parity_index, body);
                        if !reconstructed.is_empty() {
                            for (seqno, p) in reconstructed {
                                if replay_filter.add(seqno) {
                                    if let Some(p) = defrag.insert(seqno, p) {
                                        let _ = send_downraw.try_send(p);
                                    }
                                }
                            }
                        }
                    }
                    PipeFrame::Acks {
                        first_ack,
                        last_ack,
                        ack_bitmap: acks,
                        time_offset,
                    } => stats_calculator
                        .lock()
                        .add_acks(first_ack, last_ack, acks, time_offset),
                    PipeFrame::AckRequest {
                        first_ack,
                        last_ack,
                    } => {
                        log::trace!("responding to ack request {first_ack} to {last_ack}");
                        let acks = ack_responder.construct_acks(first_ack, last_ack);
                        for ack in acks {
                            let _ = send_upcoded.send(ack).await;
                        }
                    }
                },
                Event::UnackTimeout(ack_req) => {
                    if let PipeFrame::AckRequest { .. } = &ack_req {
                        stats_calculator.lock().add_ackreq();
                        log::trace!("*** SENDING ACK REQUEST ***");

                        let _ = send_upcoded.send(ack_req).await;
                    }
                } // send ack request
                Event::FecTimeout(parity_frames) => {
                    log::trace!("FecTimeout; sending {} parities", parity_frames.len());
                    for parity_frame in parity_frames {
                        let _ = send_upcoded.send(parity_frame).await;
                    }
                }
            }
        }
    }
}

#[derive(Debug)]
enum Event {
    NewOutPayload(Bytes),
    NewInPacket(PipeFrame), // either data or parity or ack request packet or acks
    UnackTimeout(PipeFrame),
    FecTimeout(Vec<PipeFrame>),
}

impl Event {
    /// Waits for a new payload to send out
    pub async fn new_out_payload(recv: &Receiver<Bytes>) -> anyhow::Result<Self> {
        Ok(Event::NewOutPayload(recv.recv().await?))
    }

    pub async fn new_in_packet(recv: &Receiver<PipeFrame>) -> anyhow::Result<Self> {
        let in_pkt = recv.recv().await?;
        Ok(Event::NewInPacket(in_pkt))
    }

    pub async fn unack_timeout(ack_client: &mut AckRequester) -> anyhow::Result<Self> {
        let req = ack_client.wait_ack_request().await;
        Ok(Event::UnackTimeout(req))
    }

    pub async fn fec_timeout(fec_machine: &mut FecEncoder, loss: f64) -> anyhow::Result<Self> {
        let parity = fec_machine.wait_parity(loss).await;

        Ok(Event::FecTimeout(parity))
    }
}
