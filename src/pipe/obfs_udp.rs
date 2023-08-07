mod crypt;
mod defrag;
mod fec;
mod frame;
mod listener;
mod listener_table;
mod recfilter;
mod stats;

use crate::{
    crypt::{triple_ecdh, ObfsAead, SymmetricFromAsymmetric, CLIENT_DN_KEY, CLIENT_UP_KEY},
    utilities::{
        sockets::{new_udp_socket_bind, MyUdpSocket},
        BatchTimer,
    },
};
use anyhow::Context;
use async_trait::async_trait;
use bytes::Bytes;
pub use listener::ObfsUdpListener;
use parking_lot::Mutex;
use priority_queue::PriorityQueue;
use rand::rngs::OsRng;
use replay_filter::ReplayFilter;
use serde::{Deserialize, Serialize};
use smol::{
    channel::{Receiver, Sender},
    future::FutureExt,
};
use std::{
    cmp::Reverse,
    convert::Infallible,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

/// Represents an unreliable datagram connection. Generally, this is not to be used directly, but fed into [crate::Multiplex] instances to be used as the underlying transport.
pub struct ObfsUdpPipe {
    send_upraw: Sender<Bytes>,
    recv_downraw: Receiver<Bytes>,

    _task: smol::Task<Infallible>,

    remote_addr: SocketAddr,

    peer_metadata: String,
}

const FEC_TIMEOUT_MS: u64 = 20;
use self::{
    crypt::{ObfsDecrypter, ObfsEncrypter},
    defrag::Defragmenter,
    fec::{FecDecoder, FecEncoder, ParitySpaceKey},
    frame::{fragment, HandshakeFrame, ObfsUdpFrame},
    stats::StatsCalculator,
};

use super::Pipe;

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
        recv_downcoded: Receiver<ObfsUdpFrame>,
        send_upcoded: Sender<ObfsUdpFrame>,
        remote_addr: SocketAddr,
        peer_metadata: &str,
    ) -> Self {
        let (send_upraw, recv_upraw) = smol::channel::bounded(1000);
        let (send_downraw, recv_downraw) = smol::channel::bounded(1000);
        let stats_calculator = Arc::new(Mutex::new(StatsCalculator::new()));

        let pipe_loop_future = pipe_loop(
            recv_upraw,
            send_upcoded,
            recv_downcoded,
            send_downraw,
            stats_calculator,
        );

        Self {
            send_upraw,
            recv_downraw,

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
        let addr = if server_addr.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        }
        .parse::<SocketAddr>()
        .unwrap();
        let socket = new_udp_socket_bind(addr).context("could not bind udp socket")?;

        // do the handshake
        // generate pk-sk pairs for encryption after the session is established
        let my_long_sk = x25519_dalek::StaticSecret::new(rand::thread_rng());
        let my_eph_sk = x25519_dalek::StaticSecret::new(rand::thread_rng());
        let cookie = SymmetricFromAsymmetric::new(server_pk.0);
        // construct the ClientHello message
        let client_hello_plain = HandshakeFrame::ClientHello {
            long_pk: (&my_long_sk).into(),
            eph_pk: (&my_eph_sk).into(),
            version: 4,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        }
        .to_bytes();
        // encrypt the ClientHello message
        let init_enc = ObfsAead::new(&cookie.generate_c2s());
        let client_hello = init_enc.encrypt(&client_hello_plain);
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
            client_commitment,
        } = deser_resp
        {
            if blake3::Hash::from(client_commitment) != blake3::hash(&client_hello_plain) {
                anyhow::bail!("the two hellos don't match")
            }
            log::trace!("***** server hello received, calculating stuff ******");
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
            let (send_upcoded, recv_upcoded) = smol::channel::bounded(1000);
            let (send_downcoded, recv_downcoded) = smol::channel::bounded(1000);
            let pipe = ObfsUdpPipe::with_custom_transport(
                recv_downcoded,
                send_upcoded,
                server_addr,
                metadata,
            );

            // start background encrypting/decrypting + forwarding task
            let shared_secret = triple_ecdh(&my_long_sk, &my_eph_sk, &long_pk, &eph_pk);
            log::trace!("CLIENT shared_secret: {:?}", shared_secret);
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
    recv_upcoded: Receiver<ObfsUdpFrame>,
    send_downcoded: Sender<ObfsUdpFrame>,
    socket: MyUdpSocket,
    server_addr: SocketAddr,
    shared_secret: blake3::Hash,
) -> anyhow::Result<()> {
    let up_key = blake3::keyed_hash(CLIENT_UP_KEY, shared_secret.as_bytes());
    let dn_key = blake3::keyed_hash(CLIENT_DN_KEY, shared_secret.as_bytes());
    let enc = ObfsEncrypter::new(ObfsAead::new(up_key.as_bytes()));
    let dec = ObfsDecrypter::new(ObfsAead::new(dn_key.as_bytes()));

    let up_loop = async {
        loop {
            let msg = recv_upcoded.recv().await.context("death in UDP up loop")?;

            let enc_msg = enc.encrypt(&msg);
            if let Err(err) = socket.send_to(&enc_msg, server_addr).await {
                log::error!("cannot send message: {:?}", err)
            }
        }
    };

    up_loop
        .race(async {
            let mut buf = [0u8; 65536];
            loop {
                let frame_fut = async {
                    let (n, _) = socket.recv_from(&mut buf).await?;
                    log::trace!("got {} bytes from server", n);
                    let dn_msg = &buf[..n];
                    let dec_msg = dec.decrypt(dn_msg)?;
                    anyhow::Ok(dec_msg)
                };
                match frame_fut.await {
                    Err(err) => {
                        log::error!("cannot recv message: {:?}", err)
                    }
                    Ok(deser_msg) => {
                        send_downcoded
                            .send(deser_msg)
                            .await
                            .context("death in UDP down loop")?;
                    }
                }
            }
        })
        .await
}

#[async_trait]
impl Pipe for ObfsUdpPipe {
    fn send(&self, to_send: Bytes) {
        let _ = self.send_upraw.try_send(to_send);
    }

    async fn recv(&self) -> std::io::Result<Bytes> {
        self.recv_downraw.recv().await.map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "obfsudp task somehow failed",
            )
        })
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
    send_upcoded: Sender<ObfsUdpFrame>,
    recv_downcoded: Receiver<ObfsUdpFrame>,
    send_downraw: Sender<Bytes>,
    stats_calculator: Arc<Mutex<StatsCalculator>>,
) -> Infallible {
    let mut next_seqno = 0;

    let mut fec_encoder = FecEncoder::new(Duration::from_millis(FEC_TIMEOUT_MS), BURST_SIZE);
    let mut fec_decoder = FecDecoder::new(100); // arbitrary size
    let mut defrag = Defragmenter::default();
    let mut replay_filter = ReplayFilter::default();
    let mut out_frag_buff = Vec::new();
    let mut ack_timer = BatchTimer::new(Duration::from_millis(200), 100);
    let mut probably_lost_incoming = PriorityQueue::new();
    let mut unacked_incoming = Vec::new();
    let mut last_incoming_seqno = 0;

    let mut loss = 0.0;
    let mut loss_time: Option<Instant> = None;

    loop {
        let loss = if loss_time.map(|t| t.elapsed().as_secs() > 0).unwrap_or(true) {
            loss = stats_calculator.lock().get_stats().loss;
            loss_time = Some(Instant::now());
            loss
        } else {
            loss
        };
        let event = Event::fec_timeout(&mut fec_encoder, loss)
            .or(Event::ack_timeout(&mut ack_timer))
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

                        stats_calculator.lock().add_sent(seqno);

                        let msg = ObfsUdpFrame::Data { seqno, body: bts };
                        let _ = send_upcoded.try_send(msg);
                    }
                }
                Event::NewInPacket(pipe_frame) => match pipe_frame {
                    ObfsUdpFrame::Data { seqno, body } => {
                        stats_calculator.lock().set_dead(false);
                        if replay_filter.add(seqno) {
                            fec_decoder.insert_data(seqno, body.clone());
                            if let Some(whole) = defrag.insert(seqno, body) {
                                let _ = send_downraw.try_send(whole); // TODO why??
                            }
                            if seqno > last_incoming_seqno + 1 {
                                log::trace!("gap in sequence numbers: {}", seqno);
                                for gap_seqno in (last_incoming_seqno + 1)..seqno {
                                    probably_lost_incoming.push(
                                        gap_seqno,
                                        Reverse(Instant::now() + Duration::from_millis(500)),
                                    );
                                }
                            }
                            last_incoming_seqno = seqno;
                            ack_timer.increment();
                            unacked_incoming.push((seqno, Instant::now()));
                            probably_lost_incoming.remove(&seqno);
                        }
                    }
                    ObfsUdpFrame::Parity {
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
                    ObfsUdpFrame::Acks { acks, naks } => {
                        let mut stats = stats_calculator.lock();
                        for (seqno, offset) in acks {
                            stats.add_ack(seqno, Duration::from_millis(offset as _));
                        }
                        for seqno in naks {
                            stats.add_nak(seqno);
                        }
                    }
                },

                Event::AckTimeout => {
                    ack_timer.reset();
                    log::trace!(
                        "ack timer fired, must send back {} acks",
                        unacked_incoming.len()
                    );
                    let naks = {
                        let mut vv = Vec::new();
                        let now = Instant::now();
                        while let Some((seqno, lost_date)) = probably_lost_incoming.pop() {
                            if lost_date.0 < now {
                                vv.push(seqno);
                            } else {
                                probably_lost_incoming.push(seqno, lost_date);
                                break;
                            }
                        }
                        vv
                    };
                    let _ = send_upcoded
                        .send(ObfsUdpFrame::Acks {
                            acks: unacked_incoming
                                .drain(..)
                                .map(|(k, v)| (k, v.elapsed().as_millis() as _))
                                .collect(),
                            naks,
                        })
                        .await;
                }

                Event::FecTimeout(parity_frames) => {
                    log::trace!("FecTimeout; sending {} parities", parity_frames.len());
                    for parity_frame in parity_frames {
                        let _ = send_upcoded.try_send(parity_frame);
                    }
                }
            }
        } else {
            // stop the pipe
            return smol::future::pending().await;
        }
    }
}

#[derive(Debug)]
enum Event {
    NewOutPayload(Bytes),
    NewInPacket(ObfsUdpFrame), // either data or parity or ack request packet or acks
    FecTimeout(Vec<ObfsUdpFrame>),
    AckTimeout,
}

impl Event {
    /// Waits for a new payload to send out
    pub async fn new_out_payload(recv: &Receiver<Bytes>) -> anyhow::Result<Self> {
        Ok(Event::NewOutPayload(recv.recv().await?))
    }

    pub async fn new_in_packet(recv: &Receiver<ObfsUdpFrame>) -> anyhow::Result<Self> {
        let in_pkt = recv.recv().await?;
        Ok(Event::NewInPacket(in_pkt))
    }
    pub async fn fec_timeout(fec_machine: &mut FecEncoder, loss: f64) -> anyhow::Result<Self> {
        let parity = fec_machine.wait_parity(loss).await;

        Ok(Event::FecTimeout(parity))
    }

    pub async fn ack_timeout(ack_timer: &mut BatchTimer) -> anyhow::Result<Self> {
        ack_timer.wait().await;
        Ok(Event::AckTimeout)
    }
}
