use crate::{
    pipe::{defrag::Defragmenter, fec::ParitySpaceKey, frame::fragment},
    utilities::ReplayFilter,
    PipeStats,
};
use bytes::Bytes;
use parking_lot::RwLock;

use smol::{
    channel::{Receiver, Sender},
    future::FutureExt,
};
use std::{convert::Infallible, sync::Arc, time::Duration};

/// Represents an unreliable datagram connection. Generally, this is not to be used directly, but fed into [crate::Multiplex] instances to be used as the underlying transport.
pub struct Pipe {
    send_upraw: Sender<Bytes>,
    recv_downraw: Receiver<Bytes>,
    stats_calculator: Arc<RwLock<StatsCalculator>>,
    _task: smol::Task<Infallible>,
}

const FEC_TIMEOUT_MS: u64 = 20;
use super::{
    ack::{AckRequester, AckResponder},
    fec::{FecDecoder, FecEncoder},
    frame::PipeFrame,
    stats::StatsCalculator,
};
const PACKET_LIVE_TIME: Duration = Duration::from_millis(500); // placeholder
const BURST_SIZE: usize = 30;

impl Pipe {
    /// Creates a new Pipe that receives messages from `recv_downcoded` and send messages to `send_upcoded`. This should only be used if you are creating your own underlying transport; otherwise use the functions provided in this crate to create Pipes backed by an obfuscated, packet loss-resistant UDP transport.
    ///
    /// The caller must arrange to drain the other end of `send_upcoded` promptly; otherwise the Pipe itself will get stuck.
    pub fn with_custom_transport(
        recv_downcoded: Receiver<PipeFrame>,
        send_upcoded: Sender<PipeFrame>,
    ) -> Self {
        let (send_upraw, recv_upraw) = smol::channel::bounded(100);
        let (send_downraw, recv_downraw) = smol::channel::bounded(100);
        let stats_calculator = Arc::new(RwLock::new(StatsCalculator::new()));

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
        }
    }

    /// Sends a datagram to the other side
    pub async fn send(&self, to_send: Bytes) {
        self.send_upraw.send(to_send).await.unwrap()
    }

    /// Receives the next datagram from the other side
    pub async fn recv(&self) -> Bytes {
        self.recv_downraw.recv().await.unwrap()
    }

    /// Receives the next datagram if one is ready to be received; non-blocking
    pub fn try_recv(&self) -> anyhow::Result<Bytes> {
        let pkt = self.recv_downraw.try_recv()?;
        Ok(pkt)
    }

    /// Returns Pipe statistics
    pub fn get_stats(&self) -> PipeStats {
        self.stats_calculator.read().get_stats()
    }
}

/// Main processing loop for the Pipe
async fn pipe_loop(
    recv_upraw: Receiver<Bytes>,
    send_upcoded: Sender<PipeFrame>,
    recv_downcoded: Receiver<PipeFrame>,
    send_downraw: Sender<Bytes>,
    stats_calculator: Arc<RwLock<StatsCalculator>>,
) -> Infallible {
    let mut next_seqno = 0;
    let mut ack_responder = AckResponder::new(100000);
    let mut ack_client = AckRequester::new(PACKET_LIVE_TIME);
    let mut fec_encoder = FecEncoder::new(Duration::from_millis(FEC_TIMEOUT_MS), BURST_SIZE);
    let mut fec_decoder = FecDecoder::new(100); // arbitrary size
    let mut defrag = Defragmenter::default();
    let mut replay_filter = ReplayFilter::default();
    let mut out_frag_buff = Vec::new();

    // the number of packets that we sent, but did not send an ack request for.
    let mut sent_without_ack_request = 0;

    loop {
        smol::future::yield_now().await;
        let loss = stats_calculator.read().get_stats().loss;
        let event = Event::unack_timeout(&mut ack_client)
            .or(Event::fec_timeout(&mut fec_encoder, loss))
            .or(Event::new_in_packet(&recv_downcoded))
            .or(Event::new_out_payload(&recv_upraw))
            .await;

        // dbg!(sent_without_ack_request);

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
                        stats_calculator.write().add_sent(seqno);

                        let msg = PipeFrame::Data {
                            frame_no: seqno,
                            body: bts,
                        };
                        let _ = send_upcoded.send(msg).await;

                        sent_without_ack_request += 1;
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
                                        let _ = send_downraw.send(p).await;
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
                        .write()
                        .add_acks(first_ack, last_ack, acks, time_offset),
                    PipeFrame::AckRequest {
                        first_ack,
                        last_ack,
                    } => {
                        let acks = ack_responder.construct_acks(first_ack, last_ack);
                        for ack in acks {
                            let _ = send_upcoded.send(ack).await;
                        }
                    }
                },
                Event::UnackTimeout(ack_req) => {
                    if let PipeFrame::AckRequest {
                        first_ack,
                        last_ack,
                    } = &ack_req
                    {
                        sent_without_ack_request -= (last_ack - first_ack) as usize;
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
