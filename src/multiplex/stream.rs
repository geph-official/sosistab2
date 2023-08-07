use crate::multiplex::pipe_pool::Message;

use bytes::Bytes;

use futures_intrusive::sync::ManualResetEvent;
use parking_lot::Mutex;
use recycle_box::{coerce_box, RecycleBox};
use smol::prelude::*;
use stdcode::StdcodeSerializeExt;

use std::{
    collections::VecDeque,
    io::{Read, Write},
    pin::Pin,
    sync::Arc,
    task::Context,
    task::Poll,
    time::{Duration, Instant},
};

use self::{congestion::Highspeed, inflight::Inflight};

use super::pipe_pool::{RelKind, Reorderer};
mod congestion;

mod inflight;

const MSS: usize = 1000;

#[deprecated]
pub type MuxStream = Stream;

/// [MuxStream] represents a reliable stream, multiplexed over a [Multiplex]. It implements [AsyncRead], [AsyncWrite], and [Clone], making using it very similar to using a TcpStream.
pub struct Stream {
    global_notify: Arc<ManualResetEvent>,
    read_ready_future: Option<Pin<RecycleBox<dyn Future<Output = ()> + Send + 'static>>>,
    read_ready_resolved: bool,
    write_ready_future: Option<Pin<RecycleBox<dyn Future<Output = ()> + Send + 'static>>>,
    write_ready_resolved: bool,
    ready: Arc<async_event::Event>,
    queues: Arc<Mutex<StreamQueues>>,
}

/// SAFETY: because of the definition of AsyncRead, it's not possible to ever concurrently end up polling the futures in the RecycleBoxes.
unsafe impl Sync for Stream {}

impl Stream {
    fn new(
        global_notify: Arc<ManualResetEvent>,
        ready: Arc<async_event::Event>,
        queues: Arc<Mutex<StreamQueues>>,
    ) -> Self {
        Self {
            global_notify,
            read_ready_future: Some(RecycleBox::into_pin(coerce_box!(RecycleBox::new(async {
                smol::future::pending().await
            })))),
            read_ready_resolved: true, // forces redoing the future on first read
            write_ready_future: Some(RecycleBox::into_pin(coerce_box!(RecycleBox::new(async {
                smol::future::pending().await
            })))),
            write_ready_resolved: true, // forces redoing the future on first write
            ready,
            queues,
        }
    }

    /// Waits until this Stream is fully connected.
    pub async fn wait_connected(&self) -> std::io::Result<()> {
        self.ready
            .wait_until(|| {
                log::trace!("waiting until connected...");
                if self.queues.lock().connected {
                    log::trace!("connected now");
                    Some(())
                } else {
                    None
                }
            })
            .await;
        Ok(())
    }

    /// Returns the "additional info" attached to the stream.
    pub fn additional_info(&self) -> &str {
        "todo"
    }

    /// Shuts down the stream, causing future read and write operations to fail.
    pub async fn shutdown(&mut self) {
        self.queues.lock().closed = true;
        self.global_notify.set();
        self.ready.notify_all();
    }

    /// Sends an unreliable datagram.
    pub async fn send_urel(&self, dgram: Bytes) -> std::io::Result<()> {
        smol::future::pending().await
    }

    /// Receives an unreliable datagram.
    pub async fn recv_urel(&self) -> std::io::Result<Bytes> {
        smol::future::pending().await
    }
}

impl Clone for Stream {
    fn clone(&self) -> Self {
        Self::new(
            self.global_notify.clone(),
            self.ready.clone(),
            self.queues.clone(),
        )
    }
}

impl AsyncRead for Stream {
    /// We use this horrible hack because we cannot simply write `async fn read()`. AsyncRead is defined in this arcane fashion largely because Rust does not have async traits yet.
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        let mut read_future = self.read_ready_future.take().unwrap();
        // if resolved, then reset
        if self.read_ready_resolved {
            let read_ready = self.ready.clone();
            let inner = self.queues.clone();
            read_future = RecycleBox::into_pin(coerce_box!(RecycleBox::recycle_pinned(
                read_future,
                async move {
                    read_ready
                        .wait_until(move || {
                            let inner = inner.lock();
                            if !inner.read_stream.is_empty() || inner.closed {
                                Some(())
                            } else {
                                None
                            }
                        })
                        .await
                }
            )));
        }
        // poll the recycle-boxed futures
        match read_future.poll(cx) {
            Poll::Ready(()) => {
                self.read_ready_resolved = true;
                self.read_ready_future = Some(read_future);
                let mut queues = self.queues.lock();
                let n = queues.read_stream.read(buf);
                self.global_notify.set();

                Poll::Ready(n)
            }
            Poll::Pending => {
                self.read_ready_resolved = false;
                self.read_ready_future = Some(read_future);
                Poll::Pending
            }
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let mut write_future = self.write_ready_future.take().unwrap();
        // if resolved, then reset
        if self.write_ready_resolved {
            let write_ready = self.ready.clone();
            let inner = self.queues.clone();
            // this waits until there's less than 1 MB waiting to be written. this produces the right backpressure
            write_future = RecycleBox::into_pin(coerce_box!(RecycleBox::recycle_pinned(
                write_future,
                async move {
                    write_ready
                        .wait_until(move || {
                            let inner = inner.lock();
                            if inner.write_stream.len() <= 1_000_000 {
                                // 1 MB
                                Some(())
                            } else {
                                None
                            }
                        })
                        .await
                }
            )));
        }
        // poll the recycle-boxed futures
        match write_future.poll(cx) {
            Poll::Ready(()) => {
                self.write_ready_resolved = true;
                self.write_ready_future = Some(write_future);
                let n = self.queues.lock().write_stream.write(buf);
                self.global_notify.set();
                Poll::Ready(n)
            }
            Poll::Pending => {
                self.write_ready_resolved = false;
                self.write_ready_future = Some(write_future);
                Poll::Pending
            }
        }
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.queues.lock().closed = true;
        self.global_notify.set();
        Poll::Ready(Ok(()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

pub(crate) struct StreamState {
    phase: Phase,
    stream_id: u16,
    additional_data: String,
    incoming_queue: Vec<Message>,
    queues: Arc<Mutex<StreamQueues>>,
    ready: Arc<async_event::Event>,

    // read variables
    next_unseen_seqno: u64,
    reorderer: Reorderer<Bytes>,

    // write variables
    inflight: Inflight,
    next_write_seqno: u64,
    congestion: Highspeed,
    last_retrans: Instant,
}

impl StreamState {
    /// Creates a new StreamState, in the pre-SYN-sent state. Also returns the "user-facing" handle.
    pub fn new_pending(
        global_notify: Arc<ManualResetEvent>,
        stream_id: u16,
        additional_data: String,
    ) -> (Self, Stream) {
        Self::new_in_phase(global_notify, stream_id, Phase::Pending, additional_data)
    }

    /// Creates a new StreamState, in the established state. Also returns the "user-facing" handle.
    pub fn new_established(
        global_notify: Arc<ManualResetEvent>,
        stream_id: u16,
        additional_data: String,
    ) -> (Self, Stream) {
        Self::new_in_phase(
            global_notify,
            stream_id,
            Phase::Established,
            additional_data,
        )
    }

    /// Creates a new StreamState, in the specified state. Also returns the "user-facing" handle.
    fn new_in_phase(
        global_notify: Arc<ManualResetEvent>,
        stream_id: u16,
        phase: Phase,
        additional_data: String,
    ) -> (Self, Stream) {
        let queues = Arc::new(Mutex::new(StreamQueues::default()));
        let ready = Arc::new(async_event::Event::new());
        let handle = Stream::new(global_notify, ready.clone(), queues.clone());
        let state = Self {
            phase,
            stream_id,
            incoming_queue: Default::default(),
            queues,
            ready,

            next_unseen_seqno: 0,
            reorderer: Reorderer::default(),
            inflight: Inflight::new(),
            next_write_seqno: 0,

            congestion: Highspeed::new(1),
            additional_data,
            last_retrans: Instant::now(),
        };
        (state, handle)
    }

    /// Injects an incoming message.
    pub fn inject_incoming(&mut self, msg: Message) {
        self.incoming_queue.push(msg);
    }

    /// "Ticks" this StreamState, which advances its state. Any outgoing messages generated are passed to the callback given. Returns the correct time to call tick again at.
    pub fn tick(&mut self, mut outgoing_callback: impl FnMut(Message)) -> Instant {
        log::trace!("ticking {} at {:?}", self.stream_id, self.phase);

        let now: Instant = Instant::now();

        match self.phase {
            Phase::Pending => {
                // send a SYN, and transition into SynSent
                outgoing_callback(Message::Rel {
                    kind: RelKind::Syn,
                    stream_id: self.stream_id,
                    seqno: 0,
                    payload: Bytes::copy_from_slice(self.additional_data.as_bytes()),
                });
                let next_resend = now + Duration::from_secs(1);
                self.phase = Phase::SynSent { next_resend };
                next_resend
            }
            Phase::SynSent { next_resend } => {
                if self.incoming_queue.drain(..).any(|msg| {
                    matches!(
                        msg,
                        Message::Rel {
                            kind: RelKind::SynAck,
                            stream_id: _,
                            seqno: _,
                            payload: _
                        }
                    )
                }) {
                    self.phase = Phase::Established;
                    self.queues.lock().connected = true;
                    self.ready.notify_all();
                    now
                } else if now >= next_resend {
                    outgoing_callback(Message::Rel {
                        kind: RelKind::Syn,
                        stream_id: self.stream_id,
                        seqno: 0,
                        payload: Bytes::copy_from_slice(self.additional_data.as_bytes()),
                    });
                    let next_resend = now + Duration::from_secs(1);
                    self.phase = Phase::SynSent { next_resend };
                    next_resend
                } else {
                    next_resend
                }
            }
            Phase::Established => {
                // First, handle receiving packets. This is the easier part.
                self.tick_read(now, &mut outgoing_callback);
                // Then, handle sending packets. This involves congestion control, so it's the harder part.
                self.tick_write(now, &mut outgoing_callback);
                // If closed, then die
                if self.queues.lock().closed {
                    self.phase = Phase::Closed;
                }
                // Finally, calculate the next interval.
                self.retick_time()
            }
            Phase::Closed => {
                self.queues.lock().closed = true;
                self.ready.notify_all();
                for _ in self.incoming_queue.drain(..) {
                    outgoing_callback(Message::Rel {
                        kind: RelKind::Rst,
                        stream_id: self.stream_id,
                        seqno: 0,
                        payload: Default::default(),
                    });
                }
                now + Duration::from_secs(30)
            }
        }
    }

    fn tick_read(&mut self, now: Instant, mut outgoing_callback: impl FnMut(Message)) {
        // Put all incoming packets into the reorderer.
        let mut to_ack = vec![];

        for packet in self.incoming_queue.drain(..) {
            // If the receive queue is too large, then we pretend like we don't see anything. The sender will eventually retransmit.
            // This unifies flow control with congestion control at the cost of a bit of efficiency.
            if self.queues.lock().read_stream.len() > 1_000_000 {
                continue;
            }

            match packet {
                Message::Rel {
                    kind: RelKind::Data,
                    stream_id,
                    seqno,
                    payload,
                } => {
                    log::trace!("incoming seqno {stream_id}/{seqno}");
                    if self.reorderer.insert(seqno, payload) {
                        to_ack.push(seqno);
                    }
                }
                Message::Rel {
                    kind: RelKind::DataAck,
                    stream_id: _,
                    seqno: lowest_unseen_seqno, // *one greater* than the last packet that got to the other side
                    payload: selective_acks,
                } => {
                    // mark every packet whose seqno is less than the given seqno as acked.
                    for _ in 0..self.inflight.mark_acked_lt(lowest_unseen_seqno) {
                        self.congestion.mark_ack(self.inflight.bdp());
                    }
                    // then, we interpret the payload as a vector of acks that should additional be taken care of.
                    if let Ok(sacks) = stdcode::deserialize::<Vec<u64>>(&selective_acks) {
                        for sack in sacks {
                            self.inflight.mark_acked(sack);
                        }
                    }
                }
                Message::Rel {
                    kind: RelKind::Syn,
                    stream_id,
                    seqno,
                    payload,
                } => {
                    // retransmit our syn-ack
                    outgoing_callback(Message::Rel {
                        kind: RelKind::SynAck,
                        stream_id,
                        seqno,
                        payload,
                    });
                }
                Message::Rel {
                    kind: RelKind::Rst,
                    stream_id,
                    seqno,
                    payload,
                } => {
                    self.phase = Phase::Closed;
                }
                msg => log::error!("not yet implemented handling for {:?}", msg),
            }
        }
        // Then, drain the reorderer
        for (seqno, packet) in self.reorderer.take() {
            self.next_unseen_seqno = seqno + 1;
            self.queues.lock().read_stream.write_all(&packet).unwrap();
            self.ready.notify_all();
        }
        // Then, generate an ack.
        if !to_ack.is_empty() {
            to_ack.retain(|a| a >= &self.next_unseen_seqno);
            outgoing_callback(Message::Rel {
                kind: RelKind::DataAck,
                stream_id: self.stream_id,
                seqno: self.next_unseen_seqno,
                payload: to_ack.stdcode().into(),
            });
        }
    }

    fn tick_write(&mut self, now: Instant, mut outgoing_callback: impl FnMut(Message)) {
        // first, we attempt to fill the congestion window as far as possible.
        // every time we add another segment, we also transmit it, and set the RTO.
        let cwnd = self.congestion.cwnd();
        while self.inflight.inflight() < cwnd {
            let mut queues = self.queues.lock();
            if queues.write_stream.is_empty() {
                queues.write_stream.shrink_to_fit();
                break;
            }

            let mut buffer = vec![0; MSS];
            let n = queues.write_stream.read(&mut buffer).unwrap();
            buffer.truncate(n);
            let seqno = self.next_write_seqno;
            self.next_write_seqno += 1;
            let msg = Message::Rel {
                kind: RelKind::Data,
                stream_id: self.stream_id,
                seqno,
                payload: buffer.into(),
            };
            self.inflight.insert(msg.clone());
            outgoing_callback(msg);

            self.ready.notify_all();

            log::trace!("filled {}/{} of cwnd", self.inflight.inflight(), cwnd);
        }

        // then, we do any retransmissions if necessary
        while let Some((seqno, retrans_time)) = self.inflight.first_rto() {
            let cwnd = self.congestion.cwnd();
            let inflight = self.inflight.inflight();
            if now >= retrans_time {
                if cwnd >= inflight {
                    self.congestion.mark_loss();
                }

                // we rate-limit retransmissions.
                // this is a quick and dirty way of preventing retransmissions themselves from overwhelming the network right when the pipe is full
                if now.saturating_duration_since(self.last_retrans).as_millis() > 10 {
                    log::debug!("after loss: {inflight}/{cwnd} of cwnd");
                    log::debug!("RTO retransmit {}", seqno);
                    let first = self.inflight.retransmit(seqno).expect("no first");
                    outgoing_callback(first);
                    self.last_retrans = now;
                } else {
                    break;
                }
            } else {
                break;
            }
        }
    }

    fn retick_time(&self) -> Instant {
        // Instant::now() + Duration::from_millis(10)
        self.inflight
            .first_rto()
            .map(|s| s.1)
            .unwrap_or_else(|| Instant::now() + Duration::from_secs(1000))
    }
}

#[derive(Clone, Copy, Debug)]
enum Phase {
    Pending,
    SynSent { next_resend: Instant },
    Established,
    Closed,
}

#[derive(Default)]
struct StreamQueues {
    read_stream: VecDeque<u8>,
    write_stream: VecDeque<u8>,
    connected: bool,
    closed: bool,
}
