use crate::multiplex::pipe_pool::Message;

use bytes::Bytes;

use diatomic_waker::WakeSource;

use parking_lot::Mutex;
use recycle_box::{coerce_box, RecycleBox};
use smol::prelude::*;

use std::{
    collections::VecDeque,
    io::{Read, Write},
    pin::Pin,
    sync::Arc,
    task::Context,
    task::Poll,
    time::{Duration, Instant},
};

use super::pipe_pool::{RelKind, Reorderer};
mod congestion;

mod inflight;

const MSS: usize = 1000;

/// [MuxStream] represents a reliable stream, multiplexed over a [Multiplex]. It implements [AsyncRead], [AsyncWrite], and [Clone], making using it very similar to using a TcpStream.
pub struct Stream {
    global_notify: WakeSource,
    read_ready_future: Option<Pin<RecycleBox<dyn Future<Output = ()> + Send + 'static>>>,
    read_ready_resolved: bool,
    write_ready_future: Option<Pin<RecycleBox<dyn Future<Output = ()> + Send + 'static>>>,
    write_ready_resolved: bool,
    ready: Arc<async_event::Event>,
    inner: Arc<Mutex<StreamQueues>>,
}

/// SAFETY: because of the definition of AsyncRead, it's not possible to ever concurrently end up polling the futures in the RecycleBoxes.
unsafe impl Sync for Stream {}

impl Stream {
    /// Waits until this Stream is fully connected.
    pub async fn wait_connected(&self) -> std::io::Result<()> {
        self.ready
            .wait_until(|| {
                if self.inner.lock().connected {
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
        todo!()
    }

    /// Shuts down the stream, causing future read and write operations to fail.
    pub async fn shutdown(&mut self) {
        todo!()
    }

    /// Sends an unreliable datagram.
    pub async fn send_urel(&self, dgram: Bytes) -> std::io::Result<()> {
        todo!()
    }

    /// Receives an unreliable datagram.
    pub async fn recv_urel(&self) -> std::io::Result<Bytes> {
        todo!()
    }
}

impl Clone for Stream {
    fn clone(&self) -> Self {
        Self {
            global_notify: self.global_notify.clone(),
            read_ready_future: Some(RecycleBox::into_pin(coerce_box!(RecycleBox::new(async {
                smol::future::pending().await
            })))),
            read_ready_resolved: true, // forces redoing the future on first read
            write_ready_future: Some(RecycleBox::into_pin(coerce_box!(RecycleBox::new(async {
                smol::future::pending().await
            })))),
            write_ready_resolved: true, // forces redoing the future on first write
            ready: self.ready.clone(),
            inner: self.inner.clone(),
        }
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
            let inner = self.inner.clone();
            read_future = RecycleBox::into_pin(coerce_box!(RecycleBox::recycle_pinned(
                read_future,
                async move {
                    read_ready
                        .wait_until(move || {
                            let inner = inner.lock();
                            if !inner.read_stream.is_empty() {
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
                Poll::Ready(self.inner.lock().read_stream.read(buf))
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
        let mut write_future = self.read_ready_future.take().unwrap();
        // if resolved, then reset
        if self.write_ready_resolved {
            let write_ready = self.ready.clone();
            let inner = self.inner.clone();
            // this waits until there's less than 4xMSS bytes waiting to be written. this produces the right backpressure
            write_future = RecycleBox::into_pin(coerce_box!(RecycleBox::recycle_pinned(
                write_future,
                async move {
                    write_ready
                        .wait_until(move || {
                            let inner = inner.lock();
                            if inner.write_stream.len() <= MSS * 4 {
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
                Poll::Ready(self.inner.lock().write_stream.write(buf))
            }
            Poll::Pending => {
                self.write_ready_resolved = false;
                self.write_ready_future = Some(write_future);
                Poll::Pending
            }
        }
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // TODO FILL THIS IN
        Poll::Ready(Ok(()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

pub(crate) struct StreamState {
    phase: StreamPhase,
    stream_id: u16,
    incoming_queue: Vec<Message>,
    queues: Arc<Mutex<StreamQueues>>,
    ready: Arc<async_event::Event>,

    // read variables
    read_until: u64,
    reorderer: Reorderer<Bytes>,
    // write variables
    inflight: Option<Message>,
    retransmit_time: Instant,
    next_write_seqno: u64,
}

impl StreamState {
    /// Creates a new StreamState, in the pre-SYN-sent state. Also returns the "user-facing" handle.
    pub fn new_pending(_stream_id: u16) -> (Self, Stream) {
        todo!()
    }

    /// Creates a new StreamState, in the established state. Also returns the "user-facing" handle.
    pub fn new_established(_stream_id: u16) -> (Self, Stream) {
        todo!()
    }

    /// Injects an incoming message.
    pub fn inject_incoming(&mut self, msg: Message) {
        self.incoming_queue.push(msg);
    }

    /// "Ticks" this StreamState, which advances its state. Any outgoing messages generated are passed to the callback given. Returns the correct time to call tick again at.
    pub fn tick(&mut self, mut outgoing_callback: impl FnMut(Message)) -> Instant {
        let now: Instant = Instant::now();

        match self.phase {
            StreamPhase::Pending => {
                // send a SYN, and transition into SynSent
                outgoing_callback(Message::Rel {
                    kind: RelKind::Syn,
                    stream_id: self.stream_id,
                    seqno: 0,
                    payload: Default::default(),
                });
                let next_resend = now + Duration::from_secs(1);
                self.phase = StreamPhase::SynSent { next_resend };
                next_resend
            }
            StreamPhase::SynSent { next_resend } => {
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
                    self.phase = StreamPhase::Established;
                    self.queues.lock().connected = true;
                    self.ready.notify_all();
                    now
                } else if now >= next_resend {
                    outgoing_callback(Message::Rel {
                        kind: RelKind::Syn,
                        stream_id: self.stream_id,
                        seqno: 0,
                        payload: Default::default(),
                    });
                    let next_resend = now + Duration::from_secs(1);
                    self.phase = StreamPhase::SynSent { next_resend };
                    next_resend
                } else {
                    next_resend
                }
            }
            StreamPhase::Established => {
                // First, handle receiving packets. This is the easier part.
                self.tick_read(&mut outgoing_callback);
                // Then, handle sending packets. This involves congestion control, so it's the harder part.
                self.tick_write(now, &mut outgoing_callback);
                // Finally, calculate the next interval. TODO: right now this is just busy-looping again 5 ms from the present, as a placeholder!
                now + Duration::from_millis(5)
            }
            StreamPhase::Closed => todo!(),
        }
    }

    fn tick_read(&mut self, mut outgoing_callback: impl FnMut(Message)) {
        // First, put all incoming packets into the reorderer.
        for packet in self.incoming_queue.drain(..) {
            match packet {
                Message::Rel {
                    kind: RelKind::Data,
                    stream_id: _,
                    seqno,
                    payload,
                } => {
                    self.reorderer.insert(seqno, payload);
                }
                _ => todo!(),
            }
        }
        // Then, drain the reorderer
        let mut gen_ack = false;
        for (seqno, packet) in self.reorderer.take() {
            self.read_until = self.read_until.max(seqno);
            self.queues.lock().read_stream.write_all(&packet).unwrap();
            self.ready.notify_all();
            gen_ack = true;
        }
        // Then, generate an ack. This acks every packet up to incoming_nogap_until using the seqno field, which is the bare minimum for correct behavior.
        if gen_ack {
            outgoing_callback(Message::Rel {
                kind: RelKind::DataAck,
                stream_id: self.stream_id,
                seqno: self.read_until,
                payload: Bytes::new(),
            });
        }
    }

    fn tick_write(&mut self, now: Instant, mut outgoing_callback: impl FnMut(Message)) {
        // Currently, an EXTREMELY TRIVIAL single-packet stop-and-go as a placeholder.
        match &self.inflight {
            Some(pkt) => {
                // if we're past the retransmit time, just retransmit and reset the retransmit time to 1 second after now.
                if now >= self.retransmit_time {
                    self.retransmit_time = now + Duration::from_secs(1);
                    outgoing_callback(pkt.clone());
                }
            }
            None => {
                // if nothing is inflight, we can pick something off of the queue and transmit it
                let mut buf = vec![0; MSS];
                let n = self
                    .queues
                    .lock()
                    .write_stream
                    .read(&mut buf)
                    .unwrap_or_default();
                if n > 0 {
                    buf.truncate(n);
                    let to_send = Message::Rel {
                        kind: RelKind::Data,
                        stream_id: self.stream_id,
                        seqno: self.next_write_seqno,
                        payload: buf.into(),
                    };
                    outgoing_callback(to_send.clone());
                    self.next_write_seqno += 1;
                    self.inflight = Some(to_send);
                    self.ready.notify_all();
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum StreamPhase {
    Pending,
    SynSent { next_resend: Instant },
    Established,
    Closed,
}

struct StreamQueues {
    read_stream: VecDeque<u8>,
    write_stream: VecDeque<u8>,
    connected: bool,
}
