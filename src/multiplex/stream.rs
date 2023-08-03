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

use super::pipe_pool::RelKind;
mod congestion;

mod inflight;

/// [MuxStream] represents a reliable stream, multiplexed over a [Multiplex]. It implements [AsyncRead], [AsyncWrite], and [Clone], making using it very similar to using a TcpStream.
pub struct Stream {
    global_notify: WakeSource,
    // has Mutex to make the read future Sync. There's probably a better way of doing this.
    read_future: Mutex<Option<Pin<RecycleBox<dyn Future<Output = ()> + Send + 'static>>>>,
    read_future_resolved: bool,
    read_ready: Arc<async_event::Event>,
    inner: Arc<Mutex<StreamQueues>>,
}

impl Stream {
    /// Waits until this Stream is fully connected.
    pub async fn wait_connected(&self) -> std::io::Result<()> {
        todo!()
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
            read_future: Mutex::new(Some(RecycleBox::into_pin(coerce_box!(RecycleBox::new(
                async { smol::future::pending().await }
            ))))),
            read_future_resolved: true, // forces redoing the future on first read
            read_ready: self.read_ready.clone(),
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
        let mut read_future = self.read_future.lock().take().unwrap();
        // if resolved, then reset
        if self.read_future_resolved {
            let read_ready = self.read_ready.clone();
            let inner = self.inner.clone();
            read_future = RecycleBox::into_pin(coerce_box!(RecycleBox::recycle_pinned(
                read_future,
                async move {
                    read_ready
                        .wait_until(move || {
                            let inner = inner.lock();
                            if !inner.write_stream.is_empty() {
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
                self.read_future_resolved = true;
                *self.read_future.lock() = Some(read_future);
                Poll::Ready(self.inner.lock().write_stream.read(buf))
            }
            Poll::Pending => {
                self.read_future_resolved = false;
                *self.read_future.lock() = Some(read_future);
                Poll::Pending
            }
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        // Writes always succeed, and always tickle the ticker
        let n = self.inner.lock().write_stream.write(buf);
        self.global_notify.notify();
        Poll::Ready(n)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        todo!()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        todo!()
    }
}

pub(crate) struct StreamState {
    phase: StreamPhase,
    stream_id: u16,
    queues: Arc<Mutex<StreamQueues>>,
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
    pub fn inject_incoming(&mut self, _msg: Message) {
        todo!()
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
                if now >= next_resend {
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
            StreamPhase::Established => todo!(),
            StreamPhase::Closed => todo!(),
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
}
