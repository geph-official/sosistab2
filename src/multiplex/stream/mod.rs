use crate::multiplex::pipe_pool::{Message, RelKind};
use async_dup::Arc as DArc;
use async_dup::Mutex as DMutex;
use bytes::Bytes;
use connvars::ConnVars;

use futures_util::{stream::IntoAsyncRead, TryStream, TryStreamExt};
use sluice::pipe::{PipeReader, PipeWriter};
use smol::channel::{Receiver, Sender};
use smol::prelude::*;
use smol_str::SmolStr;
use std::{
    pin::Pin,
    sync::Arc,
    task::Context,
    task::Poll,
    time::{Duration, Instant},
};
mod congestion;
mod connvars;
mod inflight;
mod stream_state;

pub const MSS: usize = 16384; // pretty large MSS; rely on underlying transport to fragment
const MAX_WAIT_SECS: u64 = 60;

type ByteReceiverInner = Pin<
    Box<
        dyn TryStream<Item = std::io::Result<Bytes>, Error = std::io::Error, Ok = Bytes>
            + Send
            + Sync
            + 'static,
    >,
>;

type ByteReceiver = DArc<DMutex<IntoAsyncRead<ByteReceiverInner>>>;

#[derive(Clone)]
/// [MuxStream] represents a reliable stream, multiplexed over a [Multiplex]. It implements [AsyncRead], [AsyncWrite], and [Clone], making using it very similar to using a TcpStream.
pub struct MuxStream {
    send_write: DArc<DMutex<PipeWriter>>,
    send_write_urel: Sender<Bytes>,
    recv_read: ByteReceiver,
    recv_read_urel: Receiver<Bytes>,
    additional_info: SmolStr,
}

impl MuxStream {
    /// Returns the "additional info" attached to the stream.
    pub fn additional_info(&self) -> &str {
        &self.additional_info
    }

    /// Shuts down the stream, causing future read and write operations to fail.
    pub async fn shutdown(&mut self) {
        drop(self.send_write.close().await)
    }

    /// Sends an unreliable datagram.
    pub async fn send_urel(&self, dgram: Bytes) -> std::io::Result<()> {
        self.send_write_urel
            .send(dgram)
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "cannot send"))
    }

    /// Receives an unreliable datagram.
    pub async fn recv_urel(&self) -> std::io::Result<Bytes> {
        match self.recv_read_urel.recv().await {
            Ok(val) => Ok(val),
            Err(err) => Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, err)),
        }
    }
}

impl AsyncRead for MuxStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        let recv_read = &mut self.recv_read;
        smol::pin!(recv_read);
        recv_read.poll_read(cx, buf)
    }
}

impl AsyncWrite for MuxStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let send_write = &mut self.send_write;
        smol::pin!(send_write);
        send_write.poll_write(cx, buf)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let send_write = &mut self.send_write;
        smol::pin!(send_write);
        send_write.poll_close(cx)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let send_write = &mut self.send_write;
        smol::pin!(send_write);
        send_write.poll_flush(cx)
    }
}

pub struct StreamState {}

impl StreamState {
    /// Creates a new StreamState, in the SYN-received state.
    pub fn new_syn_received(stream_id: u16) -> Self {
        todo!()
    }

    /// Injects an incoming message.
    pub fn inject_incoming(&mut self, msg: Message) {
        todo!()
    }

    /// "Ticks" this StreamState, which advances its state. Any outgoing messages generated are passed to the callback given. Returns the correct time to call tick again at.
    pub fn tick(&mut self, outgoing_callback: impl FnMut(Message)) -> Instant {
        todo!()
    }
}
