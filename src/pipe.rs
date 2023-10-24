use std::{ops::Deref, sync::Arc};

use async_trait::async_trait;
use bytes::Bytes;

use smol::future::FutureExt;

/// Abstracts over any "pipe" that can carry datagrams along one particular path. This should almost always be used in conjunction with [crate::Multiplex].
#[async_trait]
pub trait Pipe: Send + Sync + 'static {
    /// Sends a datagram to the other side. Should never block; if the datagram cannot be sent quickly it should simply be dropped.
    ///
    /// Datagrams of at least 65535 bytes must be accepted, but larger datagrams might not be.
    fn send(&self, to_send: Bytes);

    /// Receives the next datagram from the other side. If the pipe has failed, this must return an error promptly.
    async fn recv(&self) -> std::io::Result<Bytes>;

    /// Return a static string slice that identifies the protocol.
    fn protocol(&self) -> &str;

    /// Return a static string slice that contains arbitrary metadata, set by the peer.
    fn peer_metadata(&self) -> &str;

    /// Return a protocol-specific address identifying the other side.
    fn peer_addr(&self) -> String;
}

#[async_trait]
impl<P: Pipe + ?Sized, T: Deref<Target = P> + Send + Sync + 'static> Pipe for T {
    fn send(&self, to_send: Bytes) {
        self.deref().send(to_send)
    }

    async fn recv(&self) -> std::io::Result<Bytes> {
        self.deref().recv().await
    }

    fn protocol(&self) -> &str {
        self.deref().protocol()
    }

    fn peer_metadata(&self) -> &str {
        self.deref().peer_metadata()
    }

    fn peer_addr(&self) -> String {
        self.deref().peer_addr()
    }
}

/// Abstracts over any "listener" that can receive [Pipe]s.
///
/// To avoid "viral generics", trait objects are returned.
#[async_trait]
pub trait PipeListener: Sized + Send + Sync {
    /// Accepts the next pipe at this listener.
    async fn accept_pipe(&self) -> std::io::Result<Arc<dyn Pipe>>;

    /// Combines this PipeListener with another PipeListener.
    fn or<T: PipeListener>(self, other: T) -> OrPipeListener<Self, T> {
        OrPipeListener {
            left: self,
            right: other,
        }
    }
}

pub struct OrPipeListener<T: PipeListener + Sized, U: PipeListener + Sized> {
    left: T,
    right: U,
}

#[async_trait]
impl<T: PipeListener, U: PipeListener> PipeListener for OrPipeListener<T, U> {
    async fn accept_pipe(&self) -> std::io::Result<Arc<dyn Pipe>> {
        self.left.accept_pipe().or(self.right.accept_pipe()).await
    }
}
