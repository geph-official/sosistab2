mod multiplex_state;
mod pipe_pool;
mod stream;
use std::{any::Any, sync::Arc};

use concurrent_queue::ConcurrentQueue;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
// pub use congestion::*;
pub use stream::MuxStream;

use crate::Pipe;

use self::pipe_pool::PipePool;

/// A multiplex session over a sosistab session, implementing both reliable "streams" and unreliable messages.
pub struct Multiplex {
    pipe_pool: Arc<PipePool>,

    friends: ConcurrentQueue<Box<dyn Any + Send>>,

    _task: smol::Task<()>,
}

fn to_ioerror<T: Into<Box<dyn std::error::Error + Send + Sync>>>(val: T) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::ConnectionReset, val)
}

impl Multiplex {
    /// Creates a new multiplexed Pipe. If `their_long_pk` is given, verify that the other side has the given public key.
    pub fn new(my_long_sk: MuxSecret, preshared_peer_pk: Option<MuxPublic>) -> Self {
        todo!()
    }

    /// Returns this side's public key.
    pub fn local_pk(&self) -> MuxPublic {
        todo!()
    }

    /// Returns the other side's public key. This is useful for "binding"-type authentication on the application layer, where the other end of the Multiplex does not have a preshared public key, but a public key that can be verified by e.g. a signature. Returns `None` if it's not yet known.
    pub fn peer_pk(&self) -> Option<MuxPublic> {
        todo!()
    }

    /// Adds an arbitrary "friend" that will be dropped together with the multiplex. This is useful for managing RAII resources like tasks, tables etc that should live exactly as long as a particular multiplex.
    pub fn add_drop_friend(&self, friend: impl Any + Send) {
        self.friends.push(Box::new(friend)).unwrap()
    }

    /// Adds a Pipe to the Multiplex
    pub fn add_pipe(&self, pipe: impl Pipe) {
        self.pipe_pool.add_pipe(pipe)
    }

    /// Obtains the pipe last used by this multiplex for sending.
    pub fn last_send_pipe(&self) -> Option<impl Pipe> {
        self.pipe_pool.last_send_pipe()
    }

    /// Obtains the pipe last used by this multiplex for receiving.
    pub fn last_recv_pipe(&self) -> Option<impl Pipe> {
        self.pipe_pool.last_recv_pipe()
    }

    /// Iterates through *all* the underlying pipes.
    pub fn iter_pipes(&self) -> impl Iterator<Item = impl Pipe> + '_ {
        self.pipe_pool.all_pipes().into_iter()
    }

    /// Retain only the pipes that fit a certain criterion.
    pub fn retain(&self, f: impl FnMut(&dyn Pipe) -> bool) {
        self.pipe_pool.retain(f)
    }

    /// Open a reliable conn to the other end.
    pub async fn open_conn(&self, additional: &str) -> std::io::Result<MuxStream> {
        todo!()
    }

    /// Accept a reliable conn from the other end.
    pub async fn accept_conn(&self) -> std::io::Result<MuxStream> {
        todo!()
    }
}

/// A server public key for the end-to-end multiplex.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct MuxPublic(pub(crate) x25519_dalek::PublicKey);

impl MuxPublic {
    /// Returns the bytes representation.
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    /// Convert from bytes.
    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(x25519_dalek::PublicKey::from(b))
    }
}

/// A server secret key for the end-to-end multiplex.
#[derive(Clone, Serialize, Deserialize)]
pub struct MuxSecret(pub(crate) x25519_dalek::StaticSecret);

impl MuxSecret {
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
    pub fn to_public(&self) -> MuxPublic {
        MuxPublic((&self.0).into())
    }
}
