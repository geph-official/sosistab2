use std::{any::Any, sync::Arc};

use crate::{multiplex::multiplex_actor, pipe::Pipe, MuxPublic, MuxSecret};

use concurrent_queue::ConcurrentQueue;
use futures_util::TryFutureExt;
use parking_lot::RwLock;
use smol::channel::{Receiver, Sender};
use smol_str::SmolStr;

use super::{pipe_pool::PipePool, MuxStream};

/// A multiplex session over a sosistab session, implementing both reliable "streams" and unreliable messages.
pub struct Multiplex {
    pipe_pool: Arc<PipePool>,
    conn_open: Sender<(SmolStr, Sender<MuxStream>)>,
    conn_accept: Receiver<MuxStream>,
    friends: ConcurrentQueue<Box<dyn Any + Send>>,
    their_long_pk: Arc<RwLock<Option<MuxPublic>>>,
    _task: smol::Task<()>,
}

fn to_ioerror<T: Into<Box<dyn std::error::Error + Send + Sync>>>(val: T) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::ConnectionReset, val)
}

impl Multiplex {
    /// Creates a new multiplexed Pipe. If `their_long_pk` is given, verify that the other side has the given public key.
    pub fn new(my_long_sk: MuxSecret, preshared_peer_pk: Option<MuxPublic>) -> Self {
        let pipe_pool = Arc::new(PipePool::new(10, preshared_peer_pk.is_none())); // use the naive method when we are the server
        let (conn_open, conn_open_recv) = smol::channel::unbounded();
        let (conn_accept_send, conn_accept) = smol::channel::unbounded();
        let bind_val = Arc::new(RwLock::new(None));
        let _task = smolscale::spawn(
            multiplex_actor::multiplex(
                pipe_pool.clone(),
                conn_open_recv,
                conn_accept_send,
                my_long_sk.0,
                preshared_peer_pk.map(|s| s.0),
                bind_val.clone(),
            )
            .unwrap_or_else(|e| {
                log::debug!("oh no the multiplex actor RETURNED?! {:?}", e);
            }),
        );
        Multiplex {
            pipe_pool, // placeholder
            conn_open,
            their_long_pk: bind_val,
            conn_accept,
            friends: ConcurrentQueue::unbounded(),
            _task,
        }
    }

    /// Returns the other side's public key. This is useful for "binding"-type authentication on the application layer, where the other end of the Multiplex does not have a preshared public key, but a public key that can be verified by e.g. a signature. Returns `None` if it's not yet known.
    pub fn peer_pk(&self) -> Option<MuxPublic> {
        *self.their_long_pk.read()
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
        let (send, recv) = smol::channel::unbounded();
        self.conn_open
            .send((additional.into(), send))
            .await
            .map_err(to_ioerror)?;
        if let Ok(s) = recv.recv().await {
            Ok(s)
        } else {
            smol::future::pending().await
        }
    }

    /// Accept a reliable conn from the other end.
    pub async fn accept_conn(&self) -> std::io::Result<MuxStream> {
        self.conn_accept.recv().await.map_err(to_ioerror)
    }
}
