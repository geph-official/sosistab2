use std::{any::Any, sync::Arc};

use crate::{multiplex::multiplex_actor, pipe::Pipe, MuxPublic, MuxSecret};

use concurrent_queue::ConcurrentQueue;
use futures_util::TryFutureExt;
use smol::channel::{Receiver, Sender};
use smol_str::SmolStr;

use super::{structs::PipePool, MuxStream};

/// A multiplex session over a sosistab session, implementing both reliable "streams" and unreliable messages.
pub struct Multiplex {
    pipe_pool: Arc<PipePool>,
    conn_open: Sender<(SmolStr, Sender<MuxStream>)>,
    conn_accept: Receiver<MuxStream>,
    friends: ConcurrentQueue<Box<dyn Any + Send>>,
    _task: smol::Task<()>,
}

fn to_ioerror<T: Into<Box<dyn std::error::Error + Send + Sync>>>(val: T) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::ConnectionReset, val)
}

impl Multiplex {
    /// Creates a new multiplexed Pipe. If `their_long_sk` is given, verify that the other side has the given secret key.
    pub fn new(my_long_sk: MuxSecret, their_long_sk: Option<MuxPublic>) -> Self {
        let pipe_pool = Arc::new(PipePool::new(50)); // placeholder value
        let (conn_open, conn_open_recv) = smol::channel::unbounded();
        let (conn_accept_send, conn_accept) = smol::channel::unbounded();
        let _task = smolscale::spawn(
            multiplex_actor::multiplex(
                pipe_pool.clone(),
                conn_open_recv,
                conn_accept_send,
                my_long_sk.0,
                their_long_sk.map(|s| s.0),
            )
            .unwrap_or_else(|e| {
                log::debug!("oh no the multiplex actor RETURNED?! {:?}", e);
            }),
        );
        Multiplex {
            pipe_pool, // placeholder
            conn_open,
            conn_accept,
            friends: ConcurrentQueue::unbounded(),
            _task,
        }
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

    /// Removes all dead pipes from the multiplex, returning how many pipes were dead.
    pub fn clear_dead_pipes(&self) -> usize {
        self.pipe_pool.clear_dead()
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
