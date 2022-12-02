use std::sync::Arc;

use crate::{multiplex::multiplex_actor, pipe::Pipe, MuxSecret};

use futures_util::TryFutureExt;
use smol::channel::{Receiver, Sender};

use super::{structs::PipePool, MuxStream};

/// A multiplex session over a sosistab session, implementing both reliable "streams" and unreliable messages.
pub struct Multiplex {
    pipe_pool: Arc<PipePool>,
    conn_open: Sender<(Option<String>, Sender<MuxStream>)>,
    conn_accept: Receiver<MuxStream>,
    _task: smol::Task<()>,
}

fn to_ioerror<T: Into<Box<dyn std::error::Error + Send + Sync>>>(val: T) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::ConnectionReset, val)
}

impl Multiplex {
    /// Creates a new multiplexed Pipe
    pub fn new(my_long_sk: MuxSecret) -> Self {
        let pipe_pool = Arc::new(PipePool::new(10)); // placeholder value
        let (conn_open, conn_open_recv) = smol::channel::unbounded();
        let (conn_accept_send, conn_accept) = smol::channel::unbounded();
        let _task = smolscale::spawn(
            multiplex_actor::multiplex(
                pipe_pool.clone(),
                conn_open_recv,
                conn_accept_send,
                my_long_sk.0,
            )
            .unwrap_or_else(|e| {
                panic!("oh no the multiplex actor RETURNED?! {:?}", e);
            }),
        );
        Multiplex {
            pipe_pool, // placeholder
            conn_open,
            conn_accept,
            _task,
        }
    }

    /// Adds a Pipe to the Multiplex
    pub async fn add_pipe(&self, pipe: impl Pipe) {
        self.pipe_pool.add_pipe(pipe).await
    }

    /// Open a reliable conn to the other end.
    pub async fn open_conn(&self, additional: Option<String>) -> std::io::Result<MuxStream> {
        let (send, recv) = smol::channel::unbounded();
        self.conn_open
            .send((additional.clone(), send))
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
