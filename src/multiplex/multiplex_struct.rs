use std::sync::Arc;

use crate::{multiplex::multiplex_actor, pipe::Pipe, Stream};

use bytes::Bytes;
use futures_util::TryFutureExt;
use smol::{
    channel::{Receiver, Sender},
    lock::RwLock,
};

/// A multiplex session over a sosistab session, implementing both reliable "streams" and unreliable messages.
pub struct Multiplex {
    pipe_pool: Arc<PipePool>,
    conn_open: Sender<(Option<String>, Sender<Stream>)>,
    conn_accept: Receiver<Stream>,
    _task: smol::Task<()>,
}

fn to_ioerror<T: Into<Box<dyn std::error::Error + Send + Sync>>>(val: T) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::ConnectionReset, val)
}

impl Multiplex {
    /// Creates a new multiplexed Pipe
    pub fn new(my_long_sk: x25519_dalek::StaticSecret) -> Self {
        let pipe_pool = Arc::new(PipePool::new(10)); // placeholder value
        let (conn_open, conn_open_recv) = smol::channel::unbounded();
        let (conn_accept_send, conn_accept) = smol::channel::unbounded();
        let _task = smolscale::spawn(
            multiplex_actor::multiplex(
                pipe_pool.clone(),
                conn_open_recv,
                conn_accept_send,
                my_long_sk,
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
    pub async fn add_pipe(&mut self, pipe: Pipe) {
        self.pipe_pool.add_pipe(pipe).await
    }

    /// Open a reliable conn to the other end.
    pub async fn open_conn(&self, additional: Option<String>) -> std::io::Result<Stream> {
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
    pub async fn accept_conn(&self) -> std::io::Result<Stream> {
        self.conn_accept.recv().await.map_err(to_ioerror)
    }
}

pub struct PipePool {
    pipes: RwLock<Vec<(Arc<Pipe>, smol::Task<()>)>>,
    size_limit: usize,
    send_incoming: Sender<Bytes>,
    recv_incoming: Receiver<Bytes>,
    _task: smol::Task<()>,
}

impl PipePool {
    /// Creates a new instance of PipePool that reads bts from up_recv and sends them down the "best" pipe available and sends pkts from all pipes to send_incoming
    pub fn new(size_limit: usize) -> Self {
        let (send_incoming, recv_incoming) = smol::channel::bounded(1);
        let pipes = RwLock::new(Vec::new());
        let task = smolscale::spawn(async {});
        Self {
            pipes,
            size_limit,
            send_incoming,
            recv_incoming,
            _task: task,
        }
    }

    /// Adds a Pipe to the PipePool, deleting the worst-performing pipe if there are too many Pipes in the PipePool.
    pub async fn add_pipe(&self, pipe: Pipe) {
        let mut v = self.pipes.write().await;

        while v.len() + 1 >= self.size_limit {
            // find the index with the worst score
            let worst_idx = v
                .iter()
                .map(|(pipe, _)| pipe)
                .enumerate()
                .max_by_key(|(_i, pipe)| pipe.get_stats().score())
                .map(|t| t.0)
                .unwrap();
            let _ = v.remove(worst_idx);
        }
        let arc_pipe = Arc::new(pipe);
        let task = smolscale::spawn(pipe_associated_task(
            arc_pipe.clone(),
            self.send_incoming.clone(),
        ));

        v.push((arc_pipe, task))
    }

    pub async fn send(&self, pkt: Bytes) {
        let v = self.pipes.read().await;
        let best_pipe = v
            .iter()
            .map(|(pipe, _)| pipe)
            .enumerate()
            .min_by_key(|(_i, pipe)| pipe.get_stats().score())
            .map(|t| t.1)
            .unwrap();
        best_pipe.send(pkt).await
    }

    pub async fn recv(&self) -> anyhow::Result<Bytes> {
        let ret = self.recv_incoming.recv().await?;
        Ok(ret)
    }
}

async fn pipe_associated_task(pipe: Arc<Pipe>, send_incoming: Sender<Bytes>) {
    loop {
        let pkt = pipe.recv().await;
        let _ = send_incoming.send(pkt).await;
    }
}
