use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use bytes::Bytes;
use parking_lot::Mutex;
use rustc_hash::FxHashMap;
use serde::{Deserialize, Serialize};
use smol::{
    channel::{Receiver, Sender},
    lock::RwLock,
};

use crate::Pipe;

/// A sequence number.
pub type Seqno = u64;
/// An outer message.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum OuterMessage {
    /// Frame sent from client to server when opening a connection. This is always globally encrypted.
    ClientHello {
        long_pk: x25519_dalek::PublicKey,
        eph_pk: x25519_dalek::PublicKey,
        version: u64,
        /// seconds since the unix epoch
        timestamp: u64,
    },
    /// Frame sent from server to client to give a cookie for finally opening a connection.
    ServerHello {
        long_pk: x25519_dalek::PublicKey,
        eph_pk: x25519_dalek::PublicKey,
    },

    /// Non-handshake messages; inner = serialized EncryptedFrame
    EncryptedMsg { inner: Bytes },
}

/// A message
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Message {
    Rel {
        kind: RelKind,
        stream_id: u16,
        seqno: Seqno,
        payload: Bytes,
    },
    Urel {
        stream_id: u16,
        payload: Bytes,
    },
    Empty,
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub enum RelKind {
    Syn,
    SynAck,
    Data,
    DataAck,
    Fin,
    FinAck,
    Rst,
}

#[derive(Clone)]
pub struct Reorderer<T: Clone> {
    pkts: FxHashMap<Seqno, T>,
    min: Seqno,
}

impl<T: Clone> Default for Reorderer<T> {
    fn default() -> Self {
        Reorderer {
            pkts: FxHashMap::default(),
            min: 0,
        }
    }
}
impl<T: Clone> Reorderer<T> {
    /// Inserts an item into the reorderer. Returns true iff the item is accepted or has been accepted in the past.
    pub fn insert(&mut self, seq: Seqno, item: T) -> bool {
        if seq >= self.min && seq <= self.min + 20000 {
            if self.pkts.insert(seq, item).is_some() {
                log::debug!("spurious retransmission of {} received", seq);
            }
            true
        } else {
            log::debug!("out of order (seq={}, min={})", seq, self.min);
            // if less than min, we still accept
            seq < self.min
        }
    }
    pub fn take(&mut self) -> Vec<T> {
        let mut output = Vec::with_capacity(self.pkts.len());
        for idx in self.min.. {
            if let Some(item) = self.pkts.remove(&idx) {
                output.push(item.clone());
                self.min = idx + 1;
            } else {
                break;
            }
        }
        output
    }
}

#[allow(clippy::type_complexity)]
pub struct PipePool {
    pipes: RwLock<Vec<(Arc<dyn Pipe>, smol::Task<()>)>>,
    size_limit: usize,
    send_incoming: Sender<Bytes>,
    recv_incoming: Receiver<Bytes>,
    last_pipe: Mutex<Option<(Arc<dyn Pipe>, Instant)>>,
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
            last_pipe: Default::default(),
            _task: task,
        }
    }

    /// Adds a Pipe to the PipePool, deleting the worst-performing pipe if there are too many Pipes in the PipePool.
    pub async fn add_pipe(&self, pipe: impl Pipe) {
        let mut v = self.pipes.write().await;

        while v.len() + 1 >= self.size_limit {
            // find the index with the worst score
            let worst_idx = v
                .iter()
                .map(|(pipe, _)| pipe.clone())
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
        let bb = self.last_pipe.lock().as_ref().map(|(k, v)| (k.clone(), *v));
        if let Some((last, time)) = bb {
            if time.elapsed() < Duration::from_millis(400) {
                last.send(pkt).await;
                return;
            }
        }
        let v = self.pipes.read().await;
        for (pipe, _) in v.iter() {
            pipe.send(Bytes::from_static(b"!!ping!!")).await;
        }

        let best_pipe = v
            .iter()
            .map(|(pipe, _)| pipe.clone())
            .enumerate()
            .min_by_key(|(_i, pipe)| pipe.get_stats().score())
            .map(|t| t.1);
        if let Some(best_pipe) = best_pipe {
            log::debug!(
                "best pipe is {} / {}",
                best_pipe.peer_addr(),
                best_pipe.protocol()
            );
            best_pipe.send(pkt).await;
            drop(v);
            *self.last_pipe.lock() = Some((best_pipe.clone(), Instant::now()))
        }
    }

    pub async fn recv(&self) -> anyhow::Result<Bytes> {
        let ret = self.recv_incoming.recv().await?;
        Ok(ret)
    }
}

async fn pipe_associated_task(pipe: Arc<dyn Pipe>, send_incoming: Sender<Bytes>) {
    loop {
        let pkt = pipe.recv().await;
        if let Ok(pkt) = pkt {
            // these are invalid messages anyway
            if pkt[..] == b"!!ping!!"[..] {
                // in this case, we just reflect back a pong

                pipe.send(Bytes::from_static(b"!!pong!!")).await;
            } else if pkt[..] != b"!!pong!!"[..] {
                let _ = send_incoming.send(pkt).await;
            }
        } else {
            log::warn!("STOPPING");
            return;
        }
    }
}
