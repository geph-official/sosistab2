use std::{
    collections::VecDeque,
    sync::Arc,
    time::{Duration, Instant},
};

use bytes::Bytes;
use parking_lot::{Mutex, RwLock};
use rustc_hash::FxHashMap;
use serde::{Deserialize, Serialize};
use smol::channel::{Receiver, Sender};

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
        log::trace!("reorder seq={}, min={}", seq, self.min);
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
    pipes: RwLock<VecDeque<(Arc<dyn Pipe>, smol::Task<()>)>>,
    size_limit: usize,
    send_incoming: Sender<(Bytes, Arc<dyn Pipe>)>,
    recv_incoming: Receiver<(Bytes, Arc<dyn Pipe>)>,
    last_send_pipe: Mutex<Option<(Arc<dyn Pipe>, Instant)>>,
    last_recv_pipe: Mutex<Option<Arc<dyn Pipe>>>,
}

impl PipePool {
    /// Creates a new instance of PipePool that reads bts from up_recv and sends them down the "best" pipe available and sends pkts from all pipes to send_incoming
    pub fn new(size_limit: usize) -> Self {
        let (send_incoming, recv_incoming) = smol::channel::bounded(1);
        let pipes = RwLock::new(VecDeque::new());
        Self {
            pipes,
            size_limit,
            send_incoming,
            recv_incoming,
            last_send_pipe: Default::default(),
            last_recv_pipe: Default::default(),
        }
    }

    /// Clears all the dead pipes. Returns the number of pipes cleared.
    pub fn clear_dead(&self) -> usize {
        let mut pipes = self.pipes.write();
        let start_len = pipes.len();
        pipes.retain(|f| !f.0.get_stats().dead);
        start_len - pipes.len()
    }

    /// Obtains the pipe last used for sending.
    pub fn last_send_pipe(&self) -> Option<impl Pipe> {
        let pipe = self.last_send_pipe.lock();
        pipe.as_ref().map(|p| p.0.clone())
    }

    /// Obtains the pipe last used for receiving.
    pub fn last_recv_pipe(&self) -> Option<impl Pipe> {
        let pipe = self.last_recv_pipe.lock();
        pipe.clone()
    }

    /// Adds a Pipe to the PipePool, deleting the oldest pipe if there are too many Pipes in the PipePool.
    pub fn add_pipe(&self, pipe: impl Pipe) {
        let mut v = self.pipes.write();

        let arc_pipe = Arc::new(pipe);
        let task = smolscale::spawn(pipe_associated_task(
            arc_pipe.clone(),
            self.send_incoming.clone(),
        ));

        v.push_back((arc_pipe.clone(), task));
        if v.len() > self.size_limit {
            v.pop_front();
        }

        {
            let mut p = self.last_recv_pipe.lock();
            if p.is_none() {
                *p = Some(arc_pipe.clone());
            }
        }
        {
            let mut p = self.last_send_pipe.lock();
            if p.is_none() {
                *p = Some((arc_pipe.clone(), Instant::now()));
            }
        }
    }

    pub async fn send(&self, pkt: Bytes) {
        let bb = self
            .last_send_pipe
            .lock()
            .as_ref()
            .map(|(k, v)| (k.clone(), *v));
        let last_used = if let Some((last, time)) = bb {
            if time.elapsed() < Duration::from_millis(2000) {
                last.send(pkt).await;
                return;
            }
            Some(last)
        } else {
            None
        };

        let best_pipe = {
            let v = self.pipes.read();
            for (pipe, _) in v.iter() {
                let pipe = pipe.clone();
                smolscale::spawn(async move {
                    pipe.send(Bytes::from_static(b"!!ping!!")).await;
                })
                .detach();
            }
            v.iter()
                .map(|(pipe, _)| pipe.clone())
                .enumerate()
                .min_by_key(|(_i, pipe)| {
                    let stats = pipe.get_stats();
                    log::debug!(
                        "pipe {} / {} has PING {:.2} +/- {:.2} ms, LOSS {:.2}%, SCORE {}",
                        pipe.peer_addr(),
                        pipe.protocol(),
                        stats.latency.as_secs_f64() * 1000.0,
                        stats.jitter.as_secs_f64() * 1000.0,
                        stats.loss * 100.0,
                        stats.score()
                    );
                    let this_score = stats.score();
                    if let Some(last_used) = last_used.as_ref() {
                        if pipe.peer_addr() == last_used.peer_addr() {
                            return (this_score as f64 * 0.8) as _;
                        }
                    }
                    this_score
                })
                .map(|t| t.1)
        };
        if let Some(best_pipe) = best_pipe {
            log::debug!(
                "best pipe is {} / {}",
                best_pipe.peer_addr(),
                best_pipe.protocol()
            );
            best_pipe.send(pkt).await;

            *self.last_send_pipe.lock() = Some((best_pipe.clone(), Instant::now()))
        }
    }

    pub async fn recv(&self) -> anyhow::Result<Bytes> {
        let (ret, pipe) = self.recv_incoming.recv().await?;
        *self.last_recv_pipe.lock() = Some(pipe);
        Ok(ret)
    }
}

async fn pipe_associated_task(pipe: Arc<dyn Pipe>, send_incoming: Sender<(Bytes, Arc<dyn Pipe>)>) {
    loop {
        let pkt = pipe.recv().await;
        if let Ok(pkt) = pkt {
            // these are invalid messages anyway
            if pkt[..] == b"!!ping!!"[..] {
                // in this case, we just reflect back a pong

                pipe.send(Bytes::from_static(b"!!pong!!")).await;
            } else if pkt[..] != b"!!pong!!"[..] {
                let _ = send_incoming.send((pkt, pipe.clone())).await;
            }
        } else {
            log::warn!("STOPPING");
            return;
        }
    }
}
