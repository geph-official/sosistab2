use std::{
    collections::VecDeque,
    sync::Arc,
    time::{Duration, Instant},
};

use ahash::AHashMap;
use bytes::Bytes;

use event_listener::Event;

use parking_lot::{Mutex, RwLock};

use serde::{Deserialize, Serialize};
use smol::{
    channel::{Receiver, Sender},
    future::FutureExt,
    Task,
};

use crate::{MuxPublic, Pipe};

/// A sequence number.
pub type Seqno = u64;
/// An outer message.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum OuterMessage {
    /// Frame sent from client to server when opening a connection. This is always globally encrypted.
    ClientHello {
        long_pk: MuxPublic,
        eph_pk: x25519_dalek::PublicKey,
        version: u64,
        /// seconds since the unix epoch
        timestamp: u64,
    },
    /// Frame sent from server to client to give a cookie for finally opening a connection.
    ServerHello {
        long_pk: MuxPublic,
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
    pkts: AHashMap<Seqno, T>,
    min: Seqno,
}

impl<T: Clone> Default for Reorderer<T> {
    fn default() -> Self {
        Reorderer {
            pkts: AHashMap::default(),
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

struct SinglePipe {
    pipe: Arc<dyn Pipe>,
    ping_notify: Arc<Event>,
    _assoc_task: Task<()>,
    ping_us_accum: Option<u64>,
    pending_ping: Option<(Instant, Task<Duration>)>,
}

impl SinglePipe {
    /// Creates a new pipe manager.
    fn new(pipe: Arc<dyn Pipe>, send_incoming: Sender<(Bytes, Arc<dyn Pipe>)>) -> Self {
        let ping_notify = Arc::new(Event::new());

        let _assoc_task = smolscale::spawn(pipe_associated_task(
            ping_notify.clone(),
            pipe.clone(),
            send_incoming,
        ));
        Self {
            pipe: Arc::new(pipe),
            ping_notify,
            _assoc_task,
            ping_us_accum: None,
            pending_ping: None,
        }
    }
    /// Starts a pinger, if one is not already in progress.
    fn start_pinger(&mut self) {
        self.e2e_ping();
        let to_overwrite = self.pending_ping.is_none();
        if to_overwrite {
            let evlisten = self.ping_notify.listen();
            let start_time = Instant::now();
            let pipe = self.pipe.clone();
            self.pending_ping = Some((
                Instant::now(),
                smolscale::spawn(
                    async move {
                        evlisten.await;
                        start_time.elapsed()
                    }
                    .or(async move {
                        for ctr in 0u128.. {
                            log::debug!("******* ping {ctr}");
                            pipe.send(Bytes::from_static(b"!!ping!!")).await;
                            smol::Timer::after(Duration::from_secs(1)).await;
                        }
                        unreachable!()
                    }),
                ),
            ));
        }
    }

    /// Calculates the ping.
    fn e2e_ping(&mut self) -> Option<Duration> {
        // If pending, we attempt to merge
        let can_merge = self
            .pending_ping
            .as_ref()
            .map(|s| s.1.is_finished())
            .unwrap_or(false);
        if can_merge {
            let (_, task) = self.pending_ping.take().unwrap();
            let dur = smol::future::block_on(task).as_micros() as u64;
            self.ping_us_accum = Some(match self.ping_us_accum {
                Some(existing) => {
                    if dur > existing {
                        dur / 2 + existing / 2
                    } else {
                        dur / 4 + existing * 3 / 4
                    }
                }
                None => dur,
            });
        }
        let accum = self.ping_us_accum.map(Duration::from_micros)?;

        if let Some((pending_start, _)) = self.pending_ping {
            let elapsed = pending_start.elapsed();
            if elapsed > accum {
                return Some(elapsed / 2 + accum / 2);
            }
        }
        Some(accum)
    }
}

#[allow(clippy::type_complexity)]
pub struct PipePool {
    pipes: RwLock<VecDeque<Mutex<SinglePipe>>>,
    size_limit: usize,
    send_incoming: Sender<(Bytes, Arc<dyn Pipe>)>,
    recv_incoming: Receiver<(Bytes, Arc<dyn Pipe>)>,
    last_send_pipe: Mutex<Option<(Arc<dyn Pipe>, Instant)>>,
    last_recv_pipe: Mutex<Option<Arc<dyn Pipe>>>,

    naive_send: bool,
}

impl PipePool {
    /// Creates a new instance of PipePool that reads bts from up_recv and sends them down the "best" pipe available and sends pkts from all pipes to send_incoming
    pub fn new(size_limit: usize, naive_send: bool) -> Self {
        let (send_incoming, recv_incoming) = smol::channel::bounded(1);
        let pipes = RwLock::new(VecDeque::new());
        Self {
            pipes,
            size_limit,
            send_incoming,

            recv_incoming,
            last_send_pipe: Default::default(),
            last_recv_pipe: Default::default(),
            naive_send,
        }
    }

    /// Obtains the list of all pipes.
    pub fn all_pipes(&self) -> Vec<impl Pipe> {
        self.pipes
            .read()
            .iter()
            .map(|s| s.lock().pipe.clone())
            .collect()
    }

    /// Retain only the pipes the fit this criterion.
    pub fn retain(&self, mut f: impl FnMut(&dyn Pipe) -> bool) {
        self.pipes.write().retain(|p| f(&p.lock().pipe))
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
        let mut pipes = self.pipes.write();
        let pipe: Arc<dyn Pipe> = Arc::new(pipe);
        pipes.push_back(SinglePipe::new(pipe.clone(), self.send_incoming.clone()).into());
        if pipes.len() > self.size_limit {
            pipes.pop_front();
        }
        log::debug!("{} pipes in the mux", pipes.len());

        {
            let mut p = self.last_recv_pipe.lock();
            if p.is_none() {
                *p = Some(pipe.clone());
            }
        }
        {
            let mut p = self.last_send_pipe.lock();
            if p.is_none() {
                *p = Some((pipe, Instant::now()));
            }
        }
    }

    pub async fn send(&self, pkt: Bytes) {
        // If naive_send is true, we simply use the packet that we last *received* traffic from.
        // That pipe is *probably* alive, and if not the client will be opening a new one soon.
        if self.naive_send {
            if let Some(pipe) = self.last_recv_pipe() {
                pipe.send(pkt).await;
                return;
            }
        }

        let bb = self
            .last_send_pipe
            .lock()
            .as_ref()
            .map(|(k, v)| (k.clone(), *v));
        if let Some((last, time)) = bb {
            if time.elapsed() < Duration::from_millis(200) {
                last.send(pkt).await;
                return;
            }
        }
        let best_pipe = {
            let pipes = self.pipes.read();

            pipes
                .iter()
                .enumerate()
                .min_by_key(|(_i, single_pipe)| {
                    if fastrand::f64() < 0.2 {
                        single_pipe.lock().start_pinger();
                    }
                    single_pipe
                        .lock()
                        .e2e_ping()
                        .unwrap_or_else(|| Duration::from_secs(10))
                })
                .map(|t| t.1)
                .map(|p| p.lock().pipe.clone())
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

async fn pipe_associated_task(
    ping_notify: Arc<Event>,
    pipe: Arc<dyn Pipe>,
    send_incoming: Sender<(Bytes, Arc<dyn Pipe>)>,
) {
    loop {
        let pkt = pipe.recv().await;
        if let Ok(pkt) = pkt {
            // these are invalid messages anyway
            if pkt[..] == b"!!ping!!"[..] {
                // in this case, we just reflect back a pong

                pipe.send(Bytes::from_static(b"!!pong!!")).await;
            } else if pkt[..] == b"!!pong!!"[..] {
                ping_notify.notify(1);
            } else {
                let _ = send_incoming.send((pkt, pipe.clone())).await;
            }
        } else {
            return;
        }
    }
}
