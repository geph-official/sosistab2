use std::{
    collections::VecDeque,
    convert::Infallible,
    sync::Arc,
    time::{Duration, Instant},
};

use bytes::Bytes;

use event_listener::Event;

use futures_util::{stream::FuturesUnordered, StreamExt};
use parking_lot::{Mutex, RwLock};

use smol::{
    channel::{Receiver, Sender},
    future::FutureExt,
    Task,
};
use smol_timeout::TimeoutExt;
use smolscale::immortal::Immortal;

use crate::Pipe;

#[derive(Clone)]
struct SinglePipe {
    pipe: Arc<dyn Pipe>,
    ping_notify: Arc<Event>,
    _assoc_task: Arc<Task<()>>,
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
            _assoc_task: _assoc_task.into(),
        }
    }
    /// Pings the other end, returning only when a response is received.
    async fn measure_ping(&self) -> Duration {
        let start = Instant::now();
        let evlisten = self.ping_notify.listen();
        let start_time = Instant::now();
        let pipe = self.pipe.clone();
        async move {
            evlisten.await;
            start_time.elapsed()
        }
        .race(async move {
            let mut wait_millis = 1000;
            loop {
                pipe.send(Bytes::from_static(b"!!ping!!"));
                smol::Timer::after(Duration::from_millis(wait_millis)).await;
                wait_millis = fastrand::u64(wait_millis..=(wait_millis * 2)).min(100000)
            }
        })
        .await;
        start.elapsed()
    }
}

#[allow(clippy::type_complexity)]
pub struct PipePool {
    pipes: Arc<RwLock<VecDeque<SinglePipe>>>,
    size_limit: usize,
    send_incoming: Sender<(Bytes, Arc<dyn Pipe>)>,
    recv_incoming: Receiver<(Bytes, Arc<dyn Pipe>)>,
    selected_send_pipe: Arc<Mutex<Option<Arc<dyn Pipe>>>>,
    last_recv_pipe: Mutex<Option<Arc<dyn Pipe>>>,

    last_significant_recv_time: Arc<RwLock<Instant>>,

    naive_send: bool,

    _stats_gatherer: Immortal,
}

async fn stats_gatherer_loop(
    last_recv_time: Arc<RwLock<Instant>>,
    selected_send_pipe: Arc<Mutex<Option<Arc<dyn Pipe>>>>,
    pipes: Arc<RwLock<VecDeque<SinglePipe>>>,
) -> Infallible {
    smol::Timer::after(Duration::from_secs(5)).await;
    loop {
        // wait until we're chill
        while last_recv_time.read().elapsed() < Duration::from_secs(1) {
            log::warn!("waiting for chillness before pinging");
            smol::Timer::after(Duration::from_secs(1)).await;
        }
        let measure = async {
            let mut ping_gatherer = FuturesUnordered::new();
            {
                let pipes = pipes.read();
                for pipe in pipes.iter() {
                    let pipe = pipe.clone();
                    ping_gatherer.push(async move {
                        let ping = pipe.measure_ping().await;
                        (pipe, ping)
                    })
                }
            }
            if let Some((best, ping)) = ping_gatherer.next().await {
                log::warn!(
                    "picked best pipe {}/{} with ping {:?}",
                    best.pipe.protocol(),
                    best.pipe.peer_addr(),
                    ping
                );
                *selected_send_pipe.lock() = Some(best.pipe.clone());
            }
        };
        if measure.timeout(Duration::from_secs(30)).await.is_none() {
            log::warn!("pinging all pipes timed out!")
        }
        smol::Timer::after(Duration::from_secs(60)).await;
    }
}

impl PipePool {
    /// Creates a new instance of PipePool that reads bts from up_recv and sends them down the "best" pipe available and sends pkts from all pipes to send_incoming
    pub fn new(size_limit: usize, naive_send: bool) -> Self {
        let (send_incoming, recv_incoming) = smol::channel::bounded(1);
        let pipes = Arc::new(RwLock::new(VecDeque::new()));
        let selected_send_pipe: Arc<Mutex<Option<Arc<dyn Pipe>>>> = Default::default();
        let last_significant_recv_time = Arc::new(RwLock::new(Instant::now()));
        Self {
            pipes: pipes.clone(),
            size_limit,
            send_incoming,

            recv_incoming,
            selected_send_pipe: selected_send_pipe.clone(),
            last_recv_pipe: Default::default(),
            naive_send,
            last_significant_recv_time: last_significant_recv_time.clone(),

            _stats_gatherer: if naive_send {
                Immortal::spawn(smol::future::pending())
            } else {
                Immortal::spawn(stats_gatherer_loop(
                    last_significant_recv_time,
                    selected_send_pipe,
                    pipes,
                ))
            },
        }
    }

    /// Obtains the list of all pipes.
    pub fn all_pipes(&self) -> Vec<impl Pipe> {
        self.pipes.read().iter().map(|s| s.pipe.clone()).collect()
    }

    /// Retain only the pipes the fit this criterion.
    pub fn retain(&self, mut f: impl FnMut(&dyn Pipe) -> bool) {
        self.pipes.write().retain(|p| f(&p.pipe))
    }

    /// Obtains the pipe last used for sending.
    pub fn last_send_pipe(&self) -> Option<impl Pipe> {
        let pipe = self.selected_send_pipe.lock();
        pipe.as_ref().cloned()
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
        pipes.push_back(SinglePipe::new(pipe.clone(), self.send_incoming.clone()));
        if pipes.len() > self.size_limit {
            let front = pipes.pop_front();
            if let Some(front) = front {
                let selected = self.selected_send_pipe.lock().clone();
                if let Some(selected) = selected {
                    if selected.peer_addr() == front.pipe.peer_addr() {
                        pipes.pop_front();
                        pipes.push_back(front);
                    }
                }
            }
        }
        log::debug!("{} pipes in the mux", pipes.len());

        {
            let mut p = self.last_recv_pipe.lock();
            if p.is_none() {
                *p = Some(pipe.clone());
            }
        }
        {
            let mut p = self.selected_send_pipe.lock();
            if p.is_none() {
                *p = Some(pipe);
            }
        }
    }

    pub async fn send(&self, pkt: Bytes) {
        // If naive_send is true, we simply use the packet that we last *received* traffic from.
        // That pipe is *probably* alive, and if not the client will be opening a new one soon.
        if self.naive_send {
            if let Some(pipe) = self.last_recv_pipe() {
                pipe.send(pkt);
                return;
            }
        }

        let bb = self.selected_send_pipe.lock().as_ref().cloned();
        if let Some(last) = bb {
            last.send(pkt);
        }
    }

    pub async fn recv(&self) -> anyhow::Result<Bytes> {
        let (ret, pipe) = self.recv_incoming.recv().await?;
        *self.last_recv_pipe.lock() = Some(pipe);
        // on average, we update the recv time every 100 KB of reads
        if fastrand::f64() < 0.01 * (ret.len() as f64 / 1000.0) {
            *self.last_significant_recv_time.write() = Instant::now();
        }
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

                pipe.send(Bytes::from_static(b"!!pong!!"));
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
