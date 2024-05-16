mod multiplex_state;
mod pipe_pool;
mod stream;
mod trace;
use std::{
    any::Any,
    sync::Arc,
    time::{Duration, Instant},
};

use concurrent_queue::ConcurrentQueue;

use futures_intrusive::sync::ManualResetEvent;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use smol::{
    channel::{Receiver, Sender},
    future::FutureExt,
};
use stdcode::StdcodeSerializeExt;

use crate::Pipe;

#[allow(deprecated)]
pub use stream::MuxStream;

pub use stream::stream_state::StreamState;
pub use stream::RelKind;
pub use stream::Stream;
pub use stream::StreamMessage;

use self::{multiplex_state::MultiplexState, pipe_pool::PipePool};

/// A multiplex session over a sosistab session, implementing both reliable "streams" and unreliable messages.
pub struct Multiplex {
    pipe_pool: Arc<PipePool>,
    state: Arc<Mutex<MultiplexState>>,
    friends: ConcurrentQueue<Box<dyn Any + Send>>,
    recv_accepted: Receiver<Stream>,

    _task: smol::Task<()>,
}

fn to_ioerror<T: Into<Box<dyn std::error::Error + Send + Sync>>>(val: T) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::ConnectionReset, val)
}

impl Multiplex {
    /// Creates a new multiplexed Pipe. If `their_long_pk` is given, verify that the other side has the given public key.
    pub fn new(local_sk: MuxSecret, preshared_peer_pk: Option<MuxPublic>) -> Self {
        let stream_update = Arc::new(ManualResetEvent::new(false));
        let state = Arc::new(Mutex::new(MultiplexState::new(
            stream_update.clone(),
            local_sk,
            preshared_peer_pk,
        )));
        let pipe_pool = Arc::new(PipePool::new(10, preshared_peer_pk.is_none()));
        let (send_accepted, recv_accepted) = smol::channel::unbounded();
        let _task = smolscale::spawn(multiplex_loop(
            state.clone(),
            stream_update,
            pipe_pool.clone(),
            send_accepted,
        ));
        Self {
            pipe_pool,
            state,
            friends: ConcurrentQueue::unbounded(),
            recv_accepted,
            _task,
        }
    }

    /// Returns this side's public key.
    pub fn local_pk(&self) -> MuxPublic {
        self.state.lock().local_lsk.to_public()
    }

    /// Returns the other side's public key. This is useful for "binding"-type authentication on the application layer, where the other end of the Multiplex does not have a preshared public key, but a public key that can be verified by e.g. a signature. Returns `None` if it's not yet known.
    pub fn peer_pk(&self) -> Option<MuxPublic> {
        self.state.lock().peer_lpk
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
    pub async fn open_conn(&self, additional: &str) -> std::io::Result<Stream> {
        // create a pre-open stream, then wait until the ticking makes it open
        let stream = self
            .state
            .lock()
            .start_open_stream(additional)
            .map_err(to_ioerror)?;
        stream.wait_connected().await?;
        Ok(stream)
    }

    /// Accept a reliable conn from the other end.
    pub async fn accept_conn(&self) -> std::io::Result<Stream> {
        self.recv_accepted.recv().await.map_err(to_ioerror)
    }
}

/// The master loop that starts the other loops
async fn multiplex_loop(
    state: Arc<Mutex<MultiplexState>>,
    stream_update: Arc<ManualResetEvent>,
    pipe_pool: Arc<PipePool>,
    send_accepted: Sender<Stream>,
) {
    // we don't spawn more things to avoid unnecessary contention over mutexes etc
    let ticker = tick_loop(state.clone(), stream_update, pipe_pool.clone());
    let incomer = incoming_loop(state, pipe_pool, send_accepted);
    if let Err(err) = ticker.race(incomer).await {
        log::error!("BUG: ticker or incomer died: {:?}", err)
    }
}

/// Handle incoming messages
async fn incoming_loop(
    state: Arc<Mutex<MultiplexState>>,
    pipe_pool: Arc<PipePool>,
    send_accepted: Sender<Stream>,
) -> anyhow::Result<()> {
    let mut send_queue = vec![];
    loop {
        let incoming = pipe_pool.recv().await?;
        log::trace!("incoming {} bytes", incoming.len());
        if let Ok(incoming) = stdcode::deserialize(&incoming) {
            // have the state process the message
            state
                .lock()
                .recv_msg(
                    incoming,
                    |msg| send_queue.push(msg),
                    |stream| {
                        let _ = send_accepted.try_send(stream);
                    },
                )
                .unwrap_or_else(|e| {
                    log::trace!("could not process message: {:?}", e);
                });

            // send all possible replies
            for msg in send_queue.drain(..) {
                pipe_pool.send(msg.stdcode().into()).await;
            }
        }
    }
}

/// Handle "ticking" the streams
async fn tick_loop(
    state: Arc<Mutex<MultiplexState>>,
    stream_update: Arc<ManualResetEvent>,
    pipe_pool: Arc<PipePool>,
) -> anyhow::Result<()> {
    let mut timer = smol::Timer::after(Duration::from_secs(0));
    let mut next_tick;
    let mut send_queue = vec![];
    loop {
        let start = Instant::now();
        next_tick = state.lock().tick(|msg| send_queue.push(msg));
        log::trace!("tick took {:?}", start.elapsed());
        // transmit all the queue
        for msg in send_queue.drain(..) {
            pipe_pool.send(msg.stdcode().into()).await;
        }
        // sleep first to prevent too aggressively looping around
        // this is also the basis for the brand of delayed-ack handling we do
        timer.set_at(Instant::now() + Duration::from_millis(2));
        (&mut timer).await;
        timer.set_at(next_tick);
        // horrifying hax
        async {
            stream_update.wait().await;
            stream_update.reset();
            log::trace!("update woken");
        }
        .or(async {
            (&mut timer).await;
            log::trace!("timer woken");
        })
        .await;
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
        Self(x25519_dalek::StaticSecret::random())
    }

    /// Convert to a public key.
    pub fn to_public(&self) -> MuxPublic {
        MuxPublic((&self.0).into())
    }
}
