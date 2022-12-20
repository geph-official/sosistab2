use std::{
    collections::VecDeque,
    net::SocketAddr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use async_native_tls::TlsStream;
use async_trait::async_trait;
use bytes::Bytes;
use futures_util::AsyncWriteExt;
use once_cell::sync::Lazy;
use parking_lot::RwLock;
use smol::{
    channel::{Receiver, Sender},
    future::FutureExt,
    net::TcpStream,
};

use crate::{utilities::BatchTimer, Pipe, PipeStats};

use super::structs::{InnerMessage, OuterMessage};

pub struct ObfsTlsPipe {
    inner: async_dup::Arc<async_dup::Mutex<TlsStream<TcpStream>>>,
    send_write: Sender<InnerMessage>,
    peer_addr: SocketAddr,

    pings: RwLock<VecDeque<Duration>>,
    pings_outstanding: Arc<AtomicUsize>,

    peer_metadata: String,

    _task: smol::Task<anyhow::Result<()>>,
}

impl ObfsTlsPipe {
    /// Create a new pipe.
    pub(crate) fn new(
        inner: TlsStream<TcpStream>,
        peer_addr: SocketAddr,
        peer_metadata: &str,
    ) -> Self {
        let pings_outstanding = Arc::new(AtomicUsize::new(0));
        let inner = async_dup::Arc::new(async_dup::Mutex::new(inner));
        let (send_write, recv_write) = smol::channel::bounded(10);
        let _task = smolscale::spawn(send_loop(
            pings_outstanding.clone(),
            recv_write,
            inner.clone(),
        ));
        Self {
            inner,
            send_write,
            peer_addr,
            pings: Default::default(),
            pings_outstanding,
            peer_metadata: peer_metadata.into(),
            _task,
        }
    }

    /// Connect to a remote address, with the given TLS configuration and cookie. The cookie is a shared symmetric secret between the client and server, and can be of arbitrary length.
    pub async fn connect(
        remote_addr: SocketAddr,
        tls_hostname: &str,
        tls_conf_builder: native_tls::TlsConnectorBuilder,
        cookie: Bytes,
        peer_metadata: &str,
    ) -> std::io::Result<Self> {
        let connector = async_native_tls::TlsConnector::from(tls_conf_builder);
        let connection = TcpStream::connect(remote_addr).await?;
        connection.set_nodelay(true)?;
        let mut connection = connector
            .connect(tls_hostname, connection)
            .await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::ConnectionReset, e))?;
        connection.write_all(&cookie).await?;
        eprintln!("wrote cookie {:?}", cookie);
        connection
            .write_all(&(peer_metadata.len() as u32).to_be_bytes())
            .await?;
        connection.write_all(peer_metadata.as_bytes()).await?;
        connection.flush().await?;
        Ok(Self::new(connection, remote_addr, peer_metadata))
    }
}

static START_INSTANT: Lazy<Instant> = Lazy::new(Instant::now);

async fn send_loop(
    pings_outstanding: Arc<AtomicUsize>,
    recv_write: Receiver<InnerMessage>,
    mut inner: async_dup::Arc<async_dup::Mutex<TlsStream<TcpStream>>>,
) -> anyhow::Result<()> {
    let mut ping_timer = BatchTimer::new(Duration::from_millis(100), 100);
    loop {
        let send_write = async {
            let new_write = recv_write.recv().await?;
            anyhow::Ok(new_write)
        };
        let send_ping = async {
            ping_timer.wait().await;
            anyhow::Ok(InnerMessage::Ping(
                START_INSTANT.elapsed().as_millis() as u64
            ))
        };
        let msg = send_write.race(send_ping).await?;
        if matches!(msg, InnerMessage::Ping(_)) {
            ping_timer.reset();
            pings_outstanding.fetch_add(1, Ordering::SeqCst);
        } else {
            ping_timer.increment();
        }
        OuterMessage {
            version: 1,
            body: stdcode::serialize(&msg)?.into(),
        }
        .write(&mut inner)
        .await?;
    }
}

#[async_trait]
impl Pipe for ObfsTlsPipe {
    async fn send(&self, to_send: Bytes) {
        // TODO reuse memory of to_send
        for chunk in to_send.chunks(60000) {
            let _ = self
                .send_write
                .try_send(InnerMessage::Normal(Bytes::copy_from_slice(chunk)));
        }
    }

    async fn recv(&self) -> std::io::Result<Bytes> {
        loop {
            let msg = OuterMessage::read(self.inner.clone()).await?;
            let inner: InnerMessage = stdcode::deserialize(&msg.body)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            match inner {
                InnerMessage::Normal(b) => return Ok(b),
                InnerMessage::Pong(timestamp) => {
                    let now = START_INSTANT.elapsed().as_millis() as u64;
                    let ping = Duration::from_millis(now.saturating_sub(timestamp));
                    self.pings_outstanding.store(0, Ordering::SeqCst);
                    let mut pings = self.pings.write();
                    pings.push_back(ping);
                    if pings.len() > 100 {
                        pings.pop_front();
                    }
                }
                InnerMessage::Ping(their_timestamp) => {
                    let _ = self
                        .send_write
                        .send(InnerMessage::Pong(their_timestamp))
                        .await;
                }
            }
        }
    }

    fn get_stats(&self) -> PipeStats {
        let pings = self.pings.read();
        let latency: Duration = pings
            .iter()
            .copied()
            .fold(Duration::from_secs(0), |d, p| d + p)
            .max(Duration::from_secs(1))
            / (pings.len() as u32).max(1);
        let jitter = Duration::from_secs_f64(
            (pings
                .iter()
                .map(|p| (p.as_secs_f64() - latency.as_secs_f64()).powi(2))
                .sum::<f64>()
                / (pings.len().max(1) as f64))
                .sqrt(),
        );
        log::debug!(
            "TLS stats: latency = {:.2}ms, jitter = {:.2}ms",
            latency.as_secs_f64() * 1000.0,
            jitter.as_secs_f64() * 1000.0
        );
        PipeStats {
            dead: self.pings_outstanding.load(Ordering::SeqCst) > 3 || self._task.is_finished(),
            loss: 0.0,
            latency,
            jitter,
        }
    }

    fn protocol(&self) -> &str {
        "obfstls-1"
    }

    fn peer_addr(&self) -> String {
        self.peer_addr.to_string()
    }

    fn peer_metadata(&self) -> &str {
        &self.peer_metadata
    }
}
