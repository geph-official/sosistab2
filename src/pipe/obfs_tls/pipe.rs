use std::net::SocketAddr;

use async_native_tls::TlsStream;
use async_trait::async_trait;
use bytes::Bytes;
use futures_util::AsyncWriteExt;

use smol::{
    channel::{Receiver, Sender},
    net::TcpStream,
};

use crate::Pipe;

use super::structs::{InnerMessage, OuterMessage};

pub struct ObfsTlsPipe {
    inner: async_dup::Arc<async_dup::Mutex<TlsStream<TcpStream>>>,
    send_write: Sender<InnerMessage>,
    peer_addr: SocketAddr,

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
        let inner = async_dup::Arc::new(async_dup::Mutex::new(inner));
        let (send_write, recv_write) = smol::channel::bounded(10);
        let _task = smolscale::spawn(send_loop(recv_write, inner.clone()));
        Self {
            inner,
            send_write,
            peer_addr,

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
        log::debug!("wrote cookie {:?}", cookie);
        connection
            .write_all(&(peer_metadata.len() as u32).to_be_bytes())
            .await?;
        connection.write_all(peer_metadata.as_bytes()).await?;
        connection.flush().await?;
        Ok(Self::new(connection, remote_addr, peer_metadata))
    }
}

async fn send_loop(
    recv_write: Receiver<InnerMessage>,
    mut inner: async_dup::Arc<async_dup::Mutex<TlsStream<TcpStream>>>,
) -> anyhow::Result<()> {
    loop {
        let new_write = recv_write.recv().await?;
        log::trace!("tls new write: {:?}", new_write);
        OuterMessage {
            version: 1,
            body: stdcode::serialize(&new_write)?.into(),
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
                InnerMessage::Pong(_) => {}
                InnerMessage::Ping(their_timestamp) => {
                    let _ = self
                        .send_write
                        .send(InnerMessage::Pong(their_timestamp))
                        .await;
                }
            }
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
