use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::Context;
use async_trait::async_trait;
use bytes::Bytes;
use futures_util::AsyncReadExt;
use smol::{
    channel::{Receiver, Sender},
    net::TcpListener,
    Task,
};
use smol_timeout::TimeoutExt;
use subtle::ConstantTimeEq;

use crate::{Pipe, PipeListener};

use super::pipe::ObfsTlsPipe;

/// A listener for obfuscated TLS pipes.
pub struct ObfsTlsListener {
    recv_pipe: Receiver<ObfsTlsPipe>,
    _task: Task<anyhow::Result<()>>,
}

#[async_trait]
impl PipeListener for ObfsTlsListener {
    async fn accept_pipe(&self) -> std::io::Result<Arc<dyn Pipe>> {
        Ok(Arc::new(self.recv_pipe.recv().await.map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::BrokenPipe, e)
        })?))
    }
}

impl ObfsTlsListener {
    /// Binds this listener to the given address, with the given TLS configuration and symmetric "cookie". The cookie can be of arbitrary length.
    pub async fn bind(
        addr: SocketAddr,
        tls_conf: native_tls::TlsAcceptor,
        cookie: Bytes,
    ) -> std::io::Result<Self> {
        let acceptor = async_native_tls::TlsAcceptor::from(tls_conf);
        let inner = TcpListener::bind(addr).await?;
        let (send_pipe, recv_pipe) = smol::channel::bounded(100);
        let _task = smolscale::spawn(tls_listen_loop(send_pipe, inner, acceptor, cookie));
        Ok(Self { recv_pipe, _task })
    }
}

async fn tls_listen_loop(
    send_pipe: Sender<ObfsTlsPipe>,
    inner: TcpListener,
    acceptor: async_native_tls::TlsAcceptor,
    cookie: Bytes,
) -> anyhow::Result<()> {
    loop {
        let (client, client_addr) = inner.accept().await?;
        let acceptor = acceptor.clone();
        let send_pipe = send_pipe.clone();
        let cookie = cookie.clone();
        smolscale::spawn(async move {
            let negotiate = async {
                let mut accepted = acceptor.accept(client).await?;
                log::debug!("accepted a TLS connection");
                // check that the other side knows about the cookie. we don't need anything fancy if we trust tls
                if !cookie.is_empty() {
                    let mut buffer = vec![0u8; cookie.len()];
                    accepted.read_exact(&mut buffer).await?;
                    if !(bool::from(buffer[..].ct_eq(&cookie[..]))) {
                        anyhow::bail!("cookie wrong")
                    }
                }
                log::debug!("cookie read successfully");
                // then read the metadata, which is prepended by a u32be length
                let mut metadata_length = [0u8; 4];
                accepted.read_exact(&mut metadata_length).await?;
                let mut metadata_buff = vec![0u8; u32::from_be_bytes(metadata_length) as usize];
                accepted.read_exact(&mut metadata_buff).await?;
                // construct the pipe and send it on
                anyhow::Ok(ObfsTlsPipe::new(
                    accepted,
                    client_addr,
                    &String::from_utf8_lossy(&metadata_buff),
                ))
            };
            let pipe = negotiate
                .timeout(Duration::from_secs(10))
                .await
                .context("timeout")??;
            let _ = send_pipe.try_send(pipe);
            anyhow::Ok(())
        })
        .detach();
    }
}
