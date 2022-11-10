use anyhow::Context;

use moka::sync::Cache;
use smol::{
    channel::{Receiver, Sender},
    net::UdpSocket,
};
use std::{net::SocketAddr, sync::Arc};

use crate::crypt::{dnify_shared_secret, upify_shared_secret, ObfsAead};

use super::frame::PipeFrame;

pub struct PipeTable {
    table: Cache<SocketAddr, PipeBack>,
    socket: UdpSocket,
}

#[derive(Clone)]
struct PipeBack {
    recv_upcoded: Receiver<PipeFrame>,
    send_downcoded: Sender<PipeFrame>,
    encoder: ObfsAead,
    decoder: ObfsAead,
    _task: Arc<smol::Task<()>>,
}

impl PipeTable {
    /// Constructor.
    pub fn new(max_capacity: u64, socket: UdpSocket) -> Self {
        Self {
            table: Cache::new(max_capacity),
            socket,
        }
    }
    /// Adds a new entry to the table.
    pub fn add_entry(
        &mut self,
        client_addr: SocketAddr,
        recv_upcoded: Receiver<PipeFrame>,
        send_downcoded: Sender<PipeFrame>,
        sess_key: &[u8],
    ) {
        let up_key = upify_shared_secret(sess_key);
        let dn_key = dnify_shared_secret(sess_key);
        let encoder = ObfsAead::new(dn_key.as_bytes());
        let decoder = ObfsAead::new(up_key.as_bytes());

        // start down-forwarding actor
        let task = smolscale::spawn(dn_forward_loop(
            self.table.clone(),
            self.socket.clone(),
            client_addr,
            encoder.clone(),
            recv_upcoded.clone(),
        ));

        let pipe_back = PipeBack {
            recv_upcoded,
            send_downcoded,
            encoder,
            decoder,
            _task: Arc::new(task),
        };
        self.table.insert(client_addr, pipe_back);
    }

    /// Attempts to decode and forward the packet to an existing pipe. If this fails, tries to decrypt this packet with all keys from table to see if the packet is from an existing session whose client ip has changed. If this also fails, returns None.
    pub async fn try_forward(&mut self, pkt: &[u8], client_addr: SocketAddr) -> anyhow::Result<()> {
        let try_fwd = async {
            let back = self
                .table
                .get(&client_addr)
                .context("no entry in the table with this client_addr")?;
            let ptext = back.decoder.decrypt(pkt)?;
            let msg = bincode::deserialize(&ptext)?;
            back.send_downcoded.send(msg).await?;
            anyhow::Ok(())
        };
        match try_fwd.await {
            Ok(()) => Ok(()),
            Err(err) => {
                log::debug!(
                    "trying all entries because initial decryption failed: {:?}",
                    err
                );
                // try all entries in table
                for (key, mut back) in self.table.iter() {
                    if let Ok(ptext) = back.decoder.decrypt(pkt) {
                        let msg = bincode::deserialize(&ptext)?;
                        back.send_downcoded.send(msg).await?;

                        // update entry in table
                        self.table.invalidate(&key);
                        let task = smol::spawn(dn_forward_loop(
                            self.table.clone(),
                            self.socket.clone(),
                            client_addr,
                            back.encoder.clone(),
                            back.recv_upcoded.clone(),
                        ));
                        back._task = Arc::new(task);
                        self.table.insert(client_addr, back);
                        return Ok(());
                    };
                }
                anyhow::bail!("failed to match packet against any entries in the table")
            }
        }
    }
}

async fn dn_forward_loop(
    table: Cache<SocketAddr, PipeBack>,
    socket: UdpSocket,
    client_addr: SocketAddr,
    encoder: ObfsAead,
    recv_upcoded: Receiver<PipeFrame>,
) {
    let r: anyhow::Result<()> = async {
        loop {
            let msg = recv_upcoded.recv().await?;
            log::trace!("gonna send down {:?}", msg);
            let ctext = encoder.encrypt(&bincode::serialize(&msg)?);
            socket.send_to(&ctext, client_addr).await?;
        }
    }
    .await;
    if r.is_err() {
        table.invalidate(&client_addr)
    }
}
