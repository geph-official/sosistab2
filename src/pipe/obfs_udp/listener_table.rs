use anyhow::Context;

use itertools::Itertools;
use moka::sync::Cache;
use parking_lot::RwLock;
use smol::channel::{Receiver, Sender};
use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};

use crate::{
    crypt::{dnify_shared_secret, upify_shared_secret, ObfsAead},
    utilities::sockets::MyUdpSocket,
};

use super::frame::PipeFrame;

pub struct PipeTable {
    table: Arc<RwLock<HashMap<SocketAddr, PipeBack>>>,
    socket: MyUdpSocket,
    ip_blacklist: Arc<Cache<SocketAddr, ()>>,
}

#[derive(Clone)]
struct PipeBack {
    send_downcoded: Sender<PipeFrame>,
    decoder: ObfsAead,
    encoder: ObfsAead,
    recv_upcoded: Receiver<PipeFrame>,

    _task: Arc<smol::Task<()>>,
}

impl PipeTable {
    /// Constructor.
    pub fn new(socket: MyUdpSocket) -> Self {
        Self {
            table: Default::default(),
            socket,
            ip_blacklist: Arc::new(
                Cache::builder()
                    .max_capacity(100_000)
                    .time_to_idle(Duration::from_secs(120))
                    .build(),
            ),
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
            send_downcoded,
            decoder,
            encoder,
            recv_upcoded,
            _task: Arc::new(task),
        };
        self.table.write().insert(client_addr, pipe_back);
    }

    /// Attempts to decode and forward the packet to an existing pipe. If this fails, tries to decrypt this packet with all keys from table to see if the packet is from an existing session whose client ip has changed. If this also fails, returns None.
    pub async fn try_forward(&mut self, pkt: &[u8], client_addr: SocketAddr) -> anyhow::Result<()> {
        let try_fwd = async {
            let back = self
                .table
                .read()
                .get(&client_addr)
                .context("no entry in the table with this client_addr")?
                .clone();
            let ptext = back.decoder.decrypt(pkt)?;
            let msg = stdcode::deserialize(&ptext)?;

            back.send_downcoded.send(msg).await?;
            anyhow::Ok(())
        };
        match try_fwd.await {
            Ok(()) => Ok(()),
            Err(err) => {
                // roaming like this is highly DoS-vulnerable, so we use a blacklist mechanism.
                if self.ip_blacklist.contains_key(&client_addr) {
                    anyhow::bail!("bailing on blacklisted IP");
                }
                log::warn!(
                    "trying all entries because initial decryption failed: {:?}",
                    err
                );
                let mut table = self.table.write();
                let table_entries = table.iter().map(|s| (*s.0, s.1.clone())).collect_vec();
                // try all entries in table
                for (key, mut back) in table_entries {
                    if let Ok(ptext) = back.decoder.decrypt(pkt) {
                        let msg = stdcode::deserialize(&ptext)?;
                        let _ = back.send_downcoded.try_send(msg);

                        // update entry in table
                        table.remove(&key);
                        let task = smolscale::spawn(dn_forward_loop(
                            self.table.clone(),
                            self.socket.clone(),
                            client_addr,
                            back.encoder.clone(),
                            back.recv_upcoded.clone(),
                        ));
                        back._task = Arc::new(task);
                        table.insert(client_addr, back);
                        return Ok(());
                    };
                }
                self.ip_blacklist.insert(client_addr, ());
                anyhow::bail!("failed to match packet against any entries in the table")
            }
        }
    }
}

async fn dn_forward_loop(
    table: Arc<RwLock<HashMap<SocketAddr, PipeBack>>>,
    socket: MyUdpSocket,
    client_addr: SocketAddr,
    encoder: ObfsAead,
    recv_upcoded: Receiver<PipeFrame>,
) {
    let r: anyhow::Result<()> = async {
        loop {
            let msg = recv_upcoded.recv().await?;
            let ctext = encoder.encrypt(&stdcode::serialize(&msg)?);
            socket.send_to(&ctext, client_addr).await?;
        }
    }
    .await;
    if r.is_err() {
        table.write().remove(&client_addr);
    }
}
