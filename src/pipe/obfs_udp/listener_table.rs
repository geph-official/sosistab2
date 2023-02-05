use anyhow::Context;

use itertools::Itertools;
use parking_lot::{RwLock, RwLockUpgradableReadGuard};
use smol::channel::{Receiver, Sender};
use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use crate::{
    crypt::{dnify_shared_secret, upify_shared_secret, ObfsAead},
    utilities::sockets::MyUdpSocket,
};

use super::{
    crypt::{ObfsDecrypter, ObfsEncrypter},
    frame::ObfsUdpFrame,
};

pub struct PipeTable {
    table: Arc<RwLock<HashMap<SocketAddr, PipeBack>>>,
    socket: MyUdpSocket,
}

#[derive(Clone)]
struct PipeBack {
    send_downcoded: Sender<ObfsUdpFrame>,
    decrypter: ObfsDecrypter,
    encrypter: ObfsEncrypter,
    recv_upcoded: Receiver<ObfsUdpFrame>,

    _task: Arc<smol::Task<anyhow::Result<()>>>,
}

impl PipeTable {
    /// Constructor.
    pub fn new(socket: MyUdpSocket) -> Self {
        Self {
            table: Default::default(),
            socket,
        }
    }
    /// Adds a new entry to the table.
    pub fn add_entry(
        &mut self,
        client_addr: SocketAddr,
        recv_upcoded: Receiver<ObfsUdpFrame>,
        send_downcoded: Sender<ObfsUdpFrame>,
        sess_key: &[u8],
    ) {
        let up_key = upify_shared_secret(sess_key);
        let dn_key = dnify_shared_secret(sess_key);
        let encrypter = ObfsEncrypter::new(ObfsAead::new(dn_key.as_bytes()));
        let decrypter = ObfsDecrypter::new(ObfsAead::new(up_key.as_bytes()));

        // start down-forwarding actor
        let task = smolscale::spawn(dn_forward_loop(
            self.table.clone(),
            self.socket.clone(),
            client_addr,
            encrypter.clone(),
            recv_upcoded.clone(),
        ));

        let pipe_back = PipeBack {
            send_downcoded,
            decrypter,
            encrypter,
            recv_upcoded,

            _task: Arc::new(task),
        };
        self.table.write().insert(client_addr, pipe_back);
    }

    /// Attempts to decode and forward the packet to an existing pipe. If
    pub async fn try_forward(&mut self, pkt: &[u8], client_addr: SocketAddr) -> anyhow::Result<()> {
        let table = self.table.upgradable_read();
        let back = table
            .get(&client_addr)
            .context("no entry in the table with this client_addr")?;
        if let Ok(msg) = back.decrypter.decrypt(pkt) {
            let _ = back.send_downcoded.try_send(msg);
            Ok(())
        } else {
            // try all the entries
            if let Ok(mut table) = RwLockUpgradableReadGuard::try_upgrade(table) {
                let table_entries = table.iter().map(|s| (*s.0, s.1.clone())).collect_vec();
                // try all entries in table
                for (key, mut back) in table_entries {
                    if let Ok(msg) = back.decrypter.decrypt(pkt) {
                        let _ = back.send_downcoded.try_send(msg);

                        // update entry in table
                        table.remove(&key);
                        let task = smolscale::spawn(dn_forward_loop(
                            self.table.clone(),
                            self.socket.clone(),
                            client_addr,
                            back.encrypter.clone(),
                            back.recv_upcoded.clone(),
                        ));
                        back._task = Arc::new(task);
                        table.insert(client_addr, back);
                        return Ok(());
                    };
                }

                anyhow::bail!("failed to match packet against any entries in the table")
            }
            anyhow::bail!("cannot decrypt incoming")
        }
    }
}

async fn dn_forward_loop(
    table: Arc<RwLock<HashMap<SocketAddr, PipeBack>>>,
    socket: MyUdpSocket,
    client_addr: SocketAddr,
    mut encrypter: ObfsEncrypter,
    recv_upcoded: Receiver<ObfsUdpFrame>,
) -> anyhow::Result<()> {
    scopeguard::defer!({
        table.write().remove(&client_addr);
    });
    loop {
        let msg = recv_upcoded.recv().await?;
        let ctext = encrypter.encrypt(&msg);
        let _ = socket.send_to(&ctext, client_addr).await;
    }
}
