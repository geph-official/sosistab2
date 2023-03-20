use bytes::Bytes;
use dashmap::DashMap;

use rand::prelude::*;

use replay_filter::ReplayFilter;
use smol::channel::{Receiver, Sender};
use smol::prelude::*;
use smol_str::SmolStr;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{sync::Arc, time::Duration};

use crate::multiplex::pipe_pool::Message;

use crate::crypt::{triple_ecdh, NonObfsAead};

use super::{
    pipe_pool::{OuterMessage, PipePool, RelKind},
    stream::{StreamBack, StreamState},
    MuxStream,
};

pub async fn multiplex(
    pipe_pool: Arc<PipePool>,
    conn_open_recv: Receiver<(SmolStr, Sender<MuxStream>)>,
    conn_accept_send: Sender<MuxStream>,
    my_long_sk: x25519_dalek::StaticSecret,
    real_their_long_pk: Option<x25519_dalek::PublicKey>,
) -> anyhow::Result<()> {
    // encryption parameters
    let my_eph_sk_send = x25519_dalek::StaticSecret::new(rand::thread_rng());
    let my_eph_sk_recv = x25519_dalek::StaticSecret::new(rand::thread_rng());
    let mut send_aead: Option<NonObfsAead> = None;
    let mut recv_aead: Option<NonObfsAead> = None;
    let mut replay_filter = ReplayFilter::default();

    let conn_tab = Arc::new(ConnTable::default());
    let (glob_send, glob_recv) = smol::channel::unbounded();
    let (dead_send, dead_recv) = smol::channel::unbounded();

    // Reap death
    let reap_dead = {
        let dead_send = dead_send.clone();
        move |id: u16| {
            log::debug!("reaper received {}", id);
            smolscale::spawn(async move {
                smol::Timer::after(Duration::from_secs(30)).await;
                log::debug!("reaper executed {}", id);
                let _ = dead_send.try_send(id);
            })
            .detach()
        }
    };

    // enum of possible events
    enum Event {
        RecvMsg(OuterMessage),
        SendMsg(Message),
        ConnOpen(SmolStr, Sender<MuxStream>),
        Dead(u16),
    }

    loop {
        // fires on receiving messages
        let recv_msg = async {
            let raw_msg = pipe_pool.recv().await?;
            // decrypt!
            let msg = stdcode::deserialize(&raw_msg);
            if let Ok(msg) = msg {
                Ok::<_, anyhow::Error>(Event::RecvMsg(msg))
            } else {
                log::trace!("unrecognizable message from sess: {:?}", raw_msg);
                smol::future::pending().await
            }
        };
        // fires on sending messages
        let send_msg = async {
            let to_send = glob_recv.recv().await?;
            Ok::<_, anyhow::Error>(Event::SendMsg(to_send))
        };
        // fires on stream open events
        let conn_open = async {
            let (additional_data, result_chan) = conn_open_recv.recv().await?;
            Ok::<_, anyhow::Error>(Event::ConnOpen(additional_data, result_chan))
        };
        // fires on death
        let death = async {
            let res = dead_recv.recv().await?;
            Ok::<_, anyhow::Error>(Event::Dead(res))
        };
        // match on the event
        match recv_msg.or(send_msg.or(conn_open.or(death))).await? {
            Event::Dead(id) => conn_tab.del_stream(id),
            Event::ConnOpen(additional_data, result_chan) => {
                let conn_tab = conn_tab.clone();
                let glob_send = glob_send.clone();
                let reap_dead = reap_dead.clone();
                smolscale::spawn(async move {
                    let stream_id = {
                        let stream_id = conn_tab.find_id();
                        if let Some(stream_id) = stream_id {
                            let (send_sig, recv_sig) = smol::channel::bounded(1);
                            let (conn, conn_back) = MuxStream::new(
                                StreamState::SynSent {
                                    stream_id,
                                    tries: 0,
                                    result: send_sig,
                                },
                                glob_send.clone(),
                                move || reap_dead(stream_id),
                                additional_data.clone(),
                            );
                            smolscale::spawn(async move {
                                recv_sig.recv().await.ok()?;
                                result_chan.send(conn).await.ok()?;
                                Some(())
                            })
                            .detach();
                            conn_tab.set_stream(stream_id, conn_back);
                            stream_id
                        } else {
                            return;
                        }
                    };
                    log::trace!("conn open send {}", stream_id);
                    drop({
                        glob_send
                            .send(Message::Rel {
                                kind: RelKind::Syn,
                                stream_id,
                                seqno: 0,
                                payload: Bytes::copy_from_slice(additional_data.as_bytes()),
                            })
                            .await
                    });
                })
                .detach();
            }
            Event::SendMsg(msg) => {
                // if outgoing_key is available, encrypt and send off; else drop msg & send ClientHello
                if let Some(send_aead) = send_aead.as_mut() {
                    let (_, msg) = send_aead.encrypt(&stdcode::serialize(&msg).unwrap());
                    let outer = OuterMessage::EncryptedMsg { inner: msg };
                    pipe_pool
                        .send(stdcode::serialize(&outer).unwrap().into())
                        .await;
                } else {
                    log::debug!("no send_aead available, so we send a client hello");
                    let to_send = OuterMessage::ClientHello {
                        long_pk: (&my_long_sk).into(),
                        eph_pk: (&my_eph_sk_send).into(),
                        version: 1,
                        timestamp: SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_secs(),
                    };
                    pipe_pool
                        .send(stdcode::serialize(&to_send).unwrap().into())
                        .await;
                }
            }
            Event::RecvMsg(msg) => {
                match msg {
                    OuterMessage::ClientHello {
                        long_pk: their_long_pk,
                        eph_pk: their_eph_pk,
                        version: _,
                        timestamp: _,
                    } => {
                        if let Some(real) = real_their_long_pk {
                            if real != their_long_pk {
                                log::warn!("dropping invalid ClientHello");
                                continue;
                            }
                        }
                        let recv_secret = triple_ecdh(
                            &my_long_sk,
                            &my_eph_sk_recv,
                            &their_long_pk,
                            &their_eph_pk,
                        );
                        log::debug!("recv_secret {:?}", recv_secret);
                        recv_aead = Some(NonObfsAead::new(recv_secret.as_bytes()));
                        log::debug!("recv_aead registered since we received a clienthello");
                        // respond with a serverhello
                        let our_hello = OuterMessage::ServerHello {
                            long_pk: (&my_long_sk).into(),
                            eph_pk: (&my_eph_sk_recv).into(),
                        };
                        pipe_pool
                            .send(stdcode::serialize(&our_hello).unwrap().into())
                            .await;
                    }
                    OuterMessage::ServerHello {
                        long_pk: their_long_pk,
                        eph_pk: their_eph_pk,
                    } => {
                        if let Some(real) = real_their_long_pk {
                            if real != their_long_pk {
                                log::warn!("dropping invalid ServerHello");
                                continue;
                            }
                        }
                        let send_secret = triple_ecdh(
                            &my_long_sk,
                            &my_eph_sk_send,
                            &their_long_pk,
                            &their_eph_pk,
                        );
                        log::debug!("send_secret {:?}", send_secret);
                        send_aead = Some(NonObfsAead::new(send_secret.as_bytes()));
                        log::debug!("send_aead registered since we received a clienthello");
                    }

                    OuterMessage::EncryptedMsg { inner } => {
                        if let Some(recv_aead) = recv_aead.as_ref() {
                            match recv_aead.decrypt(&inner) {
                                Err(err) => {
                                    log::warn!("failed decrypting {} bytes: {:?}", inner.len(), err)
                                }
                                Ok((nonce, plain)) => {
                                    log::trace!("decrypted {} bytes, nonce {nonce}", plain.len());
                                    if replay_filter.add(nonce) {
                                        if let Ok(msg) = stdcode::deserialize::<Message>(&plain) {
                                            match msg {
                                                Message::Urel { stream_id, payload } => {
                                                    if let Some(val) =
                                                        conn_tab.get_stream(stream_id)
                                                    {
                                                        val.process(Message::Urel {
                                                            stream_id,
                                                            payload,
                                                        })
                                                        .await;
                                                    }
                                                }
                                                Message::Rel {
                                                    kind: RelKind::Syn,
                                                    stream_id,
                                                    payload,
                                                    ..
                                                } => {
                                                    if conn_tab.get_stream(stream_id).is_some() {
                                                        log::trace!(
                                                            "syn recv {} REACCEPT",
                                                            stream_id
                                                        );
                                                        let msg = Message::Rel {
                                                            kind: RelKind::SynAck,
                                                            stream_id,
                                                            seqno: 0,
                                                            payload: Bytes::copy_from_slice(&[]),
                                                        };
                                                        let _ = glob_send.try_send(msg);
                                                    } else {
                                                        log::trace!(
                                                            "syn recv {} ACCEPT",
                                                            stream_id
                                                        );
                                                        let lala =
                                                            String::from_utf8_lossy(&payload)
                                                                .to_string();
                                                        let additional_info = lala.into();
                                                        let reap_dead = reap_dead.clone();
                                                        let (new_conn, new_conn_back) =
                                                            MuxStream::new(
                                                                StreamState::SynReceived {
                                                                    stream_id,
                                                                },
                                                                glob_send.clone(),
                                                                move || {
                                                                    reap_dead(stream_id);
                                                                },
                                                                additional_info,
                                                            );
                                                        // the Stream itself is responsible for sending the SynAck. Here we just store the connection into the table, accept it, and be done with it.
                                                        conn_tab
                                                            .set_stream(stream_id, new_conn_back);
                                                        drop(conn_accept_send.send(new_conn).await);
                                                    }
                                                }
                                                // associated with existing connection
                                                Message::Rel {
                                                    stream_id, kind, ..
                                                } => {
                                                    if let Some(handle) =
                                                        conn_tab.get_stream(stream_id)
                                                    {
                                                        // log::trace!("handing over {:?} to {}", kind, stream_id);
                                                        handle.process(msg).await;
                                                    } else {
                                                        log::trace!(
                                                            "discarding {:?} to nonexistent {}",
                                                            kind,
                                                            stream_id
                                                        );
                                                        if kind != RelKind::Rst {
                                                            let msg = Message::Rel {
                                                                kind: RelKind::Rst,
                                                                stream_id,
                                                                seqno: 0,
                                                                payload: Bytes::copy_from_slice(&[]),
                                                            };
                                                            let _ = glob_send.send(msg).await;
                                                        }
                                                    }
                                                }
                                                Message::Empty => {}
                                            }
                                        }
                                    }
                                }
                            }
                        } else {
                            log::debug!(
                                "received {} bytes but we don't have recv_aead yet",
                                inner.len()
                            );
                        }
                    } // // connection opening
                }
            }
        }
    }
}

#[derive(Default)]
struct ConnTable {
    /// Maps IDs to Stream back handles.
    sid_to_stream: DashMap<u16, StreamBack>,
}

impl ConnTable {
    fn get_stream(&self, sid: u16) -> Option<StreamBack> {
        let x = self.sid_to_stream.get(&sid)?;
        Some(x.clone())
    }

    fn set_stream(&self, id: u16, handle: StreamBack) {
        self.sid_to_stream.insert(id, handle);
    }

    fn del_stream(&self, id: u16) {
        self.sid_to_stream.remove(&id);
    }

    fn find_id(&self) -> Option<u16> {
        loop {
            if self.sid_to_stream.len() >= 50000 {
                log::warn!("ran out of descriptors ({})", self.sid_to_stream.len());
                return None;
            }
            let possible_id: u16 = rand::thread_rng().gen();
            if self.sid_to_stream.get(&possible_id).is_none() {
                log::debug!(
                    "found id {} out of {}",
                    possible_id,
                    self.sid_to_stream.len()
                );
                break Some(possible_id);
            }
        }
    }
}
