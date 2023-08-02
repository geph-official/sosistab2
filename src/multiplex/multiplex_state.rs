use std::sync::Arc;

use anyhow::Context;
use bytes::Bytes;
use dashmap::DashMap;
use rand::Rng;
use replay_filter::ReplayFilter;

use crate::{
    crypt::{triple_ecdh, NonObfsAead},
    multiplex::pipe_pool::RelKind,
    MuxPublic, MuxSecret,
};

use super::{
    pipe_pool::{Message, OuterMessage},
    stream::StreamBack,
};

/// An encapsulation of the entire state of a Multiplex.
pub struct MultiplexState {
    local_esk_send: x25519_dalek::StaticSecret,
    local_esk_recv: x25519_dalek::StaticSecret,
    send_aead: Option<NonObfsAead>,
    recv_aead: Option<NonObfsAead>,
    replay_filter: ReplayFilter,

    local_lsk: MuxSecret,
    peer_lpk: Option<MuxPublic>,

    conn_tab: Arc<ConnTable>,

    send_buffer: Vec<OuterMessage>,
}

impl MultiplexState {
    /// Encrypts a message for sending.
    fn encrypt_send_msg(&self, msg: Message) -> anyhow::Result<OuterMessage> {
        todo!()
    }

    /// Drains all messages produced by the multiplex state.
    pub fn drain_send_buffer(&mut self) -> impl Iterator<Item = OuterMessage> + '_ {
        self.send_buffer.drain(..)
    }

    /// Processes an incoming message.
    pub fn recv_msg(&mut self, msg: OuterMessage) -> anyhow::Result<()> {
        match msg {
            OuterMessage::ClientHello {
                long_pk,
                eph_pk,
                version,
                timestamp,
            } => {
                if self.peer_lpk.is_none() {
                    self.peer_lpk = Some(long_pk);
                }
                let recv_secret = triple_ecdh(
                    &self.local_lsk.0,
                    &self.local_esk_recv,
                    &self.peer_lpk.unwrap().0,
                    &eph_pk,
                );
                log::debug!("receive-side symmetric key registered: {:?}", recv_secret);
                self.recv_aead = Some(NonObfsAead::new(recv_secret.as_bytes()));
                let our_hello = OuterMessage::ServerHello {
                    long_pk: self.local_lsk.to_public(),
                    eph_pk: (&self.local_esk_recv).into(),
                };
                self.send_buffer.push(our_hello);
                Ok(())
            }
            OuterMessage::ServerHello { long_pk, eph_pk } => {
                if self.peer_lpk.is_none() {
                    self.peer_lpk = Some(long_pk);
                }
                let send_secret = triple_ecdh(
                    &self.local_lsk.0,
                    &self.local_esk_send,
                    &self.peer_lpk.unwrap().0,
                    &eph_pk,
                );
                log::debug!("send-side symmetric key registered: {:?}", send_secret);
                self.send_aead = Some(NonObfsAead::new(send_secret.as_bytes()));
                Ok(())
            }
            OuterMessage::EncryptedMsg { inner } => {
                let recv_aead = &self
                    .recv_aead
                    .context("cannot decrypt messages without receive-side symmetric key")?;
                let (nonce, inner) = recv_aead.decrypt(&inner)?;
                if !self.replay_filter.add(nonce) {
                    anyhow::bail!("replay filter caught nonce {nonce}");
                }
                let inner: Message =
                    stdcode::deserialize(&inner).context("could not deserialize message")?;
                match &inner {
                    Message::Rel {
                        kind,
                        stream_id,
                        seqno,
                        payload,
                    } => {
                        if self.conn_tab.get_stream(*stream_id).is_some() {
                            log::trace!("syn recv {} REACCEPT", stream_id);
                            let msg = Message::Rel {
                                kind: RelKind::SynAck,
                                stream_id: *stream_id,
                                seqno: 0,
                                payload: Bytes::copy_from_slice(&[]),
                            };
                            let msg = self
                                .encrypt_send_msg(msg)
                                .context("cannot encrypted syn-ack response to syn")?;
                            self.send_buffer.push(msg);
                        } else {
                            log::trace!("syn recv {} ACCEPT", stream_id);
                            todo!("nyonyo wtd to open a stream properly")
                        }
                    }
                    Message::Urel { stream_id, payload } => {
                        let stream = self
                            .conn_tab
                            .get_stream(*stream_id)
                            .context("urel with unkown stream id")?;
                        stream.process(inner);
                    }
                    Message::Empty => {}
                }
                Ok(())
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
