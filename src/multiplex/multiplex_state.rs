use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use ahash::AHashMap;
use anyhow::Context;
use async_event::Event;
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
    stream::StreamState,
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

    stream_tab: AHashMap<u16, StreamState>,
    // notify this when the streams need to be rescanned
    stream_update: Event,
}

impl MultiplexState {
    /// "Ticks" the state forward once. Returns the time before which this method should be called again.
    pub fn tick(&mut self, mut outgoing_callback: impl FnMut(OuterMessage)) -> Instant {
        // encryption
        let outgoing_callback = |msg: Message| todo!();

        // iterate through every stream, ticking it, finding the minimum of the instants
        let insta = self
            .stream_tab
            .values_mut()
            .map(|stream| stream.tick(outgoing_callback))
            .min();
        insta.unwrap_or_else(|| Instant::now() + Duration::from_secs(86400))
    }

    /// Processes an incoming message. If the message is rejected for whatever reason, an error is returned, but the state should be presumed to still be in a valid state.
    pub fn recv_msg(
        &mut self,
        msg: OuterMessage,
        mut outgoing_callback: impl FnMut(OuterMessage),
    ) -> anyhow::Result<()> {
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
                outgoing_callback(our_hello);
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
                let recv_aead = self
                    .recv_aead
                    .as_ref()
                    .context("cannot decrypt messages without receive-side symmetric key")?;
                let (nonce, inner) = recv_aead.decrypt(&inner)?;
                if !self.replay_filter.add(nonce) {
                    anyhow::bail!("replay filter caught nonce {nonce}");
                }
                let inner: Message =
                    stdcode::deserialize(&inner).context("could not deserialize message")?;
                match &inner {
                    Message::Rel {
                        kind: RelKind::Syn,
                        stream_id,
                        seqno: _,
                        payload: _,
                    } => {
                        if let Some(stream) = self.stream_tab.get_mut(stream_id) {
                            stream.inject_incoming(inner);
                            self.stream_update.notify_one();
                        } else {
                            log::trace!("syn recv {} ACCEPT", stream_id);
                            // create a new stream in the right state. we don't need to do anything else
                            let mut stream = StreamState::new_syn_received(*stream_id);
                            let stream_id = *stream_id;
                            stream.inject_incoming(inner);
                            self.stream_tab.insert(stream_id, stream);
                            self.stream_update.notify_one();
                        }
                    }
                    Message::Rel {
                        kind: _,
                        stream_id,
                        seqno: _,
                        payload: _,
                    }
                    | Message::Urel {
                        stream_id,
                        payload: _,
                    } => {
                        let stream = self
                            .stream_tab
                            .get_mut(stream_id)
                            .context("urel with unknown stream id")?;
                        stream.inject_incoming(inner);
                    }

                    Message::Empty => {}
                }
                Ok(())
            }
        }
    }
}
