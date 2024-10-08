use std::{
    cmp::Reverse,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use ahash::AHashMap;
use anyhow::Context;

use bytes::Bytes;
use clone_macro::clone;
use crossbeam_queue::SegQueue;
use futures_intrusive::sync::ManualResetEvent;
use priority_queue::PriorityQueue;
use rand::Rng;
use rand_chacha::rand_core::OsRng;
use replay_filter::ReplayFilter;
use std::sync::Arc;
use stdcode::StdcodeSerializeExt;

use crate::{
    crypt::{triple_ecdh, NonObfsAead},
    frame::Frame,
    multiplex::{
        stream::RelKind,
        trace::{trace_incoming_msg, trace_outgoing_msg},
    },
    MuxPublic, MuxSecret, Stream,
};

use super::stream::{stream_state::StreamState, StreamMessage};

/// An encapsulation of the entire state of a Multiplex.
pub struct MultiplexState {
    local_esk_send: x25519_dalek::StaticSecret,
    local_esk_recv: x25519_dalek::StaticSecret,
    send_aead: Option<NonObfsAead>,
    recv_aead: Option<NonObfsAead>,
    replay_filter: ReplayFilter,

    pub local_lsk: MuxSecret,
    pub peer_lpk: Option<MuxPublic>,

    stream_tab: AHashMap<u16, StreamState>,
    // notify this when the streams need to be rescanned
    stream_tick_notify: Arc<ManualResetEvent>,
    force_ticks: Arc<SegQueue<u16>>,
    tick_times: PriorityQueue<u16, Reverse<Instant>>,
}

impl MultiplexState {
    /// Creates a new MultiplexState. "Retick" notifications are sent to the given Arc<ManualResetEvent>.
    pub fn new(
        stream_update: Arc<ManualResetEvent>,
        local_lsk: MuxSecret,
        peer_lpk: Option<MuxPublic>,
    ) -> Self {
        let local_esk_send = x25519_dalek::StaticSecret::new(OsRng {});
        let local_esk_recv = x25519_dalek::StaticSecret::new(OsRng {});
        Self {
            local_esk_send,
            local_esk_recv,
            send_aead: None,
            recv_aead: None,
            replay_filter: ReplayFilter::default(),
            local_lsk,
            peer_lpk,
            stream_tab: AHashMap::new(),
            force_ticks: Arc::new(SegQueue::new()),
            stream_tick_notify: stream_update,
            tick_times: PriorityQueue::new(),
        }
    }

    /// "Ticks" the state forward once. Returns the time before which this method should be called again.
    pub fn tick(&mut self, mut raw_callback: impl FnMut(Frame)) -> Instant {
        // if we do not have a send_aead, we send a hello and wait a second
        if self.send_aead.is_none() {
            let hello = Frame::ClientHello {
                long_pk: self.local_lsk.to_public(),
                eph_pk: (&self.local_esk_send).into(),
                version: 1,
                timestamp: (SystemTime::now().duration_since(UNIX_EPOCH).unwrap()).as_secs(),
            };
            log::debug!("no send aead, cannot send anything yet. sending another clienthello");
            raw_callback(hello);
            return Instant::now() + Duration::from_secs(1);
        }

        let start = Instant::now();

        // encryption
        let mut outgoing_callback = |msg: StreamMessage| {
            log::trace!("send in tick {:?}", msg);
            trace_outgoing_msg(&msg);
            if let Some(send_aead) = self.send_aead.as_ref() {
                let inner = send_aead.encrypt(&msg.stdcode());
                raw_callback(Frame::EncryptedMsg { inner })
            }
        };

        // push the force-ticks into the tick queue
        while let Some(val) = self.force_ticks.pop() {
            if self.stream_tab.contains_key(&val) {
                self.tick_times.push(val, Reverse(start));
            }
        }
        // tick only the streams that need to be ticked
        while let Some((stream_id, Reverse(time))) = self.tick_times.pop() {
            if time > start {
                self.tick_times.push(stream_id, Reverse(time));
                break;
            }
            let stream = self
                .stream_tab
                .get_mut(&stream_id)
                .expect("inconsistency between stream table and tick time table");
            if let Some(next_time) = stream.tick(&mut outgoing_callback) {
                self.tick_times.push(stream_id, Reverse(next_time));
            } else {
                self.tick_times.remove(&stream_id);
                self.stream_tab.remove(&stream_id);
            }
        }

        let insta = self.tick_times.peek().map(|(_, time)| time.0);
        insta.unwrap_or_else(|| Instant::now() + Duration::from_secs(86400))
    }

    /// Starts the opening of a connection, returning a Stream in the pending state.
    pub fn start_open_stream(&mut self, additional: &str) -> anyhow::Result<Stream> {
        for _ in 0..100 {
            let stream_id: u16 = rand::thread_rng().gen();
            if !self.stream_tab.contains_key(&stream_id) {
                let stream_tick_notify = self.stream_tick_notify.clone();
                let force_ticks = self.force_ticks.clone();
                let (new_stream, handle) = StreamState::new_pending(
                    move || {
                        force_ticks.push(stream_id);
                        stream_tick_notify.set();
                    },
                    stream_id,
                    additional.to_owned(),
                );
                self.stream_tab.insert(stream_id, new_stream);
                self.stream_tick_notify.set();
                return Ok(handle);
            }
        }
        anyhow::bail!("ran out of stream descriptors")
    }

    /// Processes an incoming message. If the message is rejected for whatever reason, an error is returned, but the state should be presumed to still be in a valid state.
    pub fn recv_msg(
        &mut self,
        msg: Frame,
        mut outgoing_callback: impl FnMut(Frame),
        mut accept_callback: impl FnMut(Stream),
    ) -> anyhow::Result<()> {
        match msg {
            Frame::ClientHello {
                long_pk,
                eph_pk,
                version: _,
                timestamp: _,
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
                let our_hello = Frame::ServerHello {
                    long_pk: self.local_lsk.to_public(),
                    eph_pk: (&self.local_esk_recv).into(),
                };
                outgoing_callback(our_hello);
                Ok(())
            }
            Frame::ServerHello { long_pk, eph_pk } => {
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
                // we unblock the ticks because the ticker could be in the state where it's slowly retransmitting hellos
                self.stream_tick_notify.set();
                Ok(())
            }
            Frame::EncryptedMsg { inner } => {
                let recv_aead = self
                    .recv_aead
                    .as_ref()
                    .context("cannot decrypt messages without receive-side symmetric key")?;
                let (nonce, inner) = recv_aead.decrypt(&inner)?;
                if !self.replay_filter.add(nonce) {
                    anyhow::bail!("replay filter caught nonce {nonce}");
                }
                let inner: StreamMessage =
                    stdcode::deserialize(&inner).context("could not deserialize message")?;
                log::trace!("recv {:?}", inner);
                trace_incoming_msg(&inner);
                match &inner {
                    StreamMessage::Reliable {
                        kind: RelKind::Syn,
                        stream_id,
                        seqno: _,
                        payload,
                    } => {
                        let stream_id = *stream_id;
                        if let Some(stream) = self.stream_tab.get_mut(&stream_id) {
                            stream.inject_incoming(inner);
                        } else {
                            let stream_tick_notify = self.stream_tick_notify.clone();
                            let force_ticks = self.force_ticks.clone();
                            // create a new stream in the right state. we don't need to do anything else
                            let (mut stream, handle) = StreamState::new_established(
                                move || {
                                    force_ticks.push(stream_id);
                                    stream_tick_notify.set();
                                },
                                stream_id,
                                String::from_utf8_lossy(payload).to_string(),
                            );

                            stream.inject_incoming(inner); // this creates the syn-ack
                            self.stream_tab.insert(stream_id, stream);
                            accept_callback(handle);
                        }
                    }
                    StreamMessage::Unreliable {
                        stream_id,
                        payload: _,
                    } => {
                        let stream = self
                            .stream_tab
                            .get_mut(stream_id)
                            .context("dropping urel message with unknown stream id")?;
                        stream.inject_incoming(inner);
                    }

                    StreamMessage::Reliable {
                        kind,
                        stream_id,
                        seqno: _,
                        payload: _,
                    } => {
                        if let Some(stream) = self.stream_tab.get_mut(stream_id) {
                            stream.inject_incoming(inner);
                        } else {
                            // respond with a RST if the kind is not already an RST. This prevents infinite RST loops, but kills connections that the other side thinks exists but we know do not.
                            if *kind != RelKind::Rst {
                                let inner = StreamMessage::Reliable {
                                    kind: RelKind::Rst,
                                    stream_id: *stream_id,
                                    seqno: 0,
                                    payload: Bytes::new(),
                                };
                                let inner = self
                                    .send_aead
                                    .as_ref()
                                    .context("cannot get send_aead to respond with RST")?
                                    .encrypt(&inner.stdcode());
                                outgoing_callback(Frame::EncryptedMsg { inner });
                            }
                        }
                    }

                    StreamMessage::Empty => {}
                }
                Ok(())
            }
        }
    }
}
