use std::{
    io::{Read, Write},
    sync::Arc,
    time::{Duration, Instant},
};

use bytes::Bytes;

use clone_macro::clone;
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use stdcode::StdcodeSerializeExt;

use crate::{
    multiplex::stream::{RelKind, StreamMessage},
    Stream,
};

use super::{inflight::Inflight, reorderer::Reorderer, StreamQueues};
const MSS: usize = 1150;

/// The raw internal state of a stream.
///
/// This is exposed so that crates other than `sosistab2` itself can use the reliable-stream logic of `sosistab2`, outside the context of multiplexing streams over a `sosistab2::Multiplex`.
///
/// A StreamState is constructed and used in a rather particular way:
/// - On construction, a `tick_notify` closure is passed in.
/// - The caller must arrange so that `StreamState::tick` is called
///     - every time `tick_notify` is called
///     - `tick_retval` after the last tick, where `tick_retval` is the return value of the last time the state was ticked
/// - inject_incoming is called on every incoming message
///
/// As long as the above holds, the `Stream` corresponding to the `StreamState`, which is returned from the `StreamState` constructor as well, will work properly.
pub struct StreamState {
    phase: Phase,
    stream_id: u16,
    additional_data: String,
    incoming_queue: Vec<StreamMessage>,
    queues: Arc<Mutex<StreamQueues>>,
    local_notify: Arc<async_event::Event>,
    tick_notify: Arc<dyn Fn() + Send + Sync + 'static>,

    // read variables
    next_unseen_seqno: u64,
    reorderer: Reorderer<Bytes>,

    // write variables
    inflight: Inflight,
    next_write_seqno: u64,
    rtt_count: u64,
    last_rtt_count_time: Instant,
    cwnd: f64,
    speed_gain: f64,

    in_recovery: bool,
    last_write_time: Instant,
}

impl Drop for StreamState {
    fn drop(&mut self) {
        self.queues.lock().closed = true;
        self.local_notify.notify_all();
    }
}

impl StreamState {
    /// Creates a new StreamState, in the pre-SYN-sent state. Also returns the "user-facing" handle.
    pub fn new_pending(
        tick_notify: impl Fn() + Send + Sync + 'static,
        stream_id: u16,
        label: String,
    ) -> (Self, Stream) {
        Self::new_in_phase(tick_notify, stream_id, Phase::Pending, label)
    }

    /// Creates a new StreamState, in the established state. Also returns the "user-facing" handle.
    pub fn new_established(
        tick_notify: impl Fn() + Send + Sync + 'static,
        stream_id: u16,
        label: String,
    ) -> (Self, Stream) {
        Self::new_in_phase(tick_notify, stream_id, Phase::Established, label)
    }

    /// Creates a new StreamState, in the specified state. Also returns the "user-facing" handle.
    fn new_in_phase(
        tick_notify: impl Fn() + Send + Sync + 'static,
        stream_id: u16,
        phase: Phase,
        label: String,
    ) -> (Self, Stream) {
        let queues = Arc::new(Mutex::new(StreamQueues::default()));
        let ready = Arc::new(async_event::Event::new());
        let tick_notify: Arc<dyn Fn() + Send + Sync + 'static> = Arc::new(tick_notify);
        let handle = Stream::new(
            clone!([tick_notify], move || tick_notify()),
            ready.clone(),
            queues.clone(),
            label.clone().into(),
        );

        static START: Lazy<Instant> = Lazy::new(Instant::now);
        let state = Self {
            phase,
            stream_id,
            incoming_queue: Default::default(),
            queues,
            local_notify: ready,

            next_unseen_seqno: 0,
            reorderer: Reorderer::default(),
            inflight: Inflight::new(),
            next_write_seqno: 0,
            tick_notify,

            cwnd: 10.0,
            speed_gain: 2.0,

            rtt_count: 0,
            last_rtt_count_time: Instant::now(),

            in_recovery: false,

            additional_data: label,
            last_write_time: *START,
        };
        (state, handle)
    }

    /// Injects an incoming message.
    pub fn inject_incoming(&mut self, msg: StreamMessage) {
        self.incoming_queue.push(msg);
        (self.tick_notify)();
    }

    /// "Ticks" this StreamState, which advances its state. Any outgoing messages generated are passed to the callback given. Returns the correct time to call tick again at --- but if tick_notify, passed in during construction, fires, the stream must be ticked again.
    ///
    /// Returns None if the correct option is to delete the whole thing.
    pub fn tick(&mut self, mut outgoing_callback: impl FnMut(StreamMessage)) -> Option<Instant> {
        log::trace!("ticking {} at {:?}", self.stream_id, self.phase);

        let now: Instant = Instant::now();

        match self.phase {
            Phase::Pending => {
                // send a SYN, and transition into SynSent
                outgoing_callback(StreamMessage::Reliable {
                    kind: RelKind::Syn,
                    stream_id: self.stream_id,
                    seqno: 0,
                    payload: Bytes::copy_from_slice(self.additional_data.as_bytes()),
                });
                let next_resend = now + Duration::from_secs(1);
                self.phase = Phase::SynSent { next_resend };
                Some(next_resend)
            }
            Phase::SynSent { next_resend } => {
                if self.incoming_queue.drain(..).any(|msg| {
                    matches!(
                        msg,
                        StreamMessage::Reliable {
                            kind: RelKind::SynAck,
                            stream_id: _,
                            seqno: _,
                            payload: _
                        }
                    )
                }) {
                    self.phase = Phase::Established;
                    self.queues.lock().connected = true;
                    self.local_notify.notify_all();
                    Some(now)
                } else if now >= next_resend {
                    outgoing_callback(StreamMessage::Reliable {
                        kind: RelKind::Syn,
                        stream_id: self.stream_id,
                        seqno: 0,
                        payload: Bytes::copy_from_slice(self.additional_data.as_bytes()),
                    });
                    let next_resend = now + Duration::from_secs(1);
                    self.phase = Phase::SynSent { next_resend };
                    Some(next_resend)
                } else {
                    Some(next_resend)
                }
            }
            Phase::Established => {
                // First, handle receiving packets. This is the easier part.
                self.tick_read(now, &mut outgoing_callback);
                // Then, handle sending packets. This involves congestion control, so it's the harder part.
                self.tick_write(now, &mut outgoing_callback);
                // If closed, then die
                if self.queues.lock().closed {
                    self.phase = Phase::Closed;
                }
                // Finally, calculate the next interval.
                Some(self.retick_time(now))
            }
            Phase::Closed => {
                self.queues.lock().closed = true;
                self.local_notify.notify_all();
                for _ in self.incoming_queue.drain(..) {
                    outgoing_callback(StreamMessage::Reliable {
                        kind: RelKind::Rst,
                        stream_id: self.stream_id,
                        seqno: 0,
                        payload: Default::default(),
                    });
                }
                None
            }
        }
    }

    fn tick_read(&mut self, now: Instant, mut outgoing_callback: impl FnMut(StreamMessage)) {
        // Put all incoming packets into the reorderer.
        let mut to_ack = vec![];
        // log::debug!("processing incoming queue of {}", self.incoming_queue.len());
        for packet in self.incoming_queue.drain(..) {
            // If the receive queue is too large, then we pretend like we don't see anything. The sender will eventually retransmit.
            // This unifies flow control with congestion control at the cost of a bit of efficiency.
            if self.queues.lock().read_stream.len() > 10_000_000 {
                continue;
            }

            match packet {
                StreamMessage::Reliable {
                    kind: RelKind::Data,
                    stream_id,
                    seqno,
                    payload,
                } => {
                    log::trace!("incoming seqno {stream_id}/{seqno}");
                    if self.reorderer.insert(seqno, payload) {
                        to_ack.push(seqno);
                    }
                }
                StreamMessage::Reliable {
                    kind: RelKind::DataAck,
                    stream_id: _,
                    seqno: lowest_unseen_seqno, // *one greater* than the last packet that got to the other side
                    payload: selective_acks,
                } => {
                    // mark every packet whose seqno is less than the given seqno as acked.
                    let mut ack_count = self.inflight.mark_acked_lt(lowest_unseen_seqno);
                    // then, we interpret the payload as a vector of acks that should additionally be taken care of.
                    if let Ok(sacks) = stdcode::deserialize::<Vec<u64>>(&selective_acks) {
                        for sack in sacks {
                            if self.inflight.mark_acked(sack) {
                                ack_count += 1;
                            }
                        }
                    }

                    // BBR
                    if now.saturating_duration_since(self.last_rtt_count_time)
                        > self.inflight.min_rtt()
                    {
                        self.last_rtt_count_time = now;
                        self.rtt_count += 1;
                        let multipliers = [1.25, 0.75];
                        self.speed_gain = multipliers[self.rtt_count as usize % multipliers.len()];
                        self.cwnd = (self.inflight.bdp() as f64 * 2.0).max(10.0);
                    }

                    log::debug!(
                        "ack_count = {ack_count}; send window {}; cwnd {:.1}; bdp {}; write queue {}",
                        self.inflight.inflight(),
                        self.cwnd,
                        self.inflight.bdp(),
                        self.queues.lock().write_stream.len()
                    );
                    self.local_notify.notify_all();
                }
                StreamMessage::Reliable {
                    kind: RelKind::Syn,
                    stream_id,
                    seqno,
                    payload,
                } => {
                    // retransmit our syn-ack
                    outgoing_callback(StreamMessage::Reliable {
                        kind: RelKind::SynAck,
                        stream_id,
                        seqno,
                        payload,
                    });
                }
                StreamMessage::Reliable {
                    kind: RelKind::Rst | RelKind::Fin,
                    stream_id: _,
                    seqno: _,
                    payload: _,
                } => {
                    self.phase = Phase::Closed;
                }
                StreamMessage::Unreliable {
                    stream_id: _,
                    payload,
                } => {
                    self.queues.lock().recv_urel.push_back(payload);
                    self.local_notify.notify_all();
                }
                _ => log::warn!("discarding out-of-turn packet {:?}", packet),
            }
        }
        // Then, drain the reorderer
        for (seqno, packet) in self.reorderer.take() {
            self.next_unseen_seqno = seqno + 1;
            self.queues.lock().read_stream.write_all(&packet).unwrap();
        }

        // Then, generate an ack.
        if !to_ack.is_empty() {
            self.local_notify.notify_all();
            to_ack.retain(|a| a >= &self.next_unseen_seqno);
            outgoing_callback(StreamMessage::Reliable {
                kind: RelKind::DataAck,
                stream_id: self.stream_id,
                seqno: self.next_unseen_seqno,
                payload: to_ack.stdcode().into(),
            });
        }
    }

    fn start_recovery(&mut self) {
        if !self.in_recovery {
            log::debug!("*** LOSS AT CWND = {}", self.cwnd);

            self.in_recovery = true;
        }
    }

    fn stop_recovery(&mut self) {
        self.in_recovery = false;
    }

    fn congested(&self, now: Instant) -> bool {
        self.inflight.inflight() - self.inflight.lost_at(now) >= self.cwnd as usize
    }

    fn tick_write(&mut self, now: Instant, mut outgoing_callback: impl FnMut(StreamMessage)) {
        log::trace!("tick_write for {}", self.stream_id);
        // we first handle unreliable datagrams
        {
            let mut queues = self.queues.lock();
            while let Some(payload) = queues.send_urel.pop_front() {
                outgoing_callback(StreamMessage::Unreliable {
                    stream_id: self.stream_id,
                    payload,
                });
            }
        }

        if self.inflight.lost_at(now) > 0 {
            self.start_recovery();
        } else {
            self.stop_recovery();
        }

        // speed here is calculated based on the idea that we should be able to transmit a whole cwnd of things in an rtt.
        let speed = self.speed();
        let delivery_rate = self.inflight.delivery_rate();
        let mut writes_allowed = (now
            .saturating_duration_since(self.last_write_time)
            .as_secs_f64()
            * speed) as usize;

        while !self.congested(now) && writes_allowed > 0 {
            // we do any retransmissions if necessary
            if let Some((seqno, retrans_time)) = self.inflight.first_rto() {
                if now >= retrans_time {
                    log::debug!(
                        "inflight = {}, lost = {}, cwnd = {}",
                        self.inflight.inflight(),
                        self.inflight.lost_at(now),
                        self.cwnd
                    );
                    log::debug!("*** retransmit {}", seqno);
                    let first = self.inflight.retransmit(seqno).expect("no first");
                    self.last_write_time = now;
                    writes_allowed -= 1;
                    log::debug!(
                        "RETRANSMIT {seqno} at {:.2} pkts/s, delivered {:.2}",
                        speed,
                        delivery_rate
                    );
                    outgoing_callback(first);
                    continue;
                }
            }

            // okay, we don't have retransmissions. this means we get to send a "normal" packet.
            let mut queues = self.queues.lock();
            if !queues.write_stream.is_empty() {
                let mut buffer = vec![0; MSS];
                let n = queues.write_stream.read(&mut buffer).unwrap();
                buffer.truncate(n);
                let seqno = self.next_write_seqno;
                self.next_write_seqno += 1;
                let msg = StreamMessage::Reliable {
                    kind: RelKind::Data,
                    stream_id: self.stream_id,
                    seqno,
                    payload: buffer.into(),
                };
                self.inflight.insert(msg.clone());
                self.local_notify.notify_all();

                outgoing_callback(msg);
                self.last_write_time = now;
                writes_allowed -= 1;
                log::debug!(
                    "{seqno} at {:.2} pkts/s, delivered {:.2}",
                    speed,
                    delivery_rate
                );
                continue;
            }

            break;
        }
    }

    fn speed(&self) -> f64 {
        (self.inflight.delivery_rate() * self.speed_gain).max(10.0)
    }

    fn retick_time(&self, now: Instant) -> Instant {
        let idle = { self.inflight.inflight() == 0 && self.queues.lock().write_stream.is_empty() };

        if idle {
            now + Duration::from_secs(100000)
        } else {
            now + Duration::from_secs_f64(1.0 / self.speed())
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Phase {
    Pending,
    SynSent { next_resend: Instant },
    Established,
    Closed,
}
