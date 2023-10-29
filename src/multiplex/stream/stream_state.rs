use std::{
    io::{Read, Write},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use bytes::Bytes;
use futures_intrusive::sync::ManualResetEvent;
use parking_lot::Mutex;
use stdcode::StdcodeSerializeExt;

use crate::{
    multiplex::pipe_pool::{Message, RelKind, Reorderer},
    MuxStream,
};

use super::{inflight::Inflight, StreamQueues};
const MSS: usize = 30000;

pub struct StreamState {
    phase: Phase,
    stream_id: u16,
    additional_data: String,
    incoming_queue: Vec<Message>,
    queues: Arc<Mutex<StreamQueues>>,
    local_notify: Arc<async_event::Event>,

    // read variables
    next_unseen_seqno: u64,
    reorderer: Reorderer<Bytes>,

    // write variables
    inflight: Inflight,
    next_write_seqno: u64,
    last_retrans: Instant,
    speed: f64,
    speed_max: f64,

    next_trans: Instant,
    in_recovery: bool,

    global_speed_guess: Arc<AtomicUsize>,
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
        global_notify: Arc<ManualResetEvent>,
        stream_id: u16,
        additional_data: String,
        global_speed_guess: Arc<AtomicUsize>,
    ) -> (Self, MuxStream) {
        Self::new_in_phase(
            global_notify,
            stream_id,
            Phase::Pending,
            additional_data,
            global_speed_guess,
        )
    }

    /// Creates a new StreamState, in the established state. Also returns the "user-facing" handle.
    pub fn new_established(
        global_notify: Arc<ManualResetEvent>,
        stream_id: u16,
        additional_data: String,
        global_speed_guess: Arc<AtomicUsize>,
    ) -> (Self, MuxStream) {
        Self::new_in_phase(
            global_notify,
            stream_id,
            Phase::Established,
            additional_data,
            global_speed_guess,
        )
    }

    /// Creates a new StreamState, in the specified state. Also returns the "user-facing" handle.
    fn new_in_phase(
        global_notify: Arc<ManualResetEvent>,
        stream_id: u16,
        phase: Phase,
        additional_data: String,
        global_speed_guess: Arc<AtomicUsize>,
    ) -> (Self, MuxStream) {
        let queues = Arc::new(Mutex::new(StreamQueues::default()));
        let ready = Arc::new(async_event::Event::new());
        let handle = MuxStream::new(
            global_notify,
            ready.clone(),
            queues.clone(),
            additional_data.clone().into(),
        );
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
            speed: 10.0,
            speed_max: 0.0,
            next_trans: Instant::now(),
            in_recovery: false,

            additional_data,
            last_retrans: Instant::now(),

            global_speed_guess,
        };
        (state, handle)
    }

    /// Injects an incoming message.
    pub fn inject_incoming(&mut self, msg: Message) {
        self.incoming_queue.push(msg);
    }

    /// "Ticks" this StreamState, which advances its state. Any outgoing messages generated are passed to the callback given. Returns the correct time to call tick again at. Returns None if the correct option is to delete the whole thing.
    pub fn tick(&mut self, mut outgoing_callback: impl FnMut(Message)) -> Option<Instant> {
        log::trace!("ticking {} at {:?}", self.stream_id, self.phase);

        let now: Instant = Instant::now();

        match self.phase {
            Phase::Pending => {
                // send a SYN, and transition into SynSent
                outgoing_callback(Message::Rel {
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
                        Message::Rel {
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
                    outgoing_callback(Message::Rel {
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
                Some(self.retick_time())
            }
            Phase::Closed => {
                self.queues.lock().closed = true;
                self.local_notify.notify_all();
                for _ in self.incoming_queue.drain(..) {
                    outgoing_callback(Message::Rel {
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

    fn tick_read(&mut self, _now: Instant, mut outgoing_callback: impl FnMut(Message)) {
        // Put all incoming packets into the reorderer.
        let mut to_ack = vec![];

        for packet in self.incoming_queue.drain(..) {
            // If the receive queue is too large, then we pretend like we don't see anything. The sender will eventually retransmit.
            // This unifies flow control with congestion control at the cost of a bit of efficiency.
            if self.queues.lock().read_stream.len() > 1_000_000 {
                continue;
            }

            match packet {
                Message::Rel {
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
                Message::Rel {
                    kind: RelKind::DataAck,
                    stream_id: _,
                    seqno: lowest_unseen_seqno, // *one greater* than the last packet that got to the other side
                    payload: selective_acks,
                } => {
                    // mark every packet whose seqno is less than the given seqno as acked.
                    let n = self.inflight.mark_acked_lt(lowest_unseen_seqno);
                    if n > 0 {
                        self.in_recovery = false;
                    }
                    let kb_speed = self.speed * (MSS as f64) / 1000.0;
                    let old_speed = self.speed;
                    // use BIC congestion control
                    let bic_inc = if self.speed < self.speed_max {
                        (self.speed_max - self.speed) / 2.0
                    } else {
                        self.speed - self.speed_max
                    }
                    .max(n as f64)
                    .min(n as f64 * 50.0);
                    log::debug!("bic_inc = {bic_inc}");
                    self.speed += bic_inc / self.speed;
                    self.speed = self
                        .speed
                        .min(self.inflight.delivery_rate() * 1.2)
                        .max(old_speed);

                    log::debug!("{n} acks received, raising speed from {:.2} KB/s", kb_speed);
                    // then, we interpret the payload as a vector of acks that should additional be taken care of.
                    if let Ok(sacks) = stdcode::deserialize::<Vec<u64>>(&selective_acks) {
                        for sack in sacks {
                            self.inflight.mark_acked(sack);
                        }
                    }
                }
                Message::Rel {
                    kind: RelKind::Syn,
                    stream_id,
                    seqno,
                    payload,
                } => {
                    // retransmit our syn-ack
                    outgoing_callback(Message::Rel {
                        kind: RelKind::SynAck,
                        stream_id,
                        seqno,
                        payload,
                    });
                }
                Message::Rel {
                    kind: RelKind::Rst | RelKind::Fin,
                    stream_id: _,
                    seqno: _,
                    payload: _,
                } => {
                    self.phase = Phase::Closed;
                }
                Message::Urel {
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
            self.local_notify.notify_all();
        }
        // Then, generate an ack.
        if !to_ack.is_empty() {
            to_ack.retain(|a| a >= &self.next_unseen_seqno);
            outgoing_callback(Message::Rel {
                kind: RelKind::DataAck,
                stream_id: self.stream_id,
                seqno: self.next_unseen_seqno,
                payload: to_ack.stdcode().into(),
            });
        }
    }

    fn start_recovery(&mut self) {
        if !self.in_recovery {
            // BIC
            let beta = 0.3;
            if self.speed < self.speed_max {
                self.speed_max = self.speed * (2.0 - beta) / 2.0;
            } else {
                self.speed_max = self.speed;
            }
            self.speed *= 1.0 - beta;
            self.global_speed_guess
                .store(self.speed as usize, Ordering::Relaxed);
            self.in_recovery = true;
        }
    }

    fn tick_write(&mut self, now: Instant, mut outgoing_callback: impl FnMut(Message)) {
        log::debug!("tick_write for {}", self.stream_id);
        // we first handle unreliable datagrams
        while let Some(payload) = self.queues.lock().send_urel.pop_front() {
            outgoing_callback(Message::Urel {
                stream_id: self.stream_id,
                payload,
            });
        }

        const MAX_CWND: usize = 1000;

        // every time we add another segment, we also transmit it, and set the RTO.
        let send_allowed = self.next_trans <= now;
        let next_next_trans =
            (self.next_trans + Duration::from_secs_f64(1.0 / self.speed)).max(now);
        if send_allowed {
            log::trace!(
                "send_allowed because we are {:?} since next_trans; {:?} since next_next_trans",
                now.saturating_duration_since(self.next_trans),
                now.saturating_duration_since(next_next_trans)
            );
            // we do any retransmissions if necessary
            if let Some((seqno, retrans_time)) = self.inflight.first_rto() {
                if now >= retrans_time {
                    self.start_recovery();
                    log::debug!("RTO retransmit {}", seqno);
                    let first = self.inflight.retransmit(seqno).expect("no first");
                    outgoing_callback(first);
                    self.last_retrans = now;
                    self.next_trans = next_next_trans;
                    return;
                }
            }

            // okay, we don't have retransmissions. this means we get to send a "normal" packet.
            let mut queues = self.queues.lock();
            if self.inflight.inflight() < (self.inflight.bdp() * 5).max(10)
                && !queues.write_stream.is_empty()
            // && !self.in_recovery
            {
                log::debug!(
                    "send window has grown to {}; bdp {}",
                    self.inflight.inflight(),
                    self.inflight.bdp()
                );
                let mut buffer = vec![0; MSS];
                let n = queues.write_stream.read(&mut buffer).unwrap();
                buffer.truncate(n);
                let seqno = self.next_write_seqno;
                self.next_write_seqno += 1;
                let msg = Message::Rel {
                    kind: RelKind::Data,
                    stream_id: self.stream_id,
                    seqno,
                    payload: buffer.into(),
                };
                self.inflight.insert(msg.clone());
                outgoing_callback(msg);

                self.local_notify.notify_all();

                log::trace!("filled window to {}", self.inflight.inflight());
                self.next_trans = next_next_trans;
            }
        }
    }

    fn retick_time(&self) -> Instant {
        Instant::now() + Duration::from_millis(1)
        // let first_rto = self
        //     .inflight
        //     .first_rto()
        //     .map(|s| s.1)
        //     .unwrap_or_else(|| Instant::now() + Duration::from_secs(1000));
        // if self.queues.lock().write_stream.is_empty() || self.in_recovery {
        //     first_rto.max(self.next_trans)
        // } else {
        //     first_rto.min(self.next_trans)
        // }
    }
}

#[derive(Clone, Copy, Debug)]
enum Phase {
    Pending,
    SynSent { next_resend: Instant },
    Established,
    Closed,
}
