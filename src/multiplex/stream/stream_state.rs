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
const MSS: usize = 1000;

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
    cwnd: f64,
    cwnd_max: f64,

    in_recovery: bool,

    global_cwnd_guess: Arc<AtomicUsize>,
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
            cwnd: 1.0,
            cwnd_max: 0.0,

            in_recovery: false,

            additional_data,
            last_retrans: Instant::now(),

            global_cwnd_guess: global_speed_guess,
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
                Some(self.retick_time(now))
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
            if self.queues.lock().read_stream.len() > 10_000_000 {
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
                    // then, we interpret the payload as a vector of acks that should additional be taken care of.
                    if let Ok(sacks) = stdcode::deserialize::<Vec<u64>>(&selective_acks) {
                        for sack in sacks {
                            self.inflight.mark_acked(sack);
                        }
                    }

                    // use BIC congestion control=
                    for _ in 0..n {
                        let bic_inc = if self.cwnd < self.cwnd_max {
                            (self.cwnd_max - self.cwnd) / 2.0
                        } else {
                            self.cwnd - self.cwnd_max
                        }
                        .max(self.cwnd.powf(0.4).max(1.0))
                        .min(50.0);
                        self.cwnd += bic_inc / self.cwnd;
                    }

                    // use HSTCP
                    // let incr = self.cwnd.powf(0.4).max(1.0);
                    // self.cwnd += incr / self.cwnd;

                    log::debug!(
                        "n = {n}; send window {}; cwnd {:.1}; cwnd_max {:.1}; bdp {}",
                        self.inflight.inflight(),
                        self.cwnd,
                        self.cwnd_max,
                        self.inflight.bdp()
                    );
                    self.local_notify.notify_all();
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
        }

        // Then, generate an ack.
        if !to_ack.is_empty() {
            self.local_notify.notify_all();
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
            log::debug!("*** START RECOVRY AT CWND = {}", self.cwnd);
            // BIC
            let beta = 0.15;
            if self.cwnd < self.cwnd_max {
                self.cwnd_max = self.cwnd * (2.0 - beta) / 2.0;
            } else {
                self.cwnd_max = self.cwnd;
            }
            // self.cwnd_max = self.cwnd_max.max(self.inflight.bdp() as f64);
            self.cwnd *= 1.0 - beta;
            self.cwnd = self.cwnd.max(1.0);

            // HSTCP
            // let factor = 0.75;
            // self.cwnd *= factor;
            // self.cwnd = self.cwnd.max(self.inflight.bdp() as f64 * factor).max(1.0);

            self.global_cwnd_guess
                .store(self.cwnd as usize, Ordering::Relaxed);
            self.in_recovery = true;
        }
    }

    fn stop_recovery(&mut self) {
        self.in_recovery = false;
    }

    fn congested(&self) -> bool {
        self.inflight.inflight() - self.inflight.lost() >= self.cwnd as usize
    }

    fn tick_write(&mut self, now: Instant, mut outgoing_callback: impl FnMut(Message)) {
        log::trace!("tick_write for {}", self.stream_id);
        // we first handle unreliable datagrams
        {
            let mut queues = self.queues.lock();
            while let Some(payload) = queues.send_urel.pop_front() {
                outgoing_callback(Message::Urel {
                    stream_id: self.stream_id,
                    payload,
                });
            }
        }

        if self.inflight.lost() > 0 {
            self.start_recovery();
        } else {
            self.stop_recovery();
        }
        while !self.congested() {
            // we do any retransmissions if necessary
            if let Some((seqno, retrans_time)) = self.inflight.first_rto() {
                if now >= retrans_time {
                    log::debug!(
                        "inflight = {}, lost = {}, cwnd = {}",
                        self.inflight.inflight(),
                        self.inflight.lost(),
                        self.cwnd
                    );
                    log::debug!("*** retransmit {}", seqno);
                    let first = self.inflight.retransmit(seqno).expect("no first");
                    outgoing_callback(first);
                    self.last_retrans = now;
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
                continue;
            }

            break;
        }
    }

    fn retick_time(&self, now: Instant) -> Instant {
        if self.congested() {
            let need_packets_lost = self.inflight.inflight() + 1 - self.cwnd as usize;
            // log::debug!("need {need_packets_lost} lost before we're good to go");
            self.inflight.time_when_n_lost(need_packets_lost)
        } else {
            self.inflight.first_rto().map(|s| s.1)
        }
        .unwrap_or_else(|| now + Duration::from_secs(10000))
    }
}

#[derive(Clone, Copy, Debug)]
enum Phase {
    Pending,
    SynSent { next_resend: Instant },
    Established,
    Closed,
}
