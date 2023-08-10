use std::{
    io::{Read, Write},
    sync::Arc,
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

use super::{congestion::Highspeed, inflight::Inflight, StreamQueues};
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
    congestion: Highspeed,
    last_retrans: Instant,
}

impl StreamState {
    /// Creates a new StreamState, in the pre-SYN-sent state. Also returns the "user-facing" handle.
    pub fn new_pending(
        global_notify: Arc<ManualResetEvent>,
        stream_id: u16,
        additional_data: String,
    ) -> (Self, MuxStream) {
        Self::new_in_phase(global_notify, stream_id, Phase::Pending, additional_data)
    }

    /// Creates a new StreamState, in the established state. Also returns the "user-facing" handle.
    pub fn new_established(
        global_notify: Arc<ManualResetEvent>,
        stream_id: u16,
        additional_data: String,
    ) -> (Self, MuxStream) {
        Self::new_in_phase(
            global_notify,
            stream_id,
            Phase::Established,
            additional_data,
        )
    }

    /// Creates a new StreamState, in the specified state. Also returns the "user-facing" handle.
    fn new_in_phase(
        global_notify: Arc<ManualResetEvent>,
        stream_id: u16,
        phase: Phase,
        additional_data: String,
    ) -> (Self, MuxStream) {
        let queues = Arc::new(Mutex::new(StreamQueues::default()));
        let ready = Arc::new(async_event::Event::new());
        let handle = MuxStream::new(global_notify, ready.clone(), queues.clone());
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

            congestion: Highspeed::new(1),
            additional_data,
            last_retrans: Instant::now(),
        };
        (state, handle)
    }

    /// Injects an incoming message.
    pub fn inject_incoming(&mut self, msg: Message) {
        self.incoming_queue.push(msg);
    }

    /// "Ticks" this StreamState, which advances its state. Any outgoing messages generated are passed to the callback given. Returns the correct time to call tick again at.
    pub fn tick(&mut self, mut outgoing_callback: impl FnMut(Message)) -> Instant {
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
                next_resend
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
                    now
                } else if now >= next_resend {
                    outgoing_callback(Message::Rel {
                        kind: RelKind::Syn,
                        stream_id: self.stream_id,
                        seqno: 0,
                        payload: Bytes::copy_from_slice(self.additional_data.as_bytes()),
                    });
                    let next_resend = now + Duration::from_secs(1);
                    self.phase = Phase::SynSent { next_resend };
                    next_resend
                } else {
                    next_resend
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
                self.retick_time()
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
                now + Duration::from_secs(30)
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
                    for _ in 0..self.inflight.mark_acked_lt(lowest_unseen_seqno) {
                        self.congestion.mark_ack(self.inflight.bdp());
                    }
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

    fn tick_write(&mut self, now: Instant, mut outgoing_callback: impl FnMut(Message)) {
        let mut queues = self.queues.lock();

        // we first handle unreliable datagrams
        while let Some(payload) = queues.send_urel.pop_front() {
            outgoing_callback(Message::Urel {
                stream_id: self.stream_id,
                payload,
            });
        }

        // we attempt to fill the congestion window as far as possible.
        // every time we add another segment, we also transmit it, and set the RTO.
        let cwnd = self.congestion.cwnd();
        while self.inflight.inflight() < cwnd {
            if queues.write_stream.is_empty() {
                queues.write_stream.shrink_to_fit();
                break;
            }

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

            log::trace!("filled {}/{} of cwnd", self.inflight.inflight(), cwnd);
        }

        // then, we do any retransmissions if necessary
        while let Some((seqno, retrans_time)) = self.inflight.first_rto() {
            let cwnd = self.congestion.cwnd();
            let inflight = self.inflight.inflight();
            if now >= retrans_time {
                if cwnd >= inflight {
                    self.congestion.mark_loss();
                }

                // we rate-limit retransmissions.
                // this is a quick and dirty way of preventing retransmissions themselves from overwhelming the network right when the pipe is full
                if now.saturating_duration_since(self.last_retrans).as_millis() > 10 {
                    log::debug!("after loss: {inflight}/{cwnd} of cwnd");
                    log::debug!("RTO retransmit {}", seqno);
                    let first = self.inflight.retransmit(seqno).expect("no first");
                    outgoing_callback(first);
                    self.last_retrans = now;
                } else {
                    log::debug!("waiting until the right time...");
                    break;
                }
            } else {
                break;
            }
        }
    }

    fn retick_time(&self) -> Instant {
        // Instant::now() + Duration::from_millis(10)
        self.inflight
            .first_rto()
            .map(|s| s.1)
            .unwrap_or_else(|| Instant::now() + Duration::from_secs(1000))
    }
}

#[derive(Clone, Copy, Debug)]
enum Phase {
    Pending,
    SynSent { next_resend: Instant },
    Established,
    Closed,
}