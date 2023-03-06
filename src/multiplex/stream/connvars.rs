use std::{
    collections::{BTreeSet, VecDeque},
    time::{Duration, Instant},
};

use ahash::AHashSet;

use bytes::Bytes;

use sluice::pipe::PipeReader;
use smol::channel::{Receiver, Sender};

use crate::{
    multiplex::{stream::congestion::CongestionControl, structs::*},
    pacer::Pacer,
    timer::{fastsleep, fastsleep_until},
    utilities::MyFutureExt,
};

use super::{congestion::Highspeed, inflight::Inflight, MSS};
use smol::prelude::*;

pub(crate) struct ConnVars {
    pub inflight: Inflight,
    pub next_free_seqno: Seqno,

    pub delayed_ack_timer: Option<Instant>,
    pub ack_seqnos: AHashSet<Seqno>,

    pub reorderer: Reorderer<Bytes>,
    pub lowest_unseen: Seqno,

    closing: bool,
    write_fragments: VecDeque<Bytes>,
    // next_pace_time: Instant,
    lost_seqnos: BTreeSet<Seqno>,
    last_loss: Option<Instant>,
    pacer: Pacer,
    cc: Box<dyn CongestionControl + Send>,
}

impl Default for ConnVars {
    fn default() -> Self {
        ConnVars {
            inflight: Inflight::new(),
            next_free_seqno: 0,

            delayed_ack_timer: None,
            ack_seqnos: AHashSet::default(),

            reorderer: Reorderer::default(),
            lowest_unseen: 0,

            closing: false,

            write_fragments: VecDeque::new(),

            // next_pace_time: Instant::now(),
            lost_seqnos: BTreeSet::new(),
            last_loss: None,
            // cc: Box::new(Cubic::new(0.7, 0.4)),
            cc: Box::new(Highspeed::new(1)),
            pacer: Pacer::new(Duration::from_millis(1)),
            // cc: Box::new(Trivial::new(300)),
        }
    }
}

const ACK_BATCH: usize = 1;

#[derive(Debug)]
enum ConnVarEvt {
    Rto(Seqno),
    Retransmit(Seqno),
    AckTimer,
    NewWrite(Bytes),
    NewWriteUrel(Bytes),
    NewPkt(Message),
    Closing,
}

impl ConnVars {
    /// Process a *single* event. Errors out when the thing should be closed.
    #[allow(clippy::too_many_arguments)]
    pub async fn process_one(
        &mut self,
        stream_id: u16,
        recv_write: &mut PipeReader,
        recv_write_urel: &Receiver<Bytes>,
        send_read: &Sender<Bytes>,
        send_read_urel: &Sender<Bytes>,
        recv_wire_read: &Receiver<Message>,
        transmit: &Sender<Message>,
    ) -> anyhow::Result<()> {
        assert_eq!(self.inflight.lost_count(), self.lost_seqnos.len());
        match self
            .next_event(recv_write, recv_wire_read, recv_write_urel)
            .await
        {
            Ok(ConnVarEvt::Retransmit(seqno)) => {
                if let Some(msg) = self.inflight.retransmit(seqno) {
                    self.lost_seqnos.remove(&seqno);
                    transmit.send(msg).await?;
                }
                assert_eq!(self.inflight.lost_count(), self.lost_seqnos.len());
                Ok(())
            }
            Ok(ConnVarEvt::Closing) => {
                self.closing = true;
                self.check_closed()?;
                Ok(())
            }
            Ok(ConnVarEvt::Rto(seqno)) => {
                log::debug!(
                    "RTO with {:?}, min {:?}",
                    self.inflight.rto(),
                    self.inflight.min_rtt()
                );
                log::debug!(
                    "** MARKING LOST {} (unacked = {}, inflight = {}, cwnd = {}, BDP = {}, lost_count = {}, lmf = {}) **",
                    seqno,
                    self.inflight.unacked(),
                    self.inflight.inflight(),
                    self.cc.cwnd(),
                    self.inflight.bdp() as usize ,
                    self.inflight.lost_count(),
                    self.inflight.last_minus_first()
                );
                let now = Instant::now();
                if let Some(old) = self.last_loss {
                    if now.saturating_duration_since(old) > self.inflight.min_rtt() {
                        self.cc.mark_loss();
                        self.last_loss = Some(now);
                    }
                } else {
                    self.cc.mark_loss();
                    self.last_loss = Some(now);
                }

                // assert_eq!(self.inflight.lost_count(), self.lost_seqnos.len());
                self.inflight.mark_lost(seqno);
                self.lost_seqnos.insert(seqno);
                assert_eq!(self.inflight.lost_count(), self.lost_seqnos.len());
                Ok(())
            }
            Ok(ConnVarEvt::NewPkt(Message::Urel {
                stream_id: _,
                payload,
            })) => {
                let _ = send_read_urel.send(payload).await;
                Ok(())
            }
            Ok(ConnVarEvt::NewPkt(Message::Rel {
                kind: RelKind::Rst, ..
            })) => anyhow::bail!("received RST"),
            Ok(ConnVarEvt::NewPkt(Message::Rel {
                kind: RelKind::DataAck,
                payload,
                seqno,
                ..
            })) => {
                assert_eq!(self.inflight.lost_count(), self.lost_seqnos.len());
                let seqnos = stdcode::deserialize::<Vec<Seqno>>(&payload)?;
                // log::trace!("new ACK pkt with {} seqnos", seqnos.len());
                for _ in 0..self.inflight.mark_acked_lt(seqno) {
                    self.cc.mark_ack(
                        self.inflight.bdp(),
                        self.inflight.min_rtt().as_millis() as usize,
                    )
                }
                self.lost_seqnos.retain(|v| *v >= seqno);
                assert_eq!(self.inflight.lost_count(), self.lost_seqnos.len());
                for seqno in seqnos {
                    self.lost_seqnos.remove(&seqno);
                    if self.inflight.mark_acked(seqno) {
                        self.cc.mark_ack(
                            self.inflight.bdp(),
                            self.inflight.min_rtt().as_millis() as usize,
                        );
                    }
                }
                self.check_closed()?;
                assert_eq!(self.inflight.lost_count(), self.lost_seqnos.len());
                Ok(())
            }
            Ok(ConnVarEvt::NewPkt(Message::Rel {
                kind: RelKind::Data,
                seqno,
                payload,
                ..
            })) => {
                log::trace!("new data pkt with seqno={}", seqno);
                if self.delayed_ack_timer.is_none() {
                    self.delayed_ack_timer = Instant::now().checked_add(Duration::from_millis(1));
                }
                if self.reorderer.insert(seqno, payload) {
                    self.ack_seqnos.insert(seqno);
                }
                let times = self.reorderer.take();
                self.lowest_unseen += times.len() as u64;
                let mut success = true;
                for pkt in times {
                    success |= send_read.send(pkt).await.is_ok();
                }
                assert_eq!(self.inflight.lost_count(), self.lost_seqnos.len());
                if success {
                    Ok(())
                } else {
                    anyhow::bail!("cannot write into send_read")
                }
            }
            Ok(ConnVarEvt::NewWriteUrel(bts)) => {
                transmit
                    .send(Message::Urel {
                        stream_id,
                        payload: bts,
                    })
                    .await?;
                Ok(())
            }
            Ok(ConnVarEvt::NewWrite(bts)) => {
                assert!(bts.len() <= MSS);
                log::trace!("sending write of length {}", bts.len());
                // self.limiter.wait(implied_rate).await;
                let seqno = self.next_free_seqno;
                self.next_free_seqno += 1;
                let msg = Message::Rel {
                    kind: RelKind::Data,
                    stream_id,
                    seqno,
                    payload: bts,
                };
                // put msg into inflight
                self.inflight.insert(seqno, msg.clone());

                transmit.send(msg).await?;
                assert_eq!(self.inflight.lost_count(), self.lost_seqnos.len());
                Ok(())
            }
            Ok(ConnVarEvt::AckTimer) => {
                // eprintln!("acking {} seqnos", conn_vars.ack_seqnos.len());
                let mut ack_seqnos: Vec<_> = self.ack_seqnos.iter().collect();
                assert!(ack_seqnos.len() <= ACK_BATCH);
                ack_seqnos.sort_unstable();
                let encoded_acks = stdcode::serialize(&ack_seqnos).unwrap();
                if encoded_acks.len() > 1000 {
                    log::warn!("encoded_acks {} bytes", encoded_acks.len());
                }
                transmit
                    .send(Message::Rel {
                        kind: RelKind::DataAck,
                        stream_id,
                        seqno: self.lowest_unseen,
                        payload: Bytes::copy_from_slice(&encoded_acks),
                    })
                    .await?;
                self.ack_seqnos.clear();

                self.delayed_ack_timer = None;
                assert_eq!(self.inflight.lost_count(), self.lost_seqnos.len());
                Ok(())
            }
            Err(err) => {
                log::debug!("forced to RESET due to {:?}", err);
                anyhow::bail!(err);
            }
            evt => {
                log::debug!("unrecognized event: {:#?}", evt);
                Ok(())
            }
        }
    }

    /// Checks the closed flag.
    fn check_closed(&self) -> anyhow::Result<()> {
        if self.closing && self.inflight.unacked() == 0 {
            anyhow::bail!("closing flag set and unacked == 0, so dying");
        }
        Ok(())
    }

    // /// Changes the congestion-control algorithm.
    // pub fn change_cc(&mut self, algo: impl CongestionControl + Send + 'static) {
    //     self.cc = Box::new(algo)
    // }

    /// Gets the next event.
    async fn next_event(
        &mut self,
        recv_write: &mut PipeReader,
        recv_wire_read: &Receiver<Message>,
        recv_write_urel: &Receiver<Bytes>,
    ) -> anyhow::Result<ConnVarEvt> {
        // There's a rather subtle logic involved here.
        //
        // We want to make sure the *total inflight* is less than cwnd.
        // This is very tricky when a packet is lost and must be transmitted.
        // We don't want retransmissions to cause more than CWND packets in flight, any more do we let normal transmissions do so.
        // Thus, we must have a state where a packet is known to be lost, but is not yet retransmitted.
        let first_retrans = self.lost_seqnos.iter().next().cloned();
        // let can_retransmit = self.inflight.inflight() <= self.cc.cwnd();
        // If we've already closed the connection, we cannot write *new* packets
        let can_write_new = self.inflight.inflight() <= self.cc.cwnd()
            && self.inflight.last_minus_first() <= self.cc.cwnd() * 10
            && !self.closing
            && self.lost_seqnos.is_empty();
        let force_ack = self.ack_seqnos.len() >= ACK_BATCH;
        assert!(self.ack_seqnos.len() <= ACK_BATCH);

        let write_urel = async {
            let b = recv_write_urel.recv().await?;
            anyhow::Ok(ConnVarEvt::NewWriteUrel(b))
        };

        let ack_timer = self.delayed_ack_timer;
        let ack_timer = async {
            if force_ack {
                return Ok(ConnVarEvt::AckTimer);
            }
            if let Some(time) = ack_timer {
                fastsleep_until(time).await;
                Ok::<ConnVarEvt, anyhow::Error>(ConnVarEvt::AckTimer)
            } else {
                smol::future::pending().await
            }
        };

        let first_rto = self.inflight.first_rto();
        let rto_timeout = async move {
            let (rto_seqno, rto_time) = first_rto.unwrap();
            if rto_time > Instant::now() {
                fastsleep_until(rto_time).await;
            }
            Ok::<ConnVarEvt, anyhow::Error>(ConnVarEvt::Rto(rto_seqno))
        }
        .pending_unless(first_rto.is_some());

        let new_write = async {
            while self.write_fragments.is_empty() {
                let to_write = {
                    let mut bts = Vec::new();
                    bts.extend_from_slice(&[0; MSS]);
                    let n = recv_write.read(&mut bts).await;
                    if let Ok(n) = n {
                        log::trace!("writing segment of {} bytes", n);
                        if n == 0 {
                            None
                        } else {
                            let bts: Bytes = bts.into();
                            Some(bts.slice(0..n))
                        }
                    } else {
                        None
                    }
                };
                if let Some(to_write) = to_write {
                    self.write_fragments.push_back(to_write);
                } else {
                    return Ok(ConnVarEvt::Closing);
                }
            }
            let pacing_interval = Duration::from_secs_f64(1.0 / self.pacing_rate());
            self.pacer.set_interval(pacing_interval);
            self.pacer.wait_next().await;
            Ok::<ConnVarEvt, anyhow::Error>(ConnVarEvt::NewWrite(
                self.write_fragments.pop_front().unwrap(),
            ))
        }
        .pending_unless(can_write_new);
        let new_pkt = async {
            Ok::<ConnVarEvt, anyhow::Error>(ConnVarEvt::NewPkt(recv_wire_read.recv().await?))
        };
        let final_timeout = async {
            fastsleep(Duration::from_secs(120)).await;
            anyhow::bail!("final timeout within stream actor");
        }
        .pending_unless(first_rto.is_some());
        let retransmit = async { anyhow::Ok(ConnVarEvt::Retransmit(first_retrans.unwrap())) }
            .pending_unless(first_retrans.is_some());

        write_urel
            .or(rto_timeout
                .or(retransmit)
                .or(ack_timer)
                .or(final_timeout)
                .or(new_pkt)
                .or(new_write))
            .await
    }

    fn pacing_rate(&self) -> f64 {
        // calculate implicit rate
        (self.cc.cwnd() as f64 / self.inflight.min_rtt().as_secs_f64()).max(1.0)
    }
}
