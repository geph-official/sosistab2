use crate::PipeStats;
use derivative::Derivative;
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PacketRecord {
    send_time: Instant,
    acked: AckState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AckState {
    Unknown,
    Ack(Instant),
    Nak,
}

/// A statistics calculator.
#[derive(Default, Derivative)]
#[derivative(Debug)]
pub(crate) struct StatsCalculator {
    #[derivative(Debug = "ignore")]
    packets: BTreeMap<u64, PacketRecord>,

    acked: u64,
    lost: u64,
    acked_qualified: u64,
    lost_qualified: u64,

    latency_sum: Duration,
    variance_sum: f64,
    last_latency: Duration,

    outstanding: u64,
    first_outstanding: Option<Instant>,
    last_ack: Option<Instant>,
}

impl StatsCalculator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Calculates stats based on recent data.
    pub fn get_stats(&self) -> PipeStats {
        log::trace!("calculating stats from {:?}", self);
        let loss_total = self.lost as f64 / (self.acked + self.lost).max(1) as f64;
        let loss_qualified =
            self.lost_qualified as f64 / (self.acked_qualified + self.lost_qualified).max(1) as f64;
        let dead = if let (Some(first), Some(last)) = (self.first_outstanding, self.last_ack) {
            first.elapsed() > Duration::from_secs(3)
                && last.elapsed() > Duration::from_secs(3)
                && self.outstanding > 3
        } else {
            false
        };
        PipeStats {
            dead,
            loss: loss_total.min(loss_qualified),
            latency: self.latency_sum / (self.acked.max(1) as u32),
            jitter: Duration::from_secs_f64(
                (self.variance_sum / (self.acked).max(1) as f64).sqrt(),
            ),
        }
    }

    /// Adds an acknowledgement, along with a `time_offset` that represents the local delay before the acknowledgement was sent by the remote end.
    pub fn add_ack(&mut self, seqno: u64, time_offset: Duration) {
        self.outstanding = 0;
        self.last_ack = Some(Instant::now());
        let clears_neighborhood = self.clears_neighborhood(seqno);
        if let Some(existing) = self.packets.get_mut(&seqno) {
            // record the acks
            let ack_time = Instant::now()
                .checked_sub(time_offset)
                .unwrap_or_else(Instant::now);
            existing.acked = AckState::Ack(
                Instant::now()
                    .checked_sub(time_offset)
                    .unwrap_or_else(Instant::now),
            );
            let this_latency = ack_time.saturating_duration_since(existing.send_time);
            self.latency_sum += this_latency;
            self.variance_sum +=
                (self.last_latency.as_secs_f64() - this_latency.as_secs_f64()).powi(2);
            self.acked += 1;
            self.last_latency = this_latency;
            if clears_neighborhood {
                self.acked_qualified += 1;
            }
        }
        self.cleanup();
    }

    /// Adds a negative acknowledgement of a packet.
    pub fn add_nak(&mut self, seqno: u64) {
        let clears_neighborhood = self.clears_neighborhood(seqno);
        if let Some(existing) = self.packets.get_mut(&seqno) {
            existing.acked = AckState::Nak;
            self.lost += 1;
            if clears_neighborhood {
                self.lost_qualified += 1;
            }
        }
        self.cleanup();
    }

    /// Checks whether a seqno "clears its neighborhood".
    fn clears_neighborhood(&self, seqno: u64) -> bool {
        let mut neigh = self.packets.range(seqno.saturating_sub(50)..=seqno + 50);
        let first = neigh.next();
        let last = neigh.next_back();
        if let (Some((_, &first)), Some((_, &last))) = (first, last) {
            last.send_time.saturating_duration_since(first.send_time) > Duration::from_millis(100)
        } else {
            false
        }
    }

    /// Adds a sent packet to the StatsCalculator
    pub fn add_sent(&mut self, seqno: u64) {
        if self.outstanding == 0 {
            self.first_outstanding = Some(Instant::now())
        }
        self.outstanding += 1;
        self.packets.insert(
            seqno,
            PacketRecord {
                send_time: Instant::now(),
                acked: AckState::Unknown,
            },
        );
        self.cleanup();
    }

    /// "Garbage collects"
    fn cleanup(&mut self) {
        if self.packets.len() > 10000 {
            let to_del = self.packets.keys().next().copied().unwrap();
            self.packets.remove(&to_del);
        }
        if self.acked > 100000 {
            self.acked /= 2;
            self.lost /= 2;

            self.latency_sum /= 2;
            self.variance_sum /= 2.0;
        }
        if self.acked_qualified > 1000 {
            self.acked_qualified /= 2;
            self.lost_qualified /= 2;
        }
    }
}
