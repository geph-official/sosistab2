use std::time::{Duration, Instant};

use bitvec::{prelude::Msb0, view::BitView};
use bytes::Bytes;

use rustc_hash::FxHashMap;

#[derive(Clone, Copy, Debug)]
pub struct PipeStats {
    pub dead: bool,
    pub loss: f64, // 0 to 1
    pub latency: Duration,
    pub jitter: Duration,
}

impl PipeStats {
    pub fn score(&self) -> u64 {
        if self.dead {
            u64::MAX
        } else {
            let threshold: f64 = 0.05;
            let n = threshold.log(self.loss).max(1.0); // number of transmissions needed so that Prob(pkt is lost) <= threshold
            ((n * self.latency.as_secs_f64() + self.jitter.as_secs_f64() * 3.0) * 1000.0) as u64
        }
    }

    fn lerp(&self, other: Self, factor: f64) -> Self {
        let afactor = 1.0 - factor;
        Self {
            dead: false,
            loss: self.loss * afactor + other.loss * factor,
            latency: Duration::from_secs_f64(
                self.latency.as_secs_f64() * afactor + other.latency.as_secs_f64() * factor,
            ),
            jitter: Duration::from_secs_f64(
                self.jitter.as_secs_f64() * afactor + other.jitter.as_secs_f64() * factor,
            ),
        }
    }
}

/// A statistics calculator.
pub(crate) struct StatsCalculator {
    /// seqno => sending time
    send_time: FxHashMap<u64, Instant>,
    /// seqno => if privileged, Some(the adjusted ack time), otherwise None
    ack_time: FxHashMap<u64, Option<Instant>>,
    ack_or_nack: FxHashMap<u64, bool>,

    total_qualified: f64,
    lost_qualified: f64,

    unacked_count: usize,
    last_ackreq: Instant,
    last_ack: Instant,

    /// cached stats
    cached_stat: Option<(Instant, PipeStats)>,
}

impl Default for StatsCalculator {
    fn default() -> Self {
        Self::new()
    }
}

impl StatsCalculator {
    pub fn new() -> Self {
        Self {
            send_time: Default::default(),
            ack_time: Default::default(),
            ack_or_nack: Default::default(),
            last_ackreq: Instant::now(),
            last_ack: Instant::now(),
            lost_qualified: 0.0,
            total_qualified: 0.0,
            unacked_count: 0,
            cached_stat: None,
        }
    }

    /// Calculates stats based on recent data.
    pub fn get_stats(&mut self) -> PipeStats {
        // if last ackreq is sufficiently after last ack, then we're DEAD!
        if self
            .last_ackreq
            .saturating_duration_since(self.last_ack)
            .as_secs_f64()
            > 1.0
            && self.unacked_count > 3
        {
            return PipeStats {
                dead: true,
                loss: 0.0,
                latency: Duration::from_secs(1000),
                jitter: Duration::from_secs(1000),
            };
        }

        if let Some((utime, stat)) = self.cached_stat {
            if utime.elapsed() < Duration::from_secs(1) {
                return stat;
            }
        }
        // calculate loss
        let now = Instant::now();
        const WINDOW_SIZE: usize = 100;
        const WINDOW_MIN_INTERVAL: Duration = Duration::from_millis(100);

        let mut send_time: Vec<(u64, Instant)> = self
            .send_time
            .iter()
            .filter(|(_seqno, sent_time)| {
                now.duration_since(**sent_time) < Duration::from_secs(60)
                    && now.duration_since(**sent_time) > Duration::from_secs(2)
            })
            .map(|(s, t)| (*s, *t))
            .collect();
        send_time.sort_unstable_by_key(|k| k.0);
        let mut total_qualified = 0usize;
        let mut lost_qualified = 0usize;
        let mut total = 0usize;
        let mut lost = 0usize;
        for window in send_time.windows(WINDOW_SIZE) {
            let first = window.first().unwrap();
            let last = window.last().unwrap();
            let delta_time = last.1.saturating_duration_since(first.1);
            let middle = (first.0 + last.0) / 2;
            if let Some(&was_acked) = self.ack_or_nack.get(&middle) {
                if delta_time > WINDOW_MIN_INTERVAL {
                    log::trace!("window {}..{} is GOOD", first.0, last.0);
                    log::trace!(
                        "midpoint {middle} of {}..{} was acked? {was_acked}",
                        first.0,
                        last.0
                    );
                    total_qualified += 1;
                    if !was_acked {
                        lost_qualified += 1;
                    }
                }
                total += 1;
                if !was_acked {
                    lost += 1;
                }
            }
        }
        let qualified_loss = (lost_qualified as f64 + 0.1) / (0.1 + total_qualified as f64);
        let total_loss = (lost as f64 + 0.1) / (0.1 + total as f64);
        let loss = total_loss.min(qualified_loss).min(0.3);
        // calculate latency & jitter

        let latencies: Vec<Duration> = self
            .ack_time
            .iter()
            .filter_map(|(&seqno, &ack_time)| {
                if now.duration_since(ack_time?) < Duration::from_secs(60) {
                    Some(ack_time?.duration_since(*self.send_time.get(&seqno)?))
                } else {
                    None
                }
            })
            .collect();

        let count = latencies.len();
        if count == 0 {
            return PipeStats {
                dead: true,
                loss: 0.0,
                latency: Duration::from_secs(1000),
                jitter: Duration::from_secs(1000),
            };
        }

        // latency = μ(latencies)
        let latency = latencies
            .iter()
            .fold(Duration::from_millis(0), |accum, elem| accum + *elem)
            / (count).max(1) as u32;
        log::debug!("latency sample: {:?}", latency);

        // jitter = σ(latencies)
        let jitter = Duration::from_secs_f64(
            (latencies.iter().fold(0.0, |accum, elem| {
                let base = elem.as_secs_f64() - latency.as_secs_f64();
                accum + base.powf(2.0)
            }) / (count).max(1) as f64)
                .sqrt(),
        );

        let mut stats = PipeStats {
            dead: false,
            loss,
            latency,
            jitter,
        };
        if let Some((_, old_stat)) = self.cached_stat.take() {
            stats = stats.lerp(old_stat, 0.5);
            self.cached_stat = Some((Instant::now(), stats));
        } else {
            self.cached_stat = Some((Instant::now(), stats));
        }
        log::warn!(
            "STATS ({:.2}, loss = {:.2}, latency = {:.2}ms, jitter = {:.2}ms) took {:?}",
            stats.score(),
            stats.loss,
            stats.latency.as_secs_f64() * 1000.0,
            stats.jitter.as_secs_f64() * 1000.0,
            now.elapsed()
        );
        stats
    }

    /// Adds a batch of acknowledgements to the StatsCalculator
    pub fn add_ackreq(&mut self) {
        self.unacked_count += 1;

        self.last_ackreq = Instant::now();
    }

    /// Adds a batch of acknowledgements to the StatsCalculator
    pub fn add_acks(
        &mut self,
        first_ack: u64,
        last_ack: u64,
        ack_bitmap: Bytes,
        time_offset: Option<Duration>,
    ) {
        self.cleanup();
        self.last_ack = Instant::now();
        self.unacked_count = 0;
        if let Some(time_offset) = time_offset {
            let now = Instant::now();
            let bitmap = ack_bitmap.view_bits::<Msb0>();

            for (i, (acked, seqno)) in bitmap
                .iter()
                .zip(first_ack..=last_ack)
                .map(|(acked, seqno)| (*acked, seqno))
                .enumerate()
            {
                self.ack_time.insert(
                    seqno,
                    if i == 0 {
                        Some(now - time_offset)
                    } else {
                        None
                    },
                );
                self.ack_or_nack.insert(seqno, acked);
            }
        }
    }

    fn cleanup(&mut self) {
        if self.send_time.len() > 30_000 {
            // cut down to half
            let largest = self.send_time.keys().copied().max().unwrap_or_default();
            self.send_time.retain(|k, _| largest - k < 15_000);
            self.ack_time.retain(|k, _| largest - k < 15_000);
            self.ack_or_nack.retain(|k, _| largest - k < 15_000);
        }
    }

    /// Adds a sent packet to the StatsCalculator
    pub fn add_sent(&mut self, seqno: u64) {
        self.cleanup();
        let sent_time = Instant::now();
        self.send_time.insert(seqno, sent_time);
    }
}
