use std::time::{Duration, Instant};

use bitvec::{prelude::Msb0, view::BitView};
use bytes::Bytes;

use parking_lot::RwLock;
use probability::prelude::Inverse;
use rustc_hash::FxHashMap;

#[derive(Clone, Copy, Debug)]
pub struct PipeStats {
    pub loss: f64, // 0 to 1
    pub latency: Duration,
    pub jitter: Duration,
}

impl PipeStats {
    pub fn score(&self) -> u64 {
        let threshold: f64 = 0.01;
        let n = threshold.log(self.loss).ceil(); // number of transmissions needed so that Prob(pkt is lost) <= threshold
        ((n * self.latency.as_secs_f64()).ln() * 1000.0) as u64
    }
}

/// A statistics calculator.
pub struct StatsCalculator {
    /// seqno => sending time
    send_time: FxHashMap<u64, Instant>,
    /// seqno => if privileged, Some(the adjusted ack time), otherwise None
    ack_time: FxHashMap<u64, Option<Instant>>,
    ack_or_nack: FxHashMap<u64, bool>,

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
            cached_stat: None,
        }
    }

    /// Calculates stats based on recent data.
    pub fn get_stats(&mut self) -> PipeStats {
        if let Some((utime, stat)) = self.cached_stat {
            if utime.elapsed() < Duration::from_secs(5) {
                return stat;
            }
        }
        // calculate loss
        let now = Instant::now();
        const WINDOW_SIZE: usize = 20;
        const WINDOW_MIN_INTERVAL: Duration = Duration::from_millis(100);

        let mut send_time: Vec<(u64, Instant)> = self
            .send_time
            .iter()
            .filter(|(_seqno, sent_time)| {
                now.duration_since(**sent_time) < Duration::from_secs(30)
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
        let qualified_loss = lost_qualified as f64 / (0.1 + total_qualified as f64);
        let total_loss = lost as f64 / (0.1 + total as f64);
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

        // latency = μ(latencies)
        let latency = latencies
            .iter()
            .fold(Duration::from_millis(0), |accum, elem| accum + *elem)
            / (count).max(1) as u32;

        // jitter = σ(latencies)
        let jitter = Duration::from_secs_f64(
            (latencies.iter().fold(0.0, |accum, elem| {
                let base = elem.as_secs_f64() - latency.as_secs_f64();
                accum + base.powf(2.0)
            }) / (count).max(1) as f64)
                .sqrt(),
        );

        let stats = PipeStats {
            loss,
            latency,
            jitter,
        };
        self.cached_stat = Some((Instant::now(), stats));
        log::warn!("STATS took {:?}", now.elapsed());
        stats
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
        if self.send_time.len() > 100_000 {
            // cut down to half
            let largest = self.send_time.keys().copied().max().unwrap_or_default();
            self.send_time.retain(|k, _| largest - k < 50_000);
            self.ack_time.retain(|k, _| largest - k < 50_000);
            self.ack_or_nack.retain(|k, _| largest - k < 50_000);
        }
    }

    /// Adds a sent packet to the StatsCalculator
    pub fn add_sent(&mut self, seqno: u64) {
        self.cleanup();
        let sent_time = Instant::now();
        self.send_time.insert(seqno, sent_time);
    }
}

/// Exponential moving average and standard deviation calculator
#[derive(Debug, Clone)]
pub struct EmaCalculator {
    mean_accum: f64,
    variance_accum: f64,
    set: bool,
    alpha: f64,
}

impl EmaCalculator {
    /// Creates a new calculator with the given initial estimate and smoothing factor (which should be close to 0)
    pub fn new(initial_mean: f64, alpha: f64) -> Self {
        Self {
            mean_accum: initial_mean,
            variance_accum: initial_mean.powi(2),
            alpha,
            set: true,
        }
    }

    /// Creates a new calculator with nothing set.
    pub fn new_unset(alpha: f64) -> Self {
        Self {
            mean_accum: 0.0,
            variance_accum: 0.001,
            alpha,
            set: false,
        }
    }

    /// Updates the calculator with a given data point
    pub fn update(&mut self, point: f64) {
        if !self.set {
            self.mean_accum = point;
            self.variance_accum = 0.0;
            self.set = true
        }
        // https://stats.stackexchange.com/questions/111851/standard-deviation-of-an-exponentially-weighted-mean
        self.variance_accum = (1.0 - self.alpha)
            * (self.variance_accum + self.alpha * (point - self.mean_accum).powi(2));
        self.mean_accum = self.mean_accum * (1.0 - self.alpha) + self.alpha * point;
    }

    /// Gets a very rough approximation (normal approximation) of the given percentile
    pub fn inverse_cdf(&self, frac: f64) -> f64 {
        let stddev = self.variance_accum.sqrt();
        if stddev > 0.0 {
            let dist = probability::distribution::Gaussian::new(
                self.mean_accum,
                self.variance_accum.sqrt(),
            );
            dist.inverse(frac)
        } else {
            self.mean_accum
        }
    }

    /// Gets the current mean
    pub fn mean(&self) -> f64 {
        self.mean_accum
    }
}
