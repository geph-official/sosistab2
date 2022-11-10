use std::time::{Duration, Instant};

use crate::EmaCalculator;

pub struct RttCalculator {
    inner: EmaCalculator,

    min_rtt: Duration,
    rtt_update_time: Instant,
}

impl Default for RttCalculator {
    fn default() -> Self {
        RttCalculator {
            inner: EmaCalculator::new(0.5, 0.01),
            min_rtt: Duration::from_millis(500),
            rtt_update_time: Instant::now(),
        }
    }
}

impl RttCalculator {
    pub fn record_sample(&mut self, sample: Duration) {
        let now = Instant::now();
        if sample < self.min_rtt
            || now
                .saturating_duration_since(self.rtt_update_time)
                .as_millis()
                > 3000
        {
            self.min_rtt = sample;
            self.rtt_update_time = now;
        }
        self.inner.update(sample.as_secs_f64())
    }

    pub fn rto(&self) -> Duration {
        Duration::from_secs_f64(self.inner.inverse_cdf(0.99) + 0.25)
    }

    // pub fn srtt(&self) -> Duration {
    //     Duration::from_secs_f64(self.inner.mean())
    // }

    pub fn rtt_var(&self) -> Duration {
        Duration::from_secs_f64(self.inner.inverse_cdf(0.99) - self.inner.inverse_cdf(0.01))
    }

    pub fn min_rtt(&self) -> Duration {
        self.min_rtt
    }
}

pub struct BwCalculator {
    delivered: u64,
    delivered_time: Instant,

    // delivery_max_filter: MinQueue<Reverse<(OrderedFloat<f64>, Instant)>>,
    max_speed: f64,
    max_speed_time: Instant,
}

impl Default for BwCalculator {
    fn default() -> Self {
        Self {
            delivered: 0,
            delivered_time: Instant::now(),
            max_speed: 0.0,
            max_speed_time: Instant::now(),
        }
    }
}

impl BwCalculator {
    /// On ack
    pub fn on_ack(&mut self, packet_delivered: u64, packet_delivered_time: Instant) {
        let now = Instant::now();
        self.delivered += 1;
        self.delivered_time = now;
        let delivery_rate = (self.delivered - packet_delivered) as f64
            / (self.delivered_time - packet_delivered_time).as_secs_f64();
        if delivery_rate > self.max_speed
            || now.saturating_duration_since(self.max_speed_time).as_secs() > 10
        {
            self.max_speed = delivery_rate;
        }
        // log::warn!("current rate is {}", self.delivery_rate());
    }

    /// Gets the current delivery rate
    pub fn delivery_rate(&self) -> f64 {
        self.max_speed
    }

    /// Gets the current delivered packets
    pub fn delivered(&self) -> u64 {
        self.delivered
    }

    /// Gets the current delivered time
    pub fn delivered_time(&self) -> Instant {
        self.delivered_time
    }
}
