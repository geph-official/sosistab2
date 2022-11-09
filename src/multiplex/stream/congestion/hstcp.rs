use std::time::Instant;

use super::CongestionControl;

/// HSTCP-style congestion control, with a Westwood-style modification.
pub struct Highspeed {
    cwnd: f64,
    multiplier: usize,
    bdp: usize,
    last_loss: Instant,
}

impl Highspeed {
    /// Creates a new HSTCP instance with the given increment.
    pub fn new(multiplier: usize) -> Self {
        Self {
            cwnd: 32.0,
            multiplier,
            last_loss: Instant::now(),
            bdp: 0,
        }
    }
}

impl CongestionControl for Highspeed {
    fn cwnd(&self) -> usize {
        self.cwnd as usize
    }

    fn mark_ack(&mut self, current_bdp: usize, ping: usize) {
        // let multiplier = self.last_loss.elapsed().as_secs_f64().max(1.0).min(32.0);
        // tracing::debug!("ack => {:.2}", self.cwnd);
        self.bdp = current_bdp;
        self.cwnd += self.multiplier as f64 * (ping as f64 / 50.0) * (self.cwnd.powf(0.4)).max(1.0)
            / self.cwnd;
        // tracing::debug!("ack {}", self.cwnd);
    }

    fn mark_loss(&mut self) {
        tracing::debug!("loss!!! => {:.2}", self.cwnd);
        self.cwnd = (self.cwnd * 0.5).max(4.0).max(self.bdp as f64);
        self.last_loss = Instant::now();
    }
}
