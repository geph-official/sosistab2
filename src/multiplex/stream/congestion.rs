use std::time::Instant;

/// HSTCP-style congestion control, with a Westwood-style modification.
pub struct Highspeed {
    cwnd: f64,
    multiplier: usize,
    bdp: usize,
    last_loss: Instant,
}

impl Highspeed {
    /// Creates a new HSTCP instance with the given increment.
    pub fn new(multiplier: usize, init_cwnd: usize) -> Self {
        Self {
            cwnd: init_cwnd as _,
            multiplier,
            last_loss: Instant::now(),
            bdp: 0,
        }
    }

    pub fn cwnd(&self) -> usize {
        self.cwnd as usize
    }

    pub fn mark_ack(&mut self, current_bdp: usize) {
        // let multiplier = self.last_loss.elapsed().as_secs_f64().max(1.0).min(32.0);
        // log::debug!("ack => {:.2}", self.cwnd);
        self.bdp = current_bdp;
        self.cwnd += self.multiplier as f64 * (self.cwnd.powf(0.4)).max(1.0) / self.cwnd;
        // log::debug!("ack {}", self.cwnd);
    }

    pub fn mark_loss(&mut self) {
        self.cwnd = (self.cwnd * 0.5)
            .max(1.0)
            // .max(self.bdp as f64 * 0.9)
            .min(self.cwnd);
        self.last_loss = Instant::now();
    }
}
