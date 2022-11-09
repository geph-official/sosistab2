use super::CongestionControl;

/// Completely trivial congestion-control that keeps a constant window.
pub struct Trivial {
    cwnd: usize,
}

impl Trivial {
    pub fn new(cwnd: usize) -> Self {
        Self { cwnd }
    }
}

impl CongestionControl for Trivial {
    fn cwnd(&self) -> usize {
        self.cwnd
    }

    fn mark_ack(&mut self, _cp: usize, _: usize) {}

    fn mark_loss(&mut self) {}
}
