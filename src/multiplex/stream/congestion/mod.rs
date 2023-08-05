mod highspeed;

pub use highspeed::*;

pub trait CongestionControl {
    /// Gets the current CWND
    fn cwnd(&self) -> usize;

    /// React to an incoming acknowledgement of a single packet
    fn mark_ack(&mut self);

    /// React to a loss event
    fn mark_loss(&mut self);
}
