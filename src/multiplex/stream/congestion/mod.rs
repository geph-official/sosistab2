mod cubic;
mod hstcp;
mod trivial;
pub use cubic::*;
pub use hstcp::*;
pub use trivial::*;

pub trait CongestionControl {
    /// Gets the current CWND
    fn cwnd(&self) -> usize;

    /// React to an incoming acknowledgement of a single packet
    fn mark_ack(&mut self, current_bdp: usize, current_ping: usize);

    /// React to a loss event
    fn mark_loss(&mut self);
}
