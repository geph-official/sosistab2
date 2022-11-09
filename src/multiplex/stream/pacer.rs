use std::time::{Duration, Instant};

const QUANTUM: u32 = 8;

/// A high-precision pacer that uses async-io's timers under the hood.
pub struct Pacer {
    next_pace_time: Instant,
    timer: smol::Timer,
    interval: Duration,
    counter: u32,
}

impl Pacer {
    /// Creates a new pacer with a new interval.
    pub fn new(interval: Duration) -> Self {
        Self {
            next_pace_time: Instant::now(),
            timer: smol::Timer::at(Instant::now()),
            interval,
            counter: 0,
        }
    }

    /// Waits until the next time.
    pub async fn wait_next(&mut self) {
        self.counter += 1;
        if self.counter >= QUANTUM {
            self.counter = 0;
            (&mut self.timer).await;
            self.next_pace_time = Instant::now().max(self.next_pace_time + self.interval * QUANTUM);
            self.timer.set_at(self.next_pace_time);
        } else {
            smol::future::yield_now().await;
        }
    }

    /// Changes the interval.
    pub fn set_interval(&mut self, interval: Duration) {
        self.interval = interval
    }
}
