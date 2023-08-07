use std::time::{Duration, Instant};

// A "stopwatch" that returns when a timer is up or when a counter reaches a max count, whichever is first
pub struct BatchTimer {
    deadline: Instant,
    interval: Duration,

    count: usize,
    max_count: usize,
}

impl BatchTimer {
    /// Creates a new batch timer.
    pub fn new(interval: Duration, max_count: usize) -> Self {
        Self {
            deadline: Instant::now() + interval,
            interval,
            count: 0,
            max_count,
        }
    }

    /// Waits until either a certain number of [Self::increment] calls has happened, or a certain amount of time has elapsed, since the last call to [Self::reset] or the construction of this object.
    pub async fn wait(&self) {
        if self.count == 0 {
            // println!("count is 0 so the timer does not fire");
            smol::future::pending().await
        }
        if self.count < self.max_count {
            // println!("count is {} so the timer fires later", self.count);
            smol::Timer::at(self.deadline).await;
        }
        // println!("TIMER HAS FIRED");
    }

    /// Increments the internal counter.
    pub fn increment(&mut self) {
        self.count += 1
    }

    /// Resets the timer.
    pub fn reset(&mut self) {
        self.deadline = Instant::now() + self.interval;
        self.count = 0;
    }
}
