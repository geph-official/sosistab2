use std::time::{Duration, Instant};

/// High performance sleep
pub async fn fastsleep(dur: Duration) {
    fastsleep_until(Instant::now() + dur).await;
}

/// High performance sleep until
pub async fn fastsleep_until(at: Instant) {
    smol::Timer::at(at).await;
}
