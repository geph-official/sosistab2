use std::time::{Duration, Instant};

/// High performance sleep
pub async fn fastsleep(dur: Duration) {
    fastsleep_until(Instant::now() + dur).await;
}

/// High performance sleep until
pub async fn fastsleep_until(at: Instant) {
    #[cfg(feature = "microsleep")]
    microsleep::until(at).await;

    #[cfg(not(feature = "microsleep"))]
    smol::Timer::at(at).await;
}
