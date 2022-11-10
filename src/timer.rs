use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

use dashmap::DashMap;

use futures_intrusive::sync::ManualResetEvent;
use once_cell::sync::Lazy;
use parking_lot::RwLock;

/// High performance sleep
pub async fn fastsleep(dur: Duration) {
    fastsleep_until(Instant::now() + dur).await;
}

/// High performance sleep until
pub async fn fastsleep_until(at: Instant) {
    Lazy::force(&TIMER_THREAD);
    // yield once so that if this future isn't polled we don't do anything
    smol::future::yield_now().await;
    let target_uptime_ms = at.saturating_duration_since(*START).as_millis() as u64;
    let evt = {
        let notifiers = NOTIFIERS.read();
        if CURR_UPTIME_MS.load(Ordering::SeqCst) < target_uptime_ms {
            let evt: Arc<ManualResetEvent> = notifiers
                .entry(target_uptime_ms)
                .or_insert_with(|| Arc::new(ManualResetEvent::new(false)))
                .clone();
            Some(evt)
        } else {
            None
        }
    };
    if let Some(val) = evt {
        val.wait().await
    }
}

static START: Lazy<Instant> = Lazy::new(Instant::now);
static CURR_UPTIME_MS: AtomicU64 = AtomicU64::new(0);

/// we nest a dashmap in a rwlock so the timer thread can take exclusive access as needed
static NOTIFIERS: Lazy<RwLock<DashMap<u64, Arc<ManualResetEvent>>>> = Lazy::new(Default::default);

static TIMER_THREAD: Lazy<JoinHandle<()>> = Lazy::new(|| {
    std::thread::Builder::new()
        .name("fast_timer".into())
        .spawn(|| {
            let start = Instant::now();
            let mut notified_up_to = 0;
            loop {
                let now = Instant::now();
                let current_uptime = now.saturating_duration_since(start).as_millis() as u64;
                CURR_UPTIME_MS.store(current_uptime, Ordering::SeqCst);
                // wake up everything before this
                {
                    let notifiers = NOTIFIERS.write();
                    while notified_up_to <= current_uptime {
                        if let Some((_, handle)) = notifiers.remove(&notified_up_to) {
                            handle.set();
                        }
                        notified_up_to += 1;
                    }
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        })
        .unwrap()
});
