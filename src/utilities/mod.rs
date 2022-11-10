pub mod batchtimer;
pub mod sockets;
use std::pin::Pin;
use std::task::Poll;

pub use batchtimer::*;
pub mod infallible;
pub use batchtimer::*;

use futures_util::Future;
use rustc_hash::FxHashSet;

impl<T: Future> MyFutureExt for T {}

/// Our own futures extension trait
pub(crate) trait MyFutureExt: Future + Sized {
    /// Returns a future that is pending unless a certain value is true. Useful to "turn off" a future based on a condition.
    fn pending_unless(self, unless: bool) -> PendingUnless<Self> {
        PendingUnless {
            inner: self,
            always_pending: !unless,
        }
    }
}

pub(crate) struct PendingUnless<T: Future> {
    inner: T,
    always_pending: bool,
}

impl<T: Future> Future for PendingUnless<T> {
    type Output = T::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        if self.always_pending {
            Poll::Pending
        } else {
            let inner = unsafe { self.map_unchecked_mut(|v| &mut v.inner) };
            inner.poll(cx)
        }
    }
}

/// A filter for replays. Records recently seen seqnos and rejects either repeats or really old seqnos.
#[derive(Debug, Default)]
pub struct ReplayFilter {
    top_seqno: u64,
    bottom_seqno: u64,
    seen_seqno: FxHashSet<u64>,
}

impl ReplayFilter {
    pub fn add(&mut self, seqno: u64) -> bool {
        if seqno < self.bottom_seqno {
            // out of range. we can't know, so we just say no
            return false;
        }
        // check the seen
        if self.seen_seqno.contains(&seqno) {
            return false;
        }
        self.seen_seqno.insert(seqno);
        self.top_seqno = seqno.max(self.top_seqno);
        while self.top_seqno - self.bottom_seqno > 10000 {
            self.seen_seqno.remove(&self.bottom_seqno);
            self.bottom_seqno += 1;
        }
        true
    }
}
