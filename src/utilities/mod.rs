use std::pin::Pin;
use std::task::Poll;

pub mod infallible;

use futures_util::Future;

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
