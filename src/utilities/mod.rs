pub mod batchtimer;
pub mod sockets;
use std::pin::Pin;
use std::task::Poll;

pub use batchtimer::*;
pub mod infallible;
pub use batchtimer::*;

use futures_util::Future;
use probability::prelude::Inverse;
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

/// Exponential moving average and standard deviation calculator
#[derive(Debug, Clone)]
pub struct EmaCalculator {
    mean_accum: f64,
    variance_accum: f64,
    set: bool,
    alpha: f64,
}

impl EmaCalculator {
    /// Creates a new calculator with the given initial estimate and smoothing factor (which should be close to 0)
    pub fn new(initial_mean: f64, alpha: f64) -> Self {
        Self {
            mean_accum: initial_mean,
            variance_accum: initial_mean.powi(2),
            alpha,
            set: true,
        }
    }

    /// Updates the calculator with a given data point
    pub fn update(&mut self, point: f64) {
        if !self.set {
            self.mean_accum = point;
            self.variance_accum = 0.0;
            self.set = true
        }
        // https://stats.stackexchange.com/questions/111851/standard-deviation-of-an-exponentially-weighted-mean
        self.variance_accum = (1.0 - self.alpha)
            * (self.variance_accum + self.alpha * (point - self.mean_accum).powi(2));
        self.mean_accum = self.mean_accum * (1.0 - self.alpha) + self.alpha * point;
    }

    /// Gets a very rough approximation (normal approximation) of the given percentile
    pub fn inverse_cdf(&self, frac: f64) -> f64 {
        let stddev = self.variance_accum.sqrt();
        if stddev > 0.0 {
            let dist = probability::distribution::Gaussian::new(
                self.mean_accum,
                self.variance_accum.sqrt(),
            );
            dist.inverse(frac)
        } else {
            self.mean_accum
        }
    }

    /// Gets the current mean
    pub fn mean(&self) -> f64 {
        self.mean_accum
    }
}
