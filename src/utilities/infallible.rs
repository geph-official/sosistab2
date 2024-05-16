use std::task::Poll;

use pin_project::pin_project;
use std::future::Future;

pub trait InfallibleExt<T, E, F: Future<Output = Result<T, E>>> {
    // what I really want is "async fn infallible() -> T"
    fn infallible(self) -> InfalImpl<T, E, F>;
}

impl<T, E, F: Future<Output = Result<T, E>>> InfallibleExt<T, E, F> for F {
    fn infallible(self) -> InfalImpl<T, E, F> {
        InfalImpl {
            fut: self,
            resolved: false,
        }
    }
}

#[pin_project]
pub struct InfalImpl<T, E, F: Future<Output = Result<T, E>>> {
    #[pin]
    fut: F,
    resolved: bool,
}

impl<T, E, F: Future<Output = Result<T, E>>> Future for InfalImpl<T, E, F> {
    type Output = T;

    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        if *this.resolved {
            return Poll::Pending;
        }
        match this.fut.poll(cx) {
            Poll::Ready(val) => match val {
                Ok(val) => Poll::Ready(val),
                Err(_) => {
                    *this.resolved = true;
                    Poll::Pending
                }
            },
            Poll::Pending => Poll::Pending,
        }
    }
}
