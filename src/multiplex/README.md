# Refactoring plan

## "Outer" multiplex stuff

The current "many async blocks and an enum" event handling method causes functions to be annoyingly long-winded, on top of causing the Rust compiler to generate poor-quality code.

Instead, we should have `Arc<MultiplexState>`, which will have well-defined methods for state transitions, that is passed to a few looping tasks, such as `recv_msg_loop`, that handle events and call specific methods.

This also maximizes opportunity for concurrency.

## Streams

The tricky thing here is the large number of events fired at a very fine-grained level.

Instead, we should have a KCP-style loop that calls a `tick()` function that goes through the `StreamState` and takes actions accordingly, in a non-blocking fashion.

The tricky part is avoiding the requirement to continually call `tick()` at a fixed interval (and wasting battery etc). This is by having `tick()` return an `Instant` that designates the next time it should be called.

The next tricky part, given this, is having `tick()` run immediately after an incoming event. This is done by the external loop also poll a `ManualResetEvent` or similar inside the `StreamState` in addition to the ticking timer.
