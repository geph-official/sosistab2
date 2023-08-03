# Refactoring plan

## "Outer" multiplex stuff

The current "many async blocks and an enum" event handling method causes functions to be annoyingly long-winded, on top of causing the Rust compiler to generate poor-quality code.

Instead, we should have `Arc<MultiplexState>`, which will have well-defined methods for state transitions, that is passed to a few looping tasks, such as `recv_msg_loop`, that handle events and call specific methods.

This also maximizes opportunity for concurrency.

One challenge for this approach is handling _reactions_ generated by the state, such as responses to hello packets. This can be done by having, say, the `process_msg` method take a callback that's called for every message generated.

There actually aren't any scenarios, other than streams (which are handled by "ticking", see later) where something inside the multiplex "autonomously" generates events, so there is no need for any background processes or I/O inside the multiplex struct.

The final workflow looks like this:

- One loop that handles incoming messages and calls `process_msg` on the state, which also calls a passed-in callback for generated messages.
- Another loop that calls `tick_all()`, which ticks all the streams and returns the closest Instant, as well as calling a callback for any generated messages.
- Another loop that drains the callback channel and handles things accordingly.
- Method for sending messages calls `send_outgoing` on the state directly, no channels

## Streams

The tricky thing here is the large number of events fired at a very fine-grained level.

Instead, we should have a KCP-style loop that calls a `tick()` function that goes through the `StreamState` and takes actions accordingly, in a non-blocking fashion.

The tricky part is avoiding the requirement to continually call `tick()` at a fixed interval (and wasting battery etc). This is by having `tick()` return an `Instant` that designates the next time it should be called.

The next tricky part, given this, is having `tick()` run immediately after an incoming event. This is done by the external loop also polling a `ManualResetEvent` or similar inside the `StreamState` in addition to the ticking timer.

There can be one huge loop at the multiplex level that simply loops through everything calling `tick()`. This saves on wakeups. On a busy server this just degenerates into calling `tick()` constantly (perhaps with a rate limit, like once per ms), but that's perfectly okay.

A final tricky thing is handling stream opens. This is done by the client adding a stream in the pre-syn-sent state into the connection table, then returning the Stream handle to it. Before returning, it waits until the stream enters the connected state. Everything else will be taken care of by the usual ticking etc workflow.