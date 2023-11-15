# Sosistab2 - an obfuscated datagram transport for horrible networks

[![](https://img.shields.io/crates/v/sosistab2)](https://crates.io/crates/sosistab2)
![](https://img.shields.io/crates/l/sosistab2)

Sosistab2 is a vaguely QUIC-like datagram transport framework. Over a single `Multiplex` session, it multiplexes streams that support both reliable TCP-like bytestreams and UDP-like unreliable datagrams.

The cool feature, and key innovation over the [legacy sosistab protocol](https://github.com/geph-official/sosistab), is that the same `Multiplex` can be backed by _multiple_ "pipes". Pipes implement the `Pipe` trait and are a simple abstraction over an unreliable datagram transport. A `Multiplex` will intelligently decide what pipe to send its traffic down, and automatically avoids non-functional pipes. The `Multiplex` also maintains end-to-end encryption using chacha20-poly1305 with a triple-x25519 key exchange, and does not trust the `Pipe`s for confidentiality, integrity, or authentication in any way.
