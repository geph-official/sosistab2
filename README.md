# Sosistab2 - an obfuscated datagram transport for horrible networks

[![](https://img.shields.io/crates/v/sosistab2)](https://crates.io/crates/sosistab2)
![](https://img.shields.io/crates/l/sosistab2)

Sosistab2 is a vaguely QUIC-like datagram transport framework. Over a single `Multiplex` session, it multiplexes streams that support both reliable TCP-like bytestreams and UDP-like unreliable datagrams.

The cool feature, and key innovation over the [legacy sosistab protocol](https://github.com/geph-official/sosistab), is that the same `Multiplex` can be backed by _multiple_ "pipes". Pipes implement the `Pipe` trait and are a simple abstraction over an unreliable datagram transport. A `Multiplex` will intelligently decide what pipe to send its traffic down, and automatically avoids non-functional pipes. The `Multiplex` also maintains end-to-end encryption using chacha20-poly1305 with a triple-x25519 key exchange, and does not trust the `Pipe`s for confidentiality, integrity, or authentication in any way.

This crate comes with two `Pipe` implementations:

- `ObfsUdpPipe`, an obfuscated, loss-resistant UDP transport
  - uses an active-probing-resistant and padded (obfs4-like) obfuscation, with traffic reasonably indistinguishable from random.
  - Reed-Solomon forward error correction that auto-adjusts to detected packet loss level and uses dynamic batch sizes, nearly eliminating all sporadic packet loss and making bad links much more usable. Packet loss calculation intelligently avoids counting "fully loaded" traffic to detect the _uncontended_ packet loss level, to avoid congestion causing increasing FEC redundancy and congestive collapse.
- `ObfsTlsPipe`, an obfuscated TLS transport
  - uses configurable `native-tls` connectors to mitigate TLS fingerprinting. `native-tls` uses OS-native TLS libraries and is least likely to be fingerprinted.
  - padding is used to obfuscate packet size signatures
  - servers are active-probing resistant by means of a preshared secret cookie that must be transmitted within the TLS session.
  - no attempt is made to imitate browser HTTPS. the intention is to imitate "unknown TLS-based protocols" --- blocking all unclassifiable TLS protocols is likely to cause massive collateral damage beyond blocking obfs4-like high entropy protocols, considering that it's the most common way for new software to trasmit encrypted traffic.

Other crates may also implement the `Pipe` interface. For instance, we are currently working on a thoroughly browser-imitating HTTP(S) transport.
