# Vendored libp2p-stream 0.4.0-alpha

This directory contains the source of `libp2p-stream` 0.4.0-alpha from the
[`rust-libp2p`](https://github.com/libp2p/rust-libp2p) repository.

- crates.io checksum: `1d6bd8025c80205ec2810cfb28b02f362ab48a01bee32c50ab5f12761e033464`
- upstream git commit: `7b9a558e3188eaf20a14bd8388d5e9b6e2aa9a23`
- upstream path: `protocols/stream`
- license: MIT; the upstream license text is preserved in `LICENSE`

TASK-219 carries three local production-source deltas:

- It adds the deliberately narrow API
  `Control::open_stream_on_connection(peer, connection_id, protocol)`. It selects the sender for
  that exact live connection while holding the shared-state lock, rejects a stale or wrong-peer ID
  with `io::ErrorKind::NotConnected`, and never randomly selects another connection or auto-dials.
- It removes the matching handler sender when a connection closes, so a closed ID cannot retain
  stale channel state.
- It replaces the upstream deprecated `Receiver::try_next` calls with the equivalent
  `Receiver::try_recv` API. The dial-failure regression test verifies that every queued open
  request still receives the terminal error.

All other production source remains the upstream 0.4.0-alpha implementation. The standalone
manifest is normalized for this workspace and omits upstream dev-only dependencies and test files
that are not shipped here; focused local unit tests cover the exact-connection and drain deltas.
