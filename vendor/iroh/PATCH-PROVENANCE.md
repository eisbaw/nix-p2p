# Vendored iroh 1.0.3 shutdown patch

This directory starts from the exact `iroh` 1.0.3 crate published on crates.io.

- crates.io archive SHA-256: `460de6bc52163b41b1646931f2897e5ab986f0966ade444467fec25024751a72`
- upstream repository: <https://github.com/n0-computer/iroh>
- upstream commit recorded by the crate: `f2eb930dda3779c6d852b72f3712aacd6e573ab1`
- upstream path recorded by the crate: `iroh`
- declared upstream license: `MIT OR Apache-2.0`
- upstream `LICENSE-MIT` SHA-256: `f169adb8124d3b005416d8485d00777c9a7bdd9099982c52a4493f9732e6d050`
- upstream `LICENSE-APACHE` SHA-256: `903131e2786f073a942fbf8fae122d9e576e4dad758c6da7f9f2ba58fd8611ab`
- additional packaged notice: `LICENSE-BSD3` (socket code derived in part from Tailscale)

The archive hash can be reproduced against the Cargo registry artifact named
`iroh-1.0.3.crate`. The original `.cargo_vcs_info.json` and `LICENSE-BSD3` are
preserved verbatim. The published archive declares and links the MIT and Apache
licenses without packaging their text, so `LICENSE-MIT` and `LICENSE-APACHE` are
copied verbatim from the recorded upstream commit and pinned above by hash.

The local production delta is deliberately limited to endpoint resource release:

- retain an `Arc<netwatch::UdpSocket>` for every successfully bound IP transport;
- after QUIC drain, abort and then join the socket actor so a task stuck away from
  its cancellation select cannot strand socket clones, and its future is proven
  dropped before release continues;
- on native targets, stop and join Noq runtime tasks, then await
  `UdpSocket::close()` for every retained Iroh IP-transport socket before
  marking the endpoint closed or returning from `Endpoint::close`;
- elect one internally owned close driver and make every public close caller await
  its shared completion, so cancelling a caller cannot cancel resource release;
- synchronously start Noq close on the first public poll before spawning the
  driver, preserving the endpoint-first shutdown ordering;
- move one owning terminal guard into the unpolled driver future, so spawn
  failure, pre-poll cancellation, mid-driver panic, and normal completion all
  wake every waiter exactly once;
- continue native runtime and socket release after an actor panic, then publish
  that actor failure to every waiter only after the release barrier;
- document the strengthened public close guarantee.

Six deterministic unit regressions cover the release barrier. The concurrent
and cancelled-caller cases occupy Tokio's sole blocking worker and remain pending
at the explicit UDP-close barrier. A synthetic forever-pending actor proves close
does not rely on cooperative cancellation, while a Drop sentinel separately
proves actor teardown joins through destruction of the task future. An unpolled
driver-future test proves terminal-guard ownership has no spawn-to-first-poll
gap. Finally, an already-panicked actor proves close publishes failure only after
resource release and immediate fixed-port rebind. The fixed-port cases keep an
original `Endpoint` clone alive throughout.

No retry, sleep-based release surrogate, `SO_REUSEPORT`, or downstream bind probe
is part of the patch.
