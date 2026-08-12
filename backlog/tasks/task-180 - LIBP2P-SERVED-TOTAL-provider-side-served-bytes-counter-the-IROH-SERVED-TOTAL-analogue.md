---
id: TASK-180
title: >-
  LIBP2P-SERVED-TOTAL provider-side served-bytes counter (the IROH-SERVED-TOTAL
  analogue)
status: To Do
assignee: []
created_date: '2026-08-12 23:03'
labels:
  - libp2p
  - daemon
  - e2e
  - wave-2c
dependencies:
  - TASK-179
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Add a provider-side served-bytes counter to the libp2p serving path so peer-attribution rests on a PROVIDER counter (the analogue of iroh IROH-SERVED-TOTAL), not only on the consumer-side "0 upstream egress + BOOT-holds-nothing + byte-identity" construction. Split off TASK-179 (secondary) because it is a fabric-libp2p SUBSTRATE change (not a small daemon change) + a nix e2e-image rebuild + e2e re-run; TASK-179 landed the separate-netns F1 discharge without it.

TURNKEY DESIGN (worked out under TASK-179):
1. fabric-libp2p/src/nar.rs: add `pub struct ServeByteMeter { served_bytes: AtomicU64, served_transfers: AtomicU64 }` (Default). Give ServeGate an `Arc<ServeByteMeter>` field. Add `ServeGate::with_meter(budget, supplier, meter)` and keep `new` delegating with a fresh meter (so the existing unit tests + call sites are untouched). In `respond()`, on the Ok(bytes) arm (where `admitted` is bumped), also do meter.served_bytes += bytes.len() and served_transfers += 1.
2. fabric-libp2p/src/server.rs: Libp2pServer holds `Arc<ServeByteMeter>`; `new(handle, supplier, meter)`; `serve()` builds the gate via `ServeGate::with_meter(budget, supplier, self.meter.clone())` so the counter is SHARED across serve sessions (monotonic, like iroh).
3. fabric-libp2p/src/fabric.rs: in `assemble()` create the meter when a supplier is present, pass it to Libp2pServer::new, STORE it on Libp2pFabric, and expose `pub fn serve_meter(&self) -> Option<Arc<ServeByteMeter>>`.
4. daemon/src/main.rs (setup_libp2p_provider, ~L1388 after LIBP2P-PROVIDER-ADDR): clone fabric.serve_meter() and spawn a monitor (mirror the iroh monitor ~L1149) that logs `LIBP2P-SERVED-TOTAL bytes=N transfers=M` when it advances. Use the same task-spawn discipline as the iroh path.
5. scripts/e2e_harness.py: give Libp2pNetnsTopology a `provider_served_bytes(want_at_least, timeout_s)` poller (mirror Pod.node_b_served_bytes / IROH-SERVED-TOTAL parse at ~L1194) reading lp-provider logs; assert served>=target_size in the POSITIVE arm of scenario_s7_libp2p_netns (and optionally in scenario_s7_libp2p). Rebuild .#e2e-image; re-run s7-libp2p-netns + regression (bounded); clean pods+networks.

GOTCHA: NarSize (uncompressed NAR) vs FileSize (compressed transport) are different units - assert served-bytes against the UNCOMPRESSED nar_size (P2pSeed.nar_size), which is what the gate meters (respond serves the raw NAR).
<!-- SECTION:DESCRIPTION:END -->
