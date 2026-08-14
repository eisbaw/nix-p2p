---
id: TASK-209
title: >-
  libp2p kad-DHT discovery over a SHAPED link (3-node bootstrap variant) — the
  discover-over-realistic-link extension of TASK-206
status: Done
assignee: []
created_date: '2026-08-14 17:57'
updated_date: '2026-08-14 19:08'
labels:
  - connectivity
  - measurement
  - libp2p
  - credibility
dependencies:
  - TASK-206
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-206 closed the (b) fetch-over-a-realistic-link residual: a real libp2p /nar/3 fetch/serve is BYTE-IDENTICAL over a tc-netem-shaped veth pair (scripts/shaped_libp2p.py, fabric-libp2p/examples/shaped_probe.rs). It drives the FETCH via a direct-multiaddr dial (the same serve_stream byte path), so the DISCOVER half over the shaped link is NOT exercised: kad DHT resolution over a shaped link is currently only shown unshaped (TASK-179 routed netns at ~0 RTT). SCOPE: add a 3-node variant — a bootstrap + provider in ns A, consumer in ns B — so the consumer's kad join + get_closest_peers resolution ALSO traverses the shaped veth before the fetch, matching the loopback proof (fetch_is_byte_identical_and_blake3_verified_across_two_nodes uses the DHT). Reuse shaped_probe (add a 'bootstrap'/'provide-dht'/'fetch-dht' mode threading Libp2pNodeLocator/join). Watch: kad query_timeout is 10s and the transport's locate deadline 15s — check they hold under 40ms+ RTT (a real finding if too tight). This is essentially the libp2p-through-shaped-netns discovery wiring TASK-198 also needs. Low urgency: the connectivity CREDIBILITY claim is already earned by TASK-206 (fetch) + TASK-179 (discover on routed netns); this unifies both over one shaped link.
<!-- SECTION:DESCRIPTION:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
DONE (spike feasible -> full proof + RTT-sweep finding). Impl commit f03b38e.

WHAT: extends TASK-206's shaped-libp2p substrate from a 2-node DIRECT-dial fetch to a 3-node kad topology so the DISCOVER half (get_providers + peer-routing get_closest_peers) ALSO crosses the tc-netem-shaped veth. Topology: bootstrap B + provider P in ns A, consumer C in ns B (nsenter, the TASK-206 process-level pattern). C knows ONLY B; every C round-trip (join, get_providers, get_closest_peers/locate, /nar/3 fetch) traverses the shaped link. AC#9: C is given NO provider addr/PeerId; the DHT-resolved dial address is asserted to carry P's REAL listen addr (/ip4/10.99.0.1/tcp/9099) which C was never told (it had only bootstrap :9098) -> resolution is genuinely kad, not injection.

FILES: fabric-libp2p/examples/shaped_kad_probe.rs (bootstrap/provide-dht/fetch-dht; EXAMPLE not src/, so check_shaping_out_of_daemon stays green), scripts/shaped_kad_inner.sh (3 procs across 2 netns), scripts/shaped_kad.py (proof + --sweep + --self-test), Justfile 'shaped-kad'.

PROOF (delay 20ms, cap 100mbit, 40MiB incompressible NAR): shaped RTT 53435000 ns (~2*20ms), kad find=Found locate=Found, DHT-resolved addr = P real listen, fetch byte_identical+blake3_ok, throughput 9725376 bytes/s (~0.78x cap), unshaped throughput 90852985 bytes/s, negative-control speedup 2156370978/230829179 (~9.3x). shaped_link.assert_shaping PASS.

RTT SWEEP (host RTT asserted at every point; shaping confirmed to ~3.7s RTT; each query bounded by the 10s kad query_timeout, retries within a bounded outer window):
  20ms  RTT 53ms   find=Found/1 locate=Found/1  disc 0.65s  first-shot OK
  100ms RTT 267ms  find=Found/1 locate=Found/1  disc 3.6s   first-shot OK
  250ms RTT 733ms  find=Found/1 locate=Found/1  disc 8.5s   first-shot OK (near 10s edge)
  500ms RTT 1.70s  find=Found/2 locate=Found/1  disc 24s    first-shot MISSED (retry rescued)
  750ms RTT 2.69s  find=DeadlineExceeded/4      disc 40s    UNRESOLVED
  1000ms RTT 3.70s find=DeadlineExceeded/5      disc 51s    UNRESOLVED
FINDING (real): the 10s kad query_timeout starts missing a SINGLE one-shot discovery at 500ms one-way (~1s RTT) and is fully unusable (even with retries) by 750ms one-way (~1.5s RTT). Latency grows steeply super-linearly with RTT. GEO-satellite peers (~600ms one-way / ~1.2s RTT) fall in the single-shot danger zone; residential/WAN (20-250ms) are comfortable. Filed as TASK-210 (make discovery deadline / query_timeout configurable or raise it).

GATE (bounded, all green): build --locked; clippy -D warnings on example; main proof (shaping fired + kad-discovered + byte-identical, netns clean); RTT sweep; shaped_kad.py --self-test (10 mutations bitten); shaped_libp2p.py --self-test (6, untouched); check-discovery-no-shortcut.py --self-test; cargo test -p fabric-libp2p (80+ tests, 0 failed); cargo fmt --all --check; ruff check/format; just independence (check_shaping_out_of_daemon: 82 src files clean). netns/procs: 0 leaked; disk stable 65G.

GOTCHA (harness bug caught + fixed before reporting): the inner script's ping -W 2 (2s per-reply wait) timed out at >=1000ms delay because the ~2s+ RTT replies arrived after the 2s deadline -> a working shaped link mis-read as 'ping did not complete', which would have been a FALSE breaking point. Fixed by scaling -W to 2 + 4*delay_ms so the shaping witness survives multi-second RTT; re-ran to get the honest sweep above.

HONEST LIMITS (inherited from shaped_link): one host, shared kernel; models mean RTT + rate cap, NOT loss/jitter/cross-traffic/NAT-traversal cost/real-NIC effects. Removes the loopback UPPER bound on kad discovery; NOT a field measurement. The sweep's absolute latencies include real DHT record-propagation/retry wall-time, not pure query depth.
<!-- SECTION:NOTES:END -->
