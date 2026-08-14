---
id: TASK-206
title: >-
  libp2p connectivity credible across REAL uplinks/RTT (shaped/multi-host swarm
  proof) — the (b) residual
status: Done
assignee: []
created_date: '2026-08-14 16:46'
updated_date: '2026-08-14 17:57'
labels:
  - connectivity
  - measurement
  - libp2p
  - credibility
dependencies:
  - TASK-103
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
COMPASS 2026-08-14 credibility gap. The decentralized-DISCOVERY claim is now credibly proven on a genuine routed topology (TASK-179 netns, minimal-pair control). But 'robust CONNECTIVITY works' has TWO honest residuals: (a) zero NAT — TASK-168 closes it (hole-punch/relay/AutoNAT); (b) single physical host + UNSHAPED routing — every connectivity proof runs on one host with no real RTT/loss/asymmetric home-uplink conditions, so the fetch-over-a-realistic-link half is not shown for the libp2p-primary path the way TASK-94/99's shaped links showed it for compression. TASK-80 exists but is iroh/BitTorrent-tournament-framed + parked, so it does NOT cover this. SCOPE: prove a libp2p peer fetch (discover->fetch->serve byte-identical) over a SHAPED link (reuse TASK-70's shaped-link primitive: netns+veth+tc-netem, RTT + bandwidth cap, host-side asserted with a negative control) and/or a genuine multi-host swarm, so the connectivity claim is earned under real link conditions, not just unshaped one-host routing. Complements TASK-168 (NAT) — 168 is 'can they connect at all behind NAT', this is 'does the connection perform honestly under real RTT/bandwidth'. Do after 168 (or interleave). Owner steer: robust connectivity is a basics-first priority.
<!-- SECTION:DESCRIPTION:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
TASK-206 DONE (spike feasible -> full proof). Shaped-libp2p connectivity proof: real libp2p discover->fetch->serve between two swarm nodes, PROVIDER in ns A + CONSUMER in ns B (nsenter), traffic across a tc-netem-shaped veth pair (real RTT + bandwidth cap). Reuses the TASK-70 netns/veth/tc substrate structure verbatim and the proven shaped_link.assert_shaping oracle.

INTEGRATION APPROACH (env-frontier, records the how): PROCESS-level netns via nsenter (NOT thread-level setns) sidesteps the tokio-thread-migration netns hazard entirely - each libp2p node process (incl. its runtime threads) lives wholly in one netns, so all its sockets bind there. Provider binds /ip4/10.99.0.1/tcp/9099 in ns A; fetcher runs 'nsenter -t <child-pid> -n shaped_probe fetch' in ns B and dials 10.99.0.1 by multiaddr (the proven direct_fetch idiom: add_address + dial + fetch_nar_streaming over /nar/3). Provider writes its PeerId to a file the harness polls (readiness pattern from shaped_link_inner.sh). NAR is deterministic INCOMPRESSIBLE (splitmix64) so zstd cannot shrink the wire volume and the cap is observable in fetch throughput.

MEASURED (nar_seed=20206, 40 MiB NAR, delay 20ms, cap 100mbit; stable across 3 runs):
 shaped   : RTT 48111000 ns (~=2*20ms), throughput 9471222 bytes/s (~75.8 mbit, 0.76x cap), byte_identical + blake3_ok
 unshaped : RTT 44000 ns, throughput 72923263 bytes/s (~583 mbit), byte_identical + blake3_ok
 negative-control speedup shaped/unshaped elapsed = 2214235913/287583401 (~7.7x). Oracle PASS.
No-float rule: RTT integer ns, throughput integer bytes/sec, speedup exact Fraction; floats only inside the proven assert_shaping gate.

FILES: fabric-libp2p/examples/shaped_probe.rs (provide/fetch probe - EXAMPLE not src/, so check_shaping_out_of_daemon stays green), scripts/shaped_libp2p_inner.sh (netns/veth/tc + launches the two nodes), scripts/shaped_libp2p.py (2-arm orchestrator + reuses shaped_link oracle + --self-test), Justfile 'shaped-libp2p' recipe.

GATE (bounded): example builds; proof shows shaping fired + byte-identical (3 stable runs); shaped_link.py --self-test green; shaped_libp2p.py --self-test green (6 mutations bitten); cargo test -p fabric-libp2p green (nar_transport two-node transport unchanged); cargo fmt --check green; clippy -D warnings green on example; ruff check/format green; just independence + check_shaping_out_of_daemon green. netns/procs: 0 leaked, disk stable 66G avail.

HONEST LIMITS (inherited from shaped_link): one host, shared kernel; models mean RTT + rate cap, NOT loss/jitter/cross-traffic/NAT-traversal-cost/real-NIC effects. Removes the loopback UPPER bound on the libp2p fetch; NOT a field measurement. Discovery-over-shaped-link uses the direct-multiaddr dial (same serve_stream byte path); a 3-node kad-DHT-over-shaped-link variant (bootstrap in ns A) is the natural extension and is what TASK-198 also needs.
<!-- SECTION:NOTES:END -->
