---
id: TASK-209
title: >-
  libp2p kad-DHT discovery over a SHAPED link (3-node bootstrap variant) — the
  discover-over-realistic-link extension of TASK-206
status: To Do
assignee: []
created_date: '2026-08-14 17:57'
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
