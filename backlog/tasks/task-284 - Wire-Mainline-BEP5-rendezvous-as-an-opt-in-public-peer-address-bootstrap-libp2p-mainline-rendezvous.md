---
id: TASK-284
title: >-
  Wire Mainline (BEP5) rendezvous as an opt-in public peer-address bootstrap
  (--libp2p-mainline-rendezvous)
status: To Do
assignee: []
created_date: '2026-08-20 18:24'
labels:
  - bootstrap
  - discovery
dependencies:
  - TASK-258
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Promote the TASK-258 SPIKE (the mainline-rendezvous crate + mainline_spike_measure.py privacy measurement, currently a separate workspace member NOT depended on by any shipped binary) into a WIRED, shipped, opt-in public bootstrap behind --libp2p-mainline-rendezvous. This is the missing PUBLIC/internet zero-config entry point: mDNS (TASK-257) bootstraps the LAN pool, but at HEAD the DHT cannot self-bootstrap across the internet and there are no default nodes, so a node outside a single LAN has no way in. Mainline-as-RENDEZVOUS (one well-known infohash, get_peers for ADDRESSES only, content routing stays on our own kad) is the only bootstrap option needing no infrastructure we own or fund. Mirror the TASK-257 mDNS wiring shape. The privacy cost is measured and load-bearing (TASK-258): announce_peer lets anyone enumerate node MEMBERSHIP (not holdings) via get_peers on the infohash -- opt-in + disclosed, never default-on. MUST respect the TASK-280 LAN-public isolation guarantee: a lan-share node joining Mainline would bridge LAN content to the public swarm, so mainline-rendezvous is refused under --profile lan-share and permitted only for public-share/router.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 --libp2p-mainline-rendezvous on a shipped binary (daemon-libp2p at minimum) joins the Mainline DHT strictly as a CLIENT (no BEP5 adaptive server promotion), announces membership under ONE hardcoded well-known infohash, and get_peers-es it to learn peer ADDRESSES that feed the libp2p dial/address-book only. Default OFF; fresh-install behaviour unchanged.
- [ ] #2 Content discovery stays kad-exclusive: check-discovery-no-shortcut.py scan_rendezvous_wiring passes -- the mainline path feeds ADDRESS/bootstrap wiring only and derives NO infohash from any Nix content hash. The guard goes RED if a content-hash-keyed get_peers is wired (mutation-proven).
- [ ] #3 Isolation (TASK-280): a --profile lan-share node MUST NOT join Mainline -- it fails closed at startup if --libp2p-mainline-rendezvous is combined with lan-share; mainline-rendezvous is permitted only for public-share/router. Biting test reddens if the refusal is removed.
- [ ] #4 Privacy disclosure: startup prints the node-MEMBERSHIP enumeration cost in exactly those terms (membership, not holdings), and README + docs/status.md are updated to state the opt-in exposure. Consistent with the mDNS presence-disclosure pattern (TASK-275).
- [ ] #5 Client-only verification: the node is never promoted to a serving Mainline DHT node -- observable from the peer/capture side (serves no inbound get_peers). Reuse the TASK-258 mainline_spike_measure.py capture approach; re-derive counts from the raw pcap, fail-closed on an empty capture.
- [ ] #6 E2E across container network namespaces: a fresh node given ONLY --libp2p-mainline-rendezvous (no seeds, no explicit --libp2p-bootstrap) discovers a peer via Mainline, joins the swarm, and fetches a NAR byte-identical to the signed upstream with 0 upstream NAR egress on a hit and a clean upstream fallback on a miss. The Mainline crate is promoted into the shipped closure (was a non-shipped workspace member).
<!-- AC:END -->
