---
id: TASK-218
title: >-
  fabric-libp2p: consumer cannot resolve a NAT'd provider's /p2p-circuit
  dial-address via kad peer-routing (TASK-207 residual)
status: To Do
assignee: []
created_date: '2026-08-15 12:35'
updated_date: '2026-08-15 14:27'
labels:
  - libp2p
  - fabric
  - nat
  - hardening
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Real-NAT VM harness (TASK-207, nixos/nat-vm-test.nix) proved: a NAT'd provider obtains a circuit-v2 relay reservation over a real NAT (ReservationReqAccepted), a direct dial to its private address is blocked (negative control), and the consumer DISCOVERS the provider record via kad get_providers. BUT the end-to-end NAR fetch does not complete: the consumer's node-locator gets a 'kad peer-routing miss' resolving the provider's /p2p-circuit dial-address, even though the provider self-advertises that address via --libp2p-external-address and holds a live reservation. Root area: fabric-libp2p/src/locator.rs locate_via_dht -> swarm.rs locate_peer/get_closest_peers + the identify->kad.add_address path (swarm.rs ~1150) for circuit multiaddrs. The fabric API-level proof (fabric-libp2p/tests/nat_traversal.rs) shows the relay DATA path is load-bearing when the circuit address is supplied directly (add_address+dial), so the gap is specifically the DHT-side propagation/resolution of a /p2p-circuit address to a consumer that only did kad discovery (no injection). Fixing this closes TASK-168 AC#1 (real-NAT relay fetch) and flips the RESIDUAL subtest in nat-vm-test.nix to a byte-identical relay-carried fetch.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A consumer that discovers a NAT'd provider via kad get_providers resolves the provider's /p2p-circuit dial-address via kad peer-routing (no --libp2p-provider-addr injection) and fetches a NAR byte-identical THROUGH the relay, proven by flipping the RESIDUAL subtest in nixos/nat-vm-test.nix to a positive relay-carried fetch
- [ ] #2 The fix does not weaken the no-injection oracle (check-discovery-no-shortcut.py) nor the kad-exclusive discovery guarantee
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
TASK-207 hardening (2026-08-15): 218 scope now INCLUDES delivering the LOAD-BEARING B2 reachability bite that 207 could only defer. nat-vm-test.nix ships SUPPORTING structural guards only (the real ReservationReqAccepted positive proof; zboot relay-server DISABLED so no alternative relay path exists; the B1 direct-path block; provider MainPID liveness across a relay stop; per-VM journal-cursor discipline). It does NOT prove the relay is load-bearing: a provider-side no-reservation-after-relay-stop bite is TAUTOLOGICAL because libp2p-relay 0.18 reservation renewal is connection-scoped, so a running provider silently drops its lease on relay disconnect and emits nothing gateable (measured: zero relay-client journal activity for 120s post-stop, even at libp2p_relay=debug). When 218 unblocks the /p2p-circuit byte-fetch, ADD the consumer-side load-bearing bite to nat-vm-test.nix: POSITIVE CONTROL = a FRESH consumer fetches the store path byte-identical THROUGH the relay; BITE = with the relay stopped, a FRESH unwarmed consumer dial/fetch of the same path FAILS within a bounded timeout, while provider MainPID is unchanged and the provider sole reservation relay is the relay. That fresh-dial-fails bite is the real B2 load-bearing proof.
<!-- SECTION:NOTES:END -->
