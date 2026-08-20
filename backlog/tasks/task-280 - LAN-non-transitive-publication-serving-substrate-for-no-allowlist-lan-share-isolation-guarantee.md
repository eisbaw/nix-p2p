---
id: TASK-280
title: >-
  LAN-non-transitive publication + serving substrate for no-allowlist lan-share
  (isolation guarantee)
status: To Do
assignee: []
created_date: '2026-08-20 07:29'
labels:
  - irreversible
  - privacy
  - security
dependencies:
  - TASK-276
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Splits out the CRITICAL egress-transitivity defect codex found during TASK-276 (Mark-emulator: listener-INDEPENDENT, so PRE-EXISTING, fires identically under the pre-276 loopback default; 276 did not create it). A lan-share node feeds mDNS/Kad-returned/Identify addresses into Kademlia UNFILTERED, dials them, announces transitively (start_providing/put_record), and serves /nar over ANY established connection incl provider-ORIGINATED (libp2p bidirectional) -> a dual-homed same-v1 Kad node on the LAN also joined to public peers bridges the provider to the public DHT; a public peer fetches over the outbound connection, never traversing the private listener. Cannot fire by default (no default public swarm at HEAD) but falsifies the lan-share public-isolation GUARANTEE. This task holds that guarantee.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 No-allowlist lan-share path filters mDNS / Kad-returned / Identify addresses to LAN-only literals (reuse the TASK-276 FIX#1 positive-grammar classifier) BEFORE they enter Kademlia or the dial queue -> the node never dials a non-LAN peer address
- [ ] #2 /nar serving is restricted to connections of LAN PROVENANCE (peer observed remote address is loopback/link-local/private) -> an outbound connection to a non-LAN peer cannot be used to serve (closes the bidirectional-serve leg)
- [ ] #3 Evaluate a DISTINCT Kademlia protocol scope for lan-share (not the shared v1) so a lan-share node's DHT is structurally not the public DHT; decide in-task whether address-filtering + serve-provenance suffice or the scope split is required
- [ ] #4 Biting e2e (the codex exploit as a negative control): a dual-homed same-v1 bridge node on the LAN + a public peer; the public peer CANNOT learn the content key and CANNOT fetch. RED against today's HEAD (proves it bites), GREEN after the fix
<!-- AC:END -->
