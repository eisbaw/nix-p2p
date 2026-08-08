---
id: TASK-37
title: 'Claim wire schema v1 (record format, versioned, transport-tagged)'
status: To Do
assignee: []
created_date: '2026-08-08 20:12'
labels:
  - irreversible
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The networks shared language and first wave-2 FROZEN surface. Design the claim record: {schema_version, key=NarHash, payload: enum WholeNar{blake3} (future CastoreRoot), holders:[NodeId], transport: enum Iroh (future BitTorrent), reserved fields for v2 signed-narinfo-relay + claim signatures}. A peer ignores payload/transport variants it does not understand (forward-compat). The DHT KEY DERIVATION is deliberately NOT frozen here (deferred to the wave-2b DHT spike) - this is the record format only. Irreversible: once two daemons exchange claims this cannot change without a version bump + network split.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Serde (de)serialization round-trips; a claim with an unknown payload/transport variant parses and is ignored, not an error (forward-compat test)
- [ ] #2 schema_version present and checked; a wrong-version claim is rejected cleanly (bite)
- [ ] #3 Reserved fields exist for signed-narinfo-relay and claim-signatures so v2 needs no wire break (documented, not implemented)
- [ ] #4 BitTorrent transport tag is representable (proves the schema admits a 2nd transport without a fork), even though only Iroh is implemented
<!-- AC:END -->
