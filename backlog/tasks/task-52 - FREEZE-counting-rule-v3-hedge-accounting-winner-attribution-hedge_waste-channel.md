---
id: TASK-52
title: >-
  FREEZE: counting-rule v3 - hedge accounting (winner attribution + hedge_waste
  channel)
status: To Do
assignee: []
created_date: '2026-08-08 20:28'
updated_date: '2026-08-18 20:36'
labels:
  - irreversible
  - measurement
  - pilot-critical
  - counting-rule
dependencies:
  - TASK-9
  - TASK-62
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
qa+arch: net-upstream-egress-v2 is UNDEFINED for the hedge regime (marks the hedge-loser row UNRESOLVED; a hedge-loser partial is byte-indistinguishable from a truncated primary -> every hedge run is INVALID/fail-closed). So the hedge policy candidate CANNOT be measured. task-44 depends on fixing this. Define v3: attribute exactly ONE winning transfer per payload to payload egress; count hedge-LOSER bytes in a separate provenance-tagged hedge_waste channel (discriminated by request PROVENANCE, which the testproxy log must now carry - not by byte count). Extending the frozen counting rule is a deep-gate irreversible event. Ground: task-35 confirms hedge is the PRIMARY offload mechanism, so measuring it correctly is essential, not optional.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A run containing a hedge (winner + cancelled loser) is VALID; winner bytes -> payload egress, loser bytes -> hedge_waste, discriminated by request provenance in the testproxy log (bite: a truncated PRIMARY still INVALID; a hedge loser is NOT)
- [ ] #2 v3 is a version bump with rationale; existing v2 numbers remain comparable for the no-hedge regime (documented)
- [ ] #3 testproxy request log carries provenance (which fetch a byte belongs to) so hedge_waste is attributable, not guessed
- [ ] #4 The frozen schema uses exact unit-suffixed fields including upstream_cache_payload_bytes_compressed_wire, hedge_waste_upstream_bytes_compressed_wire, hedge_waste_peer_bytes_compressed_wire, peer_socket_total_bytes_compressed_wire and payload_bytes_uncompressed_nar; provider/requester socket witnesses and requester source attribution are independent, never derived from raw-fixture equality.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
## Forward-carried from task-42 (profiling harness)

THE v2 RULE HELD UP UNDER A REAL PEER HIT. `just profile` runs
`measure.classify_run` unchanged over a peers-ON arm and a peers-OFF arm; the
peer arm produced 10/10 VALID runs at exactly 0 payload wire bytes, i.e. v2's
zero-or-one rule admitted the offload as designed (offload fraction 1.0). So the
v1->v2 correction is now confirmed against real p2p traffic, not just reasoning.

WHAT v3 MUST CARRY, from what task-42 had to build around it:
1. UNITS IN THE SCHEMA, not in prose. The doc says 'compressed on-wire bytes,
   never NarSize', and the trap still recurred three times. profile_p2p makes it
   mechanical: every `*_bytes` key must end in `_ram`, `_ondisk`,
   `_uncompressed_nar` or `_compressed_wire`, and `unit_violations()` FAILS the
   run otherwise (proven by mutation). A hedge channel makes this worse, not
   better: the loser's bytes are WIRE bytes while a peer-served count is NarSize,
   and `hedge_waste` named plainly `_bytes` would invite exactly the sum that is
   forbidden. Name the channel `hedge_waste_bytes_compressed_wire`.
2. A CHECKED PRECONDITION beats a caveat. Where a comparison genuinely needs
   wire == NarSize, ASSERT `file_size == nar_size` from the manifest and refuse
   to run otherwise (profile_p2p's `assert_unit_coincidence`) rather than
   documenting that the reader should be careful.
3. PROVENANCE FOR THE PARTIAL-CROSSING DISCRIMINATOR. The v2 doc already flags
   that a hedge loser and a truncated primary are byte-for-byte indistinguishable
   under the current `bytes_sent < file_size` test. Nothing in task-42 resolves
   that; it stays your task, and the testproxy log must grow request provenance.
4. A ZERO-EGRESS RUN NEEDS AN INDEPENDENT WITNESS. v2 accepts a zero crossing
   when the CLIENT confirms delivery. task-42 adds a second, stronger witness -
   the holder's own iroh provider byte counter - and records
   `peer_serve_shortfall_runs` when it did not advance by the full workload. A
   peers-ON arm that quietly fell back to upstream is otherwise invisible: every
   run is 'valid', the egress is just... full. Consider making the holder-side
   witness part of v3 for any arm that claims a peer hit.

MEASURED CONTEXT for the hedge cost model: on this host the peer path is ~3.7x
SLOWER than the loopback cache (0.690 s vs 0.184 s realise) while saving 100% of
payload egress, and BOTH ends of a whole-NAR peer transfer resident-size the
payload (holder 248 MiB, fetcher 141 MiB, for a 110 MiB NAR - the blob store is
`MemStore`). A hedge therefore costs loser BYTES *and* concurrent MEMORY.

Deprioritized to Low in the Wave-2c cleanup (2026-08-14): libp2p-PRIMARY trunk proven (libp2p-kad discovery + store-supply + streamed NAR). Per PRD §634-691 (normative owner-direction authority) content discovery is libp2p-kad; iroh is an OPTIONAL transport only. This task belongs to a superseded-discovery / premature-tournament / far-future-BitTorrent / optional-comparator track. Fate confirmed by TASK-202 (owner-gated §693-743 reconcile). Reversible — not deleted; revisit after 202.

2026-08-18 superseding priority ruling: TASK-237 and the field pilot require hedge-aware net egress, so this is pilot-critical after TASK-62, not deferred optional comparator work. Freeze v3 before any hedge/value measurement; v2 remains the explicit no-hedge rule.

Downgraded 2026-08-18 (COMPASS F3): an IRREVERSIBLE freeze for a mechanism (hedging) that is not implemented, whose only consumer TASK-44 is Low/deferred. The TASK-237 edge is dropped. Re-raise when a hedge policy is actually on the near path -- freezing a counting rule before the mechanism exists is how a frozen surface gets burned.
<!-- SECTION:NOTES:END -->
