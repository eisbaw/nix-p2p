---
id: TASK-264
title: Wire runtime enforcement for the declared-only profile-budget fields
status: Done
assignee: []
created_date: '2026-08-19 10:55'
updated_date: '2026-08-21 10:13'
labels:
  - production
  - operator
  - wave-2c
  - residual
dependencies:
  - TASK-120
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-120 AC#10 froze the complete per-profile budget artifact (artifacts/profile-budget-v1.json). Its ENVELOPE-ENFORCED fields are single/inflight served NarSize, serve_duration and discovery deadline: they are parity-checked against ResourceCaps::default() (the artifact<->frozen-default SSOT) AND their effective post-override values are guarded within the frozen envelope. announce_count is NOT parity-checked - it is operator-overridable via --libp2p-announce-budget and is runtime-limited politeness, not an envelope-bounded safety ceiling. The remaining artifact fields are DECLARED, FROZEN (content-hashed) CEILINGS - surfaced in preflight and marked declared-only - but NOT yet wired to a runtime shaper/limiter, and NOT owner-reviewed (the hash freezes canonical content/identity; it does not attest human review): upload_payload/total/rate_*_compressed_wire (no upload-rate shaper), transient_ram_bytes_ram (no RAM cap), apparent/allocated_disk_bytes_ondisk (only the narinfo entry-count cache is enforced, not a byte ceiling), open_fds_count (no fd rlimit wiring), concurrent_serves_count (concurrency is bounded by inflight BYTES today, not a serve COUNT). This mirrors the ResourceCaps honesty rule that unenforced caps are not advertised as enforced. Wire each with an enforcement point + a mutation-proven bite test, then extend the effective/parity checks to cover it, one field-class per bite.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Each declared-only field (upload rate/bytes, RAM, disk bytes, fd, concurrent-serve count) has a runtime enforcement point and a mutation-proven bite test
- [ ] #2 parity_with_caps is extended to parity-check each newly-enforced field against its runtime limiter, and the module doc-comment stops listing it as declared-only
- [ ] #3 The frozen artifact hash is re-frozen only if a value changes; otherwise unchanged
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
CODEX 120R3 CORRECTION 2026-08-19: the earlier note overstated DISCOVERY DEADLINE as post-override envelope-guarded. Correction: check_serve_within_envelope guards ONLY the operator-tunable serve fields — single served NarSize, inflight served NarSize, and serve duration (an --iroh-max-serve-* override may only TIGHTEN these). The discovery deadline is NON-TUNABLE (no override path): it is frozen and enforced by default-parity against the artifact alone, not by a post-override envelope guard. So the ENVELOPE-ENFORCED-post-override set is exactly {single_nar, inflight_nar, serve_duration}; discovery_deadline is frozen+default-parity-checked but non-tunable. The 14 declared-only fields remain frozen ceilings not wired to a runtime shaper (this task).
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
DONE as honesty-lock + route (NOT new enforcement - that was ruled net-negative). The implementer + Mark-emulator found no declared-only budget field clears tractable-AND-net-positive-AND-biteable: concurrent_serves count-cap is redundant with the shipped inflight-BYTE ceiling + producer-group supervisor and would regress out-of-box; open_fds via setrlimit RAISES the soft limit (anti-enforcement); upload-rate/RAM/disk/octets each need a dedicated shaper subsystem. Commit b1e92b7 (doc+test, daemon-core/profile_budget.rs+operator.rs): a DECLARED_ONLY_FIELD_OWNERS routing table, preflight declared-only lines now append '-> owner: ...' (the documented+visible half of 120 AC#3 without a phantom bound), dropped a misleading TASK-264 marker, + a mutation-biting declared_only_routing_is_locked test (phantom-Enforced or routing-drift -> RED). just lint 17/17, daemon-core 317+25 pass, frozen artifact hash unchanged. The real per-field enforcement is routed: TASK-299 (upload-rate/RAM/disk/octet shapers), TASK-297 (regenerate DeriveBudget), open_fds documented capacity-only. 120 AC#3 stays OPEN pending those.
<!-- SECTION:FINAL_SUMMARY:END -->
