---
id: TASK-264
title: Wire runtime enforcement for the declared-only profile-budget fields
status: To Do
assignee: []
created_date: '2026-08-19 10:55'
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
TASK-120 AC#10 froze the complete per-profile budget artifact (artifacts/profile-budget-v1.json). Its ENFORCED fields (single/inflight served NarSize, serve_duration, discovery deadline, announce count) are parity-checked against the running ResourceCaps and enforced by the peer-fabric budgets. The remaining artifact fields are DECLARED owner-reviewed CEILINGS that are surfaced (preflight/status) and fail-closed hashed, but NOT yet wired to a runtime shaper/limiter: upload_payload/total/rate_*_compressed_wire (no upload-rate shaper), transient_ram_bytes_ram (no RAM cap), apparent/allocated_disk_bytes_ondisk (only the narinfo entry-count cache is enforced, not a byte ceiling), open_fds_count (no fd rlimit wiring), concurrent_serves_count (concurrency is bounded by inflight BYTES today, not a serve COUNT). This mirrors the existing ResourceCaps honesty note that unenforced caps are deliberately not advertised as enforced. Wire each with an enforcement point + a bite test, then extend parity_with_caps to cover it, one field-class per bite.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Each declared-only field (upload rate/bytes, RAM, disk bytes, fd, concurrent-serve count) has a runtime enforcement point and a mutation-proven bite test
- [ ] #2 parity_with_caps is extended to parity-check each newly-enforced field against its runtime limiter, and the module doc-comment stops listing it as declared-only
- [ ] #3 The frozen artifact hash is re-frozen only if a value changes; otherwise unchanged
<!-- AC:END -->
