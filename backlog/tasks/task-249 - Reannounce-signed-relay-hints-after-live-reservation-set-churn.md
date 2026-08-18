---
id: TASK-249
title: Reannounce signed relay hints after live reservation-set churn
status: To Do
assignee: []
created_date: '2026-08-18 06:35'
updated_date: '2026-08-18 20:36'
labels:
  - libp2p
  - nat
  - hardening
  - pilot-readiness
  - operator-ux
dependencies:
  - TASK-120
  - TASK-219
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
After TASK-219, refresh signed relay hints when the live accepted reservation set changes, without turning a large holding set into an announcement storm. The provider schedules bounded durable latest-generation work under the authoritative TASK-120 profile announcement count/wire/rate budgets. Serving remains available when refresh work is delayed or exhausted; status/preflight expose stale generation, queue pressure, budget use, and corrective action. Preserve no-address-injection, no content withdrawal, sequence monotonicity, privacy, and fail-closed hint bounds.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Detect a change in the accepted /p2p-circuit listener identity set from live swarm events; configured, attempted, bootstrap, and unaccepted relays never count.
- [ ] #2 An R2-to-R3 integration test keeps the same provider/content, gives the consumer neither relay address out of band, resolves the newer signed R3 identity through raw kad, and fetches exact bytes through R3.
- [ ] #3 Biting controls prove stale R2-only records fail after R2 is severed, duplicate/no-op events do not create reannounce storms, at-most-two hint bounds remain enforced, and restart preserves sequence monotonicity.
- [ ] #4 Reservation changes enqueue only a bounded durable latest relay-generation marker plus a bounded cursor/work window, not one unbounded item per held claim. Repeated churn coalesces to the newest generation; restart resumes monotonically, and checked queue/work ceilings prevent memory/disk growth.
- [ ] #5 Each claim refresh is admitted by the selected TASK-120 profile announcement count, signed-wire-octet, and rate-window budgets. Budget exhaustion defers work with a stable reason and operator-visible queue/staleness metrics; it never bypasses limits, withdraws content, blocks serving, or silently drops the latest generation.
- [ ] #6 Rate/volume and work accounting have biting large-holdings/churn tests: an unbounded reannounce-all loop, per-event duplicate queue, missing coalescing, or hidden exhaustion fails while a bounded R2-to-R3 refresh eventually converges after budget becomes available.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Downgraded 2026-08-18 (COMPASS §4): pilot-readiness for a public RESIDENTIAL swarm; a LAN/org pool has no relay churn. Re-raise when the public-network pilot is actually next.
<!-- SECTION:NOTES:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Focused tests, workspace build/lint/test, mandatory architecture and QA review, and just e2e pass.
<!-- DOD:END -->
