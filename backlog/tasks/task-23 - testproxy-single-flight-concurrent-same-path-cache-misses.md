---
id: TASK-23
title: 'testproxy: single-flight concurrent same-path cache misses'
status: Done
assignee:
  - '@claude'
created_date: '2026-08-08 07:31'
updated_date: '2026-08-18 21:17'
labels:
  - testproxy
  - follow-up
  - wave-hardening
dependencies: []
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
task-2's cache is integrity-safe under concurrency (atomic tmp+rename; every reader sees a complete file - proven by concurrent_same_path_requests_are_never_torn). But N concurrent MISSES for the same cold path each fetch upstream independently and each rename over the final path (last wins). Correct, but redundant upstream work. A single-flight/coalescing layer would collapse them to one fetch. Deferred as hardening (contract: exhaustive edge coverage is task-13/14's job). Also note: a client on a Content-Length response returns before the proxy's post-transfer fsync+rename commits, so an immediately-following request can still miss - acceptable for a fixture; coalescing would also narrow this.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 concurrent misses for one cold path cause exactly one upstream fetch
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
task-13 triage: KEEP for wave-2 - testproxy single-flight coalescing is a redundant-work OPTIMISATION; integrity already holds under concurrency (atomic rename). Not a correctness finding on the stabilized surfaces; distinct concern.

Downgraded 2026-08-18 (COMPASS §4): an optimisation of the TEST FIXTURE. Integrity already holds; zero user value.

TASK-23 implemented: per-path single-flight coalescer in testproxy/src/proxy.rs (SingleFlight = Mutex<HashMap<PathBuf, Arc<Flight>>> + Condvar; leader/waiter Lease; RAII LeaseGuard released AFTER commit). First same-path miss leads the one upstream fetch; concurrent same-path misses wait then serve the committed file as a hit -> exactly one fetch for N concurrent same-path misses. Keyed by resolved disk path so different paths never block each other. Egress untouched: leader and waiter both run the normal serve path, so fault injection (corrupt/truncate/throttle) still fires per-request and the cache only ever holds upstream-correct bytes (AC#3 intact). in_flight COUNTER semantics untouched (separate field). Bites in testproxy/tests/single_flight.rs (gated in-memory origin, deterministic): (1) exactly-one-fetch, (2) different-paths-independent, (4) fault-reaches-every-waiter, (5) failure-path bounded/no-false-success; bite 3 = pre-existing concurrent_same_path_requests_are_never_torn still green. Each mutation-proven red. Known limit (mped review): same-path waiters block on the single leader with no independent deadline, bounded by the leader upstream 60s idle read timeout; a slow-drip upstream can extend that across the herd. Acceptable for a localhost fixture.

DONE (LIGHT scoped gate). Commit bbd5083. Per-path single-flight coalescer: exactly ONE upstream fetch for N concurrent same-path misses (leader/waiter + Condvar + RAII lease, keyed by disk path); egress/fault-injection untouched; failed-leader retry bounded. 5 mutation-proven bites incl fault-reaches-every-coalesced-waiter (uncatchable by the single-request test) + failure-path. mped concurrency-reviewed (no deadlock/lost-wakeup/livelock). Scoped gate (testproxy only).
<!-- SECTION:NOTES:END -->
