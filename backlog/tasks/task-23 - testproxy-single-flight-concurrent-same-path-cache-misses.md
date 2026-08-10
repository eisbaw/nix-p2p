---
id: TASK-23
title: 'testproxy: single-flight concurrent same-path cache misses'
status: To Do
assignee: []
created_date: '2026-08-08 07:31'
updated_date: '2026-08-10 22:36'
labels:
  - testproxy
  - follow-up
  - wave-hardening
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
task-2's cache is integrity-safe under concurrency (atomic tmp+rename; every reader sees a complete file - proven by concurrent_same_path_requests_are_never_torn). But N concurrent MISSES for the same cold path each fetch upstream independently and each rename over the final path (last wins). Correct, but redundant upstream work. A single-flight/coalescing layer would collapse them to one fetch. Deferred as hardening (contract: exhaustive edge coverage is task-13/14's job). Also note: a client on a Content-Length response returns before the proxy's post-transfer fsync+rename commits, so an immediately-following request can still miss - acceptable for a fixture; coalescing would also narrow this.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 concurrent misses for one cold path cause exactly one upstream fetch
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
task-13 triage: KEEP for wave-2 - testproxy single-flight coalescing is a redundant-work OPTIMISATION; integrity already holds under concurrency (atomic rename). Not a correctness finding on the stabilized surfaces; distinct concern.
<!-- SECTION:NOTES:END -->
