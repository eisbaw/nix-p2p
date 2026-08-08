---
id: TASK-36
title: Systematic hardening / library-based rewrite of hand-rolled HTTP framing
status: To Do
assignee: []
created_date: '2026-08-08 19:46'
labels:
  - hardening
dependencies: []
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Root-cause task (mark-emulator decision on task-13, 2026-08-08). The daemon layers manual Connection/Transfer-Encoding handling on top of hyper, and the testproxy hand-rolls a std-only HTTP parser; four codex passes on task-13 each found more HTTP framing edge-case defects (not converging). These are ROBUSTNESS bugs behind Nix hash gate (daemon is outside the trust base; a truncated/smuggled/mis-cached NAR -> failed build + retry, not a poisoned store path), and wave-1 fronts a TRUSTED upstream so malicious-upstream smuggling is out of scope - hence deferred here by design rather than patched round-by-round. Fix at the source: daemon TE/Connection on hyper (or a vetted framing lib); retire or replace the testproxy std-only parser (test fixture - lower priority than the product daemon).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 daemon: whitespace-separated Connection tokens (e.g. \x27X-Hop X-Other\x27) do not leak hop headers (fail-closed on any non-clean token, incl internal whitespace)
- [ ] #2 daemon: Transfer-Encoding empty members (\x27chunked,\x27) and any coding list other than a single chunked/identity fail closed
- [ ] #3 daemon: a response with both Transfer-Encoding and a conflicting Content-Length is handled per RFC (TE wins / reject), never truncate-and-serve
- [ ] #4 cache: legacy v1 cache entries written before the coding-check fix cannot be served as poisoned 200 (format-version bump or revalidation); persistent cache-hit/startup/correlation read paths honor MAX_NARINFO_BYTES (no unbounded std::fs::read)
- [ ] #5 cap-before-status: a large (>2MiB) non-200 upstream response is not turned into a spurious 502 by the size cap firing before status discrimination
- [ ] #6 testproxy: never caches a premature-EOF / short-body NAR as a complete 200 entry
<!-- AC:END -->
