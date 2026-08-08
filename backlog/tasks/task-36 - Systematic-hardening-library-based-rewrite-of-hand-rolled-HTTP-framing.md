---
id: TASK-36
title: Systematic hardening / library-based rewrite of hand-rolled HTTP framing
status: To Do
assignee: []
created_date: '2026-08-08 19:46'
updated_date: '2026-08-08 19:55'
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

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Scope correction (task-13 final round, commit 1c317aa): the 'chunked + Content-Length conflict' item is ALREADY FIXED in task-13 - a response carrying both Transfer-Encoding and Content-Length now FAILS CLOSED (502) via source::has_ambiguous_framing (serving + cache gates), pinned by daemon test transfer_encoding_with_conflicting_content_length_fails_closed. task-36 therefore owns only the STILL-open framing edge cases: whitespace-in-Connection-token, empty TE members (e.g. 'chunked,'), legacy v1 poisoned cache entries / cache-format bump, unbounded std::fs::read on the cache-hit path, and cap-before-status 502. Also fixed in task-13 (not task-36): premature-EOF NAR never committed to the testproxy cache, and error/malformed 200s never cached by the narinfo cache.
<!-- SECTION:NOTES:END -->
