---
id: TASK-111
title: >-
  The 1000 ms upstream header timeout is a PRODUCT default that 502s a healthy
  upstream on a loaded or distant host
status: To Do
assignee: []
created_date: '2026-08-10 20:30'
updated_date: '2026-08-13 12:10'
labels: []
dependencies:
  - TASK-33
  - TASK-109
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
task-109 raised the harness's upstream header timeout to 10 s so the daemon integration tests stop measuring the host's scheduling latency. It deliberately did NOT touch the PRODUCT default, because that is a separate question and changing it under cover of a flake fix would have hidden a real decision.

THE QUESTION. daemon/src/upstream.rs sets connect_timeout and header_timeout to 1000 ms, documented as 'short by design (AC#6): a down upstream fails clean, fast'. That is a defensible choice against a DOWN upstream. It is a different claim against a SLOW one. A healthy upstream that needs more than a second to return response headers is indistinguishable, to this daemon, from a dead one - and it answers 502.

WHY IT IS NOT HYPOTHETICAL. Under 2x CPU oversubscription on loopback - no network at all - the harness daemon was diagnosed as 502ing a healthy in-process upstream on exactly this deadline. A real user on a WAN link to cache.nixos.org, on a laptop compiling in another terminal, is in a strictly harder position than that loopback case.

WHAT TO DECIDE (not to pre-judge here):
  1. Is 1000 ms right for the connect phase, the header phase, or neither? They are different physics: a TCP connect on a reachable host is one RTT, while header latency includes the upstream's own work (a cache miss upstream can be slow while perfectly healthy).
  2. connect_timeout currently has NO setter, unlike header_timeout's with_header_timeout. If it stays fixed at 1 s it cannot be tuned by an operator or pinned by a test.
  3. What does Nix itself do? Matching the substituter's own tolerances is the relevant benchmark, since a 502 from us sends Nix to the next substituter.
  4. Is a 502 even the right answer for a timeout, versus a retry or a pass-through-with-longer-deadline?

EVIDENCE TO GATHER FIRST - do not change the constant without it: measure real header latency against a real upstream at realistic RTT (task-33/task-35 already own real-upstream re-measurement), and characterise the 502 rate as a function of load. TESTING.md already records that this deadline does NOT compose across a daemon chain, so any change interacts with the depth story.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The decision explicitly separates connect_timeout from header_timeout rather than treating them as one number
- [ ] #2 connect_timeout is either made configurable like header_timeout, or its fixedness is justified in a comment
- [ ] #3 The interaction with the known non-composition across a daemon chain (TESTING.md task-33 note) is stated
- [ ] #4 If the default changes, the e2e boundary pin and any depth/fault matrix expectations are re-derived, not assumed unchanged
- [ ] #5 At least 100 authenticated-HTTPS observations in each idle, loaded and WAN/RTT profile report connect/header distributions; chosen numeric defaults are recorded, replay yields zero timeout-induced 502s for those healthy observations, and a response delayed beyond the configured bound fails within 10% of that bound.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
FORWARD-CARRY from TASK-24: the TLS upstream path (daemon-core/src/upstream.rs) has a FROZEN tls-upstream-v1 CONNECT budget (10000ms total DNS+connect+handshake, connect/handshake<=5000 each) exposed as pub consts + TlsBudget, tunable via UpstreamHttp::with_tls_budget (default==v1). This is SEPARATE from the 1000ms header_timeout TASK-111 targets - the header-read deadline still governs response-header arrival AFTER connect on BOTH plain and TLS paths. When TASK-111 makes header_timeout WAN-aware, do it for both transports and take real-HTTPS observations via the #[ignore]d tls_real_cache_nixos_org_over_https smoke (production webpki-roots path, verified reachable).
<!-- SECTION:NOTES:END -->
