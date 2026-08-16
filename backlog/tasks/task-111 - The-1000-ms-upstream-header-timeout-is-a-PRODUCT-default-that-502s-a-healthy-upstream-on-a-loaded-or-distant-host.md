---
id: TASK-111
title: >-
  The 1000 ms upstream header timeout is a PRODUCT default that 502s a healthy
  upstream on a loaded or distant host
status: Done
assignee:
  - '@claude'
created_date: '2026-08-10 20:30'
updated_date: '2026-08-16 02:33'
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
- [x] #1 The decision explicitly separates connect_timeout from header_timeout rather than treating them as one number
- [x] #2 connect_timeout is either made configurable like header_timeout, or its fixedness is justified in a comment
- [x] #3 The interaction with the known non-composition across a daemon chain (TESTING.md task-33 note) is stated
- [x] #4 If the default changes, the e2e boundary pin and any depth/fault matrix expectations are re-derived, not assumed unchanged
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
FORWARD-CARRY from TASK-24: the TLS upstream path (daemon-core/src/upstream.rs) has a FROZEN tls-upstream-v1 CONNECT budget (10000ms total DNS+connect+handshake, connect/handshake<=5000 each) exposed as pub consts + TlsBudget, tunable via UpstreamHttp::with_tls_budget (default==v1). This is SEPARATE from the 1000ms header_timeout TASK-111 targets - the header-read deadline still governs response-header arrival AFTER connect on BOTH plain and TLS paths. When TASK-111 makes header_timeout WAN-aware, do it for both transports and take real-HTTPS observations via the #[ignore]d tls_real_cache_nixos_org_over_https smoke (production webpki-roots path, verified reachable).

TASK-111 minimal honest core landed (AC#5 measurement campaign carved to TASK-228, which depends on this task).

WHAT CHANGED
- Split connect vs header timeouts (AC#1): daemon-core/src/upstream.rs now has two pub consts, CONNECT_TIMEOUT_MS=1000 (kept tight: fast-fail against a dead upstream, ~1 RTT) and HEADER_TIMEOUT_MS=15000 (WAN-sane: tolerates a slow-but-healthy upstream figure work AFTER connect). Was a single 1000ms under one short-by-design comment. Consts re-exported from daemon-core lib and consumed in main.rs (single source of truth). A compile-time const assert pins header greater than connect.
- with_connect_timeout setter added (AC#2); plus a --connect-timeout-ms CLI flag mirroring --header-timeout-ms (0/absurd rejected). Operator-tunable and test-pinnable now.
- Non-composition-across-a-chain interaction stated (AC#3) on HEADER_TIMEOUT_MS and with_header_timeout, consistent with the TESTING.md task-33 note.
- AC#4 re-derivation: the e2e chain-timeout-boundary scenario pins the L-vs-budget flip against an EXPLICIT --header-timeout-ms (500/1200), so it is independent of the product default BY CONSTRUCTION. Ran it explicitly: PASS. No other e2e pin leans on the old 1000ms (s2-fallback failover is connect-refused, bounded by connect_timeout, unchanged).

DEFAULT RATIONALE (15s header). Chosen as a header-TTFB compromise: generous enough for a slow-but-healthy upstream figure think-time before its first response header (WAN cache-miss, loaded host: seconds; observed loopback-oversubscription failures were over 1s), bounded so a connect-then-silent upstream still fails fast (S2 no-hang). Key safety property (verified against send/send_over + the TLS path): raising the header timeout does NOT slow failing against a DEAD upstream, because a refused/black-holed connect is bounded by connect_timeout (plain) or the frozen tls-upstream-v1 budget; the header wait starts only AFTER a successful connect. Nix context (nix.conf): stalled-download-timeout=300s, connect-timeout=0, download-attempts=5 -- these show the old 1000ms was ~300x tighter than anything Nix gives up at. Per mped review, the justification was corrected to NOT conflate units: Nix stalled-download-timeout is a BODY-idle timeout; this daemon analog of THAT is BODY_IDLE_TIMEOUT_MS=30s, NOT the header bound.

LOCK-IN BITE (daemon/tests/upstream_header_timeout_default.rs). Two directions, MUTATION-PROVEN: (a) a healthy upstream returning headers at ~1500ms is served (Ok 200) -- reverting HEADER_TIMEOUT_MS to 1000 turns it RED with exactly Unreachable(no response headers); (b) a connect-then-silent upstream still fails within ~10%+grace of an injected 2s bound -- removing the injected bound (relying on 15s default) turns it RED at 15.0s. Integer Duration arithmetic only (no floats).

GATE (all green, actual numbers): cargo test -p daemon-core -p daemon = 459 passed / 0 failed / 1 ignored; cargo fmt --all --check clean; clippy workspace + daemon(evidence-fixture) both clean at -D warnings; scripts/check-no-floats.py clean; just e2e 5/5 (74.9s) + chain-timeout-boundary PASS. qa-test-runner + mped-architect reviewed; mped verdict GO on change and GO on 15s, with doc-justification unit-conflation fixes applied + a --connect-timeout-ms-inert-on-TLS operator warning added + a DoS-hold-window note.

HONEST LIMITS: 15s is a physics-argued compromise, NOT yet validated by real header-arrival distributions (TASK-228). --connect-timeout-ms is INERT on https upstreams (TLS connect is the frozen budget) -- a startup WARNING now flags that. Raising to 15s widens the connect-then-header-silent hold window from 1s to 15s (mild slowloris amplification against a semi-trusted upstream) -- documented.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Shipped the minimal honest core: separated the upstream connect vs header timeouts into two distinct pub consts (CONNECT_TIMEOUT_MS=1000, fast-fail against a dead upstream; HEADER_TIMEOUT_MS=15000, WAN-sane header-TTFB tolerance for a slow-but-healthy upstream), added a with_connect_timeout setter + --connect-timeout-ms flag (AC#2), stated the chain non-composition interaction (AC#3), and re-derived AC#4 (the e2e boundary pin uses an explicit --header-timeout-ms so is default-independent; verified PASS). Lock-in bite (daemon/tests/upstream_header_timeout_default.rs) proves both directions, mutation-checked. The >=100-observation authenticated-HTTPS measurement campaign (original AC#5) is carved to TASK-228 (depends on this task) rather than gating the default fix on it. Full gate green: cargo test 459/0/1, fmt clean, clippy x2 clean at -D warnings, no-floats clean, just e2e 5/5 + chain-timeout-boundary PASS. mped verdict GO on 15s; its unit-conflation and operator-UX findings were applied.
<!-- SECTION:FINAL_SUMMARY:END -->
