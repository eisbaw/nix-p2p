---
id: TASK-11
title: 'Long-chain test: client -> daemon x3 -> testproxy -> mock'
status: Done
assignee: []
created_date: '2026-08-07 21:56'
updated_date: '2026-08-08 16:50'
labels: []
dependencies:
  - TASK-5
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
PRD round-5 requirement: proxy composition must survive depth. Chain at least three product daemons; assert S1 byte identity, no header/metadata mangling (content-type, content-length vs chunked, compression fields untouched), bounded added latency (timeouts must not multiply per hop), and clean fallback when a middle daemon is killed.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Depth-3 chain green: S1 + exact per-hop request counts; scenario exercises BOTH compression encodings (none + xz) and 404 fidelity at depth
- [x] #2 Timeout invariant: client-visible failure time at depth 3 approximately equals depth 1 (must NOT scale with depth); per-hop added-latency bound fixed BEFORE implementation at 50ms/hop local (changed only by a recorded review note, never post-hoc to fit results)
- [x] #3 Kill middle daemon mid-run: client build still succeeds; failure mode visible in logs
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
IMPLEMENTED (task-11). Pod gains daemon_chain=N: N product daemons on in-pod ports 8082,8083,... (host ports 18082,18083,...), each --upstream the NEXT hop, last --upstream testproxy. Client enters at daemon-1 (chain head, the only preferred substituter); each daemon's only upstream is the next hop, so the testproxy receiving a request at all proves the whole chain carried it (boundary oracle for no-hop-skipped). Single-daemon with_daemon=True path kept byte-identical (role "daemon"); chain uses roles daemon-1..daemon-N. Mutually exclusive; ceiling MAX_DAEMON_CHAIN=32 (fail-fast).

5 scenarios, all green in full just e2e (all 20 scenarios PASS):
- chain-s1-and-counts (13/13): S1 byte identity at depth-3 for app(xz)+lib(none) one closure = BOTH compression encodings; boundary counts (testproxy exactly 1 upstream+1 served per payload, no multiplication); per-hop corroboration (each daemon served each NAR once).
- chain-corrupt-bite (5/5): corrupt-NAR at origin FAILS build through 3 hops with hash-mismatch (S1 bite AT DEPTH).
- chain-absent-404 (5/5): absent path 404s through 3 hops (never 502), present sibling still 200, build proceeds.
- chain-timeout-invariant (9/9): per-hop added latency 0.09ms << 50ms bound (FIXED BEFORE IMPL, change only by recorded note); fixed 300ms upstream delay incurred ONCE not per hop (shallow 302ms ~= deep 302.5ms, multiplying would be ~900ms); BITE: predicate flags synthetic per-hop-multiplied sample.
- chain-kill-middle-daemon (11/11): kill daemon-2 mid-NAR (bytes-observed), client recovers via direct testproxy fallback, byte oracle holds, proxy truncated-transfer event visible; skip-bite control: daemon-2 still dead + NO fallback => build FAILS (middle hop load-bearing).

GOTCHAS:
- REGRESSION I introduced+fixed: adding *, role=/deadline_s= keyword-only to _daemon_action_at_bytes broke _kill_daemon_at_bytes/_stall_daemon_at_bytes (they passed deadline_s positionally) -> crash-kill-mid-nar + crash-sigstop-stall TypeError. Fixed: wrappers pass deadline_s= by keyword. Lesson: check ALL callers when adding keyword-only barrier.
- S1 oracle only reads path-info for the paths NAMED as realise targets; app alone pulls lib via closure but lib narhash was None until I named both app+lib as targets.

FINDING (filed TASK-33, not papered over): daemon header_timeout (upstream.rs, 1000ms) is a FIXED PER-HOP budget that does NOT compose across hops. At latency_narinfo_ms=1000 (==timeout) the 1-hop entry returns 200 but the 3-hop entry returns 502 (outer hops time out; the fixed delay + serial per-hop setup exceeds their fixed budget). NOT multiplication (delay incurred once) - a depth-composition ceiling. AC#2 oracle deliberately injects 300ms (<<timeout) to measure the property it names.

LIMIT (honest): keep-alive DESYNC guard at EACH middle hop (task-7 carry) NOT implemented here - out of the 3 ACs; depth-1 desync still covered by crash-keepalive-desync. Forward-carried to task-13.

FORWARD-CARRY task-13 (fault x depth matrix): reuse Pod(daemon_chain=N), _daemon_action_at_bytes(role="daemon-i"), _daemon_reachable_at(i), daemon_host_port(i). Add per-hop keep-alive desync + pin the TASK-33 502-at-depth boundary. FORWARD-CARRY task-15 (p2p multi-hop): daemon chaining validates transparent multi-hop passthrough + the header_timeout-does-not-compose finding is directly relevant to relay/multi-hop timeout budgeting.
<!-- SECTION:NOTES:END -->
