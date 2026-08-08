---
id: TASK-6
title: 'JOURNEY J1: operator substitutes, then loses the daemon'
status: Done
assignee: []
created_date: '2026-08-07 21:55'
updated_date: '2026-08-08 11:51'
labels:
  - journey
dependencies:
  - TASK-5
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
First interspersed journey (every ~5 tasks). Act as a fresh operator, not a test: start daemon with default config, run a real nix build through the chain, watch logs tell a comprehensible story, then stop the daemon and build again - fallback must feel invisible. File every rough edge found as a new backlog task; journey findings are feature work, not polish.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Journey is executable, not prose: just journey runs the operator steps; log comprehensibility is asserted (one line per substitution: path, source, bytes, duration - grep-asserted, nonzero exit on missing events)
- [x] #2 S2 experienced AND asserted: daemon stopped mid-journey, subsequent build succeeds via fallback (request counts prove fallback served)
- [x] #3 Friction points filed as backlog tasks, or 'none found' emitted by the journey run itself (not hand-written prose)
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
DELIVERED: just journey (scripts/journey.py) reuses the task-5 Pod seam (no second harness). Operator narrative: (step1) start origin<-testproxy<-daemon with default ports, point nix at the daemon, realise all 4 fixture payloads; (step2) Pod.kill('daemon') then realise again with daemon+fallback substituters. 14/14 oracles pass; e2e + build/lint/test/fmt + nix build .#daemon all green.

HEADLINE FINDING (fixed inline): the daemon was SILENT on the operator path - it printed only its startup banner, never a per-substitution line. AC#1 could not have passed. Added daemon/src/server.rs::log_substitution + a presentation-only App.upstream_label field (threaded via main.rs + 4 test sites): one line per served NAR -> 'daemon: substituted path=/nar/<token> source=<upstream> bytes=<n|unknown> duration_ms=<d>'. Logged at the integration site (handle), not inside the source module, so the server layer stays trait-only.

ORACLES (all bite):
 - AC#1: grep SUBST_RE over podman logs; asserts >=1 line (0 => nonzero exit; was the pre-change reality), exactly one line per payload (total==unique==4, so double-logging bites), every line bytes>0, source==the daemon's real upstream. Exit-code path unit-checked (empty->1, fail->1, pass->0).
 - AC#2: after kill, build via ctx.substituter_daemon_and_fallback() exits 0 AND testproxy received-NAR count==4 (fallback truly served, not exit 0 alone) AND per-payload NarHash byte oracle on the fallback path.
 - AC#3: FRICTION manifest emitted by the run: TASK-29 (detected via runtime probe - no 'narinfo disk cache at' line by default; auto-clears when 29 default-wires it) and TASK-31 (declared limitation, filed).

GOTCHAS / LIMITS (be blunt):
 - The daemon log's bytes=Content-Length (COMPRESSED wire size), NOT the signed NarSize (uncompressed) - mixing them was a latent unit bug caught in review; absent Content-Length now logs bytes=unknown, never a guessed number. duration=time-to-upstream-HEADERS, not full body drain (body streams verbatim after the line). Both filed as TASK-31 for wave-2 full-drain accounting; TASK-9 measurement must treat the daemon log as narration and the testproxy stats/log as ground truth.
 - Default operator experience is still thin: --upstream defaults to http://127.0.0.1:8081 (a dev port), no narinfo cache by default (TASK-29), no TLS upstream (TASK-24). J1 exercises the local chain, not a real cache.fixtures.org.
 - Shared helper e2e.daemon_reachable() now backs both the s2 scenario and the journey's 'daemon is really gone' probe (SSOT); new Pod.logs(role) accessor reads container stdout host-side (reused by task-7/9).

FILED: TASK-31 (accurate full-drain byte/duration accounting). Forward-carried notes to TASK-7 (crash-visible behavior + logs accessor), TASK-9 (log semantics for measurement), TASK-29 (journey friction detector auto-clears on default-wiring).
<!-- SECTION:NOTES:END -->
