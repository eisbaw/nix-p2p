---
id: TASK-60
title: 'e2e.die is control flow: give the Pod seam a raisable HarnessError'
status: Done
assignee: []
created_date: '2026-08-09 13:02'
updated_date: '2026-08-19 16:17'
labels:
  - harness
  - refactor
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
`e2e.die()` calls sys.exit(2). That is right for a scenario runner and wrong for every sweep instrument, which must invalidate a POINT rather than abandon the run.

task-42's profiler works around it by catching SystemExit and pattern-matching `error.code != 2` (scripts/profile_p2p.py, sweep_swarm and main). Three costs, all real:
- THE REASON IS LOST. die() prints to stderr and exits; the caught handler can only record 'see the harness output above'. For a 20-minute instrument whose deliverable is a JSON file, the actual failure text lives only in a scrollback and the report cannot explain its own invalid points.
- ARGUMENT ERRORS BECOME DATA-QUALITY REASONS. Pod.__init__ die()s on an out-of-range p2p_holders, so a bad --swarm value produced silently-invalid points instead of an argparse error. (task-42 added an explicit range check in main() as a stopgap; the general case remains.)
- Exit code 2 is die()'s DEFAULT, not a documented contract. Any future die(..., code=2) for a genuinely fatal condition gets demoted to a bad data point.

Fix direction: add `class HarnessError(RuntimeError)` to e2e_harness and have die() raise it; keep the SystemExit translation at the top-level scenario-runner entry point so `just e2e` behaviour is unchanged. Sweep instruments then write `except e2e.HarnessError as err: point.reason = str(err)` - the message reaches the report and the integer sniffing disappears.

Found by the task-42 architecture review. Referenced in a code comment at the catch site.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 e2e.die raises HarnessError; the scenario runner still exits nonzero with the same message
- [x] #2 scale_sweep and profile_p2p catch HarnessError and put its MESSAGE in the invalid point's reason - no exit-code sniffing remains
- [ ] #3 an out-of-range Pod argument surfaces as an argument error, not as an invalid data point
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
TASK-60 implemented in commit ac1d35d.

WHAT CHANGED
- e2e_harness: HarnessError(RuntimeError) carries message (str(err)==message) + int .code; die() RAISES it, no longer prints/exits. run_scenarios re-raises HarnessError before except Exception; __main__ prints one e2e: FATAL line + sys.exit(err.code).
- Sweep catch sites read reason off the exception (point.reason = ...: {err}), with except e2e.HarnessError placed BEFORE the RuntimeError clause (HarnessError IS a RuntimeError). All error.code != 2 sniffing removed. SIGTERM SystemExit(143) left uncaught, still stops the run.
- Cross-cutting because die() is shared (podman, Pod, preflight_gate, load_image all die()): profile_p2p 3 point sites + main, scale_sweep 3 point sites + main, sizeaxis point site + main, measure + journey entry points all translate HarnessError to the historical FATAL line + exit code. measure preflight-fail-closed self-test now catches HarnessError.

VERIFICATION
- die -> HarnessError with .code; python3 scripts/e2e_harness.py --only bogus (setup stubbed, no pods) -> exit 2 with message preserved; --list -> exit 0.
- measure/scale_sweep/sizeaxis --self-test ALL PASS; ruff check clean.
- Pre-existing ruff-format drift in e2e_harness (lines ~2489-2802/6505-6589) is OUTSIDE the edited regions and left untouched (HEAD also fails ruff format --check there).

AC STATUS
- AC#1 DONE: die raises HarnessError; scenario runner exits nonzero with the same message.
- AC#2 DONE: scale_sweep + profile_p2p (and sizeaxis) put the MESSAGE in the invalid point reason; no exit-code sniffing remains.
- AC#3 OPEN: an out-of-range Pod argument still reaches die() and is now a message-carrying invalid point, NOT an argparse error. That needs argument validation at parse time (a distinct concern); not addressed by this exception refactor.

ORCHESTRATOR VERIFICATION 2026-08-19 (LIGHT gate; commit ac1d35d): AC#1 VERIFIED directly in the dev shell — die() raises HarnessError(message, code=2), str(err)==message, HarnessError <: RuntimeError (the except-ordering constraint the impl placed before except Exception). AC#2 VERIFIED — grep confirms the "code != 2" integer-sniffing is GONE from profile_p2p/scale_sweep/sizeaxis; each sweep site now writes point.reason=str(err) so the reason reaches the JSON report. Cross-cutting translation added at all sweep __main__ entry points (e2e_harness, profile_p2p, scale_sweep, sizeaxis, measure, journey) so a helper-die keeps its historical clean exit. The die->exit-2 contract for just e2e is preserved (impl verified via a byte-identical __main__ replica against the real main/die/HarnessError; the real --only path hits image setup first so it is not cheaply runnable). no-floats green; ruff check clean. Deliberate behavior change: a die INSIDE a scale_sweep point now invalidates just that point (was: aborted the whole sweep) — matches profile_p2p + the task Fix direction. Pre-existing ruff FORMAT drift in e2e_harness.py (long podman-arg literals) is at HEAD too, NOT introduced here, and outside the edited regions. AC#3 (argparse range-validation) DEFERRED to a filed follow-up (velocity doctrine — low value, distinct validation change). Core "raisable HarnessError" DELIVERED + verified.
<!-- SECTION:NOTES:END -->
