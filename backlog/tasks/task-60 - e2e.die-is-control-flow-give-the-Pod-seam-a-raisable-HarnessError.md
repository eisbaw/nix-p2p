---
id: TASK-60
title: 'e2e.die is control flow: give the Pod seam a raisable HarnessError'
status: To Do
assignee: []
created_date: '2026-08-09 13:02'
updated_date: '2026-08-10 22:36'
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
- [ ] #1 e2e.die raises HarnessError; the scenario runner still exits nonzero with the same message
- [ ] #2 scale_sweep and profile_p2p catch HarnessError and put its MESSAGE in the invalid point's reason - no exit-code sniffing remains
- [ ] #3 an out-of-range Pod argument surfaces as an argument error, not as an invalid data point
<!-- AC:END -->
