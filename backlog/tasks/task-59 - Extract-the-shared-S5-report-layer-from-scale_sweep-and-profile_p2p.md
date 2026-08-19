---
id: TASK-59
title: Extract the shared S5 report layer from scale_sweep and profile_p2p
status: Done
assignee: []
created_date: '2026-08-09 13:01'
updated_date: '2026-08-19 16:48'
labels:
  - refactor
  - harness
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The two sweep instruments have grown parallel implementations of the same thing.

`profile_p2p.build_report` is a near-copy of `scale_sweep.build_report`: same measured/models split, same distinct_n / valid_observations_per_n / points / invalid_points construction, same counting_rule / caveat / red_flags / honesty / verdict skeleton - with DIVERGENT key names already (`swarm_valid_observations` vs `axis_status[].valid_observations`). Two definitions of 'what a compliant S5 report looks like' is exactly the shape that lets one drift silently, and one already has.

Also copied rather than shared: `provenance()` (byte-for-byte the same /proc/meminfo loop, git rev-parse, host dict and note string) and `MIN_FREE_DISK_BYTES` plus its `shutil.disk_usage` check. `install_sigterm_cleanup` and `silent_expect`/`int_list` were already made shared during task-42; these are the remainder.

RELATED AND ARGUABLY MORE IMPORTANT: the UNIT RULE is repo-wide honesty, not one instrument's preference, but `unit_violations()` lives in profile_p2p and polices only ITS report. `scale_sweep` emits a sibling report carrying `daemon_rss_hwm_bytes`, `chain_total_rss_hwm_bytes` and `mem_total_bytes` - all unlabelled, all of which that gate would reject. So the repo has two report schemas and one is unpoliced. The rule belongs in `scalefit.py` (already the shared, stdlib-only, harness-free honesty module) folded into `sweep_report_violations`, with scale_sweep's keys renamed in the same move.

Found by the task-42 architecture review.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 one shared implementation builds the measured/models/red_flags/honesty/verdict skeleton for both instruments; neither has its own copy
- [x] #2 provenance() and the disk-headroom precondition are defined once and take the per-instrument extras as parameters
- [x] #3 the unit rule lives in scalefit and is enforced on BOTH reports; scale_sweep's byte keys carry unit suffixes
- [x] #4 both instruments' self-tests still pass and their honesty mutations still bite
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
ORCHESTRATOR VERIFICATION 2026-08-19 (commit 2d79794; implementer held the commit for its mped re-review which returned GO; I ran the gate mped explicitly did NOT re-run, per its own caveat). VERIFIED: 5 self-tests (profile_p2p/scale_sweep/scalefit/sizeaxis/measure) rc=0; ruff clean; no-floats green. HONESTY GAP CLOSED + mutation-proven: scale_sweep byte fields relabelled unit-suffixed (daemon_rss_hwm_bytes_ram, chain_total_rss_hwm_bytes_ram, mem_total_bytes_ram) and its report now runs scalefit.unit_violations; the scale_sweep --self-test injects a bare daemon_rss_hwm_bytes and asserts the unit rule REJECTS it (bites), passing once _bytes_ram-labelled — the previously-unpoliced report is now policed. Shared layer (build_report sub-helpers, provenance, MIN_FREE_DISK_BYTES/disk_headroom_ok, unit rule) lives once in scalefit; schema converged (swarm_valid_observations divergence gone, only historical comments remain). mped fixes verified independently: sizeaxis consumer reads the renamed aggregate_samples byte keys (was a KeyError); the role_metrics self-test now drives the real producer so the byte-key contract bites. Design deviations mped-endorsed (unit_violations standalone; composed sub-helpers over monolithic build_report). AI-credit clean; not pushed.
<!-- SECTION:NOTES:END -->
