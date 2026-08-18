---
id: TASK-21
title: Path-based residual in fixture publication (ancestor-swap hardening)
status: To Do
assignee: []
created_date: '2026-08-08 06:32'
updated_date: '2026-08-18 20:36'
labels:
  - hardening
dependencies:
  - TASK-113
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Codex round-8 residual finding 4 (FILE, don't fix). The round-7 claim that all fixture-publication filesystem operations are descriptor-relative was overstated. Several steps in scripts/gen-fixtures.py remain PATH-based rather than performed relative to a held O_NOFOLLOW|O_DIRECTORY descriptor: generation resolution (fx.resolve_current / resolve_previous walk out_dir by path), retention (retained() reads the previous symlink by path), and the link flips (point_link_at creates and os.replace's current/previous by path under out_dir).

THREAT MODEL BOUND (why this is deferred, not urgent): exploiting the residual requires a hostile actor able to swap an ANCESTOR directory of fixtures/out mid-operation - i.e. write access under the same uid on the host. That attacker is explicitly OUTSIDE the fixture tooling's threat model (recorded in scripts/fixturelib.py and fixtures/README.md): they can edit fixtures/workload.lock.json, workload.nix, and the generation trees directly, so descriptor discipline buys nothing against them. The anchoring that IS in place (anchored_publication holds out_fd + generations_fd; commit_lock/load_baseline/read_workload_version go through anchored_fixtures_dir; purge_marked_dir/unlink_contents/collect_generations are fully dir_fd-relative) defends against the in-scope cases: a concurrent ancestor swap of the generations directory and a static ancestor symlink written through. This residual is the same species one level up (the publication ROOT and the link namespace), against an out-of-scope attacker.

REMEDIATION SHAPE (for the hardening wave, not now): thread the held out_fd into resolve_current/resolve_previous/point_link_at so the symlink reads (readlinkat) and flips (symlinkat + renameat over the link) are all relative to the anchored root descriptor, and re-verify the root's (dev,ino) via same_inode before each. This removes the last path-based ancestor walks from the publication critical section. Bite to add: swap out_dir for a symlink after anchored_publication resolves it, then flip current - the flip must land in the real (renamed-away) root or fail closed, never through the swapped-in symlink.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 resolve_current/resolve_previous/point_link_at operate relative to the held anchored-root descriptor (no path-based ancestor walk in the publication critical section)
- [ ] #2 a bite swaps out_dir for a symlink after anchored_publication resolves it and proves the current flip does not follow the swap (lands in the real root or fails closed)
- [ ] #3 the threat-model note in fixturelib.py/README is updated to state that publication link ops are now descriptor-relative too
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Additional guard residual (task-3 round 9, orchestrator-verified): check-lock-sources.py exempts gen-fixtures.py (the baseline owner) from the literal scan, so a bare-literal baseline read smuggled into a NON-owner helper INSIDE gen-fixtures.py is not caught (verified exit 0). Low severity - gen-fixtures legitimately owns the baseline; the runtime GATE modules (which must derive only from current->gen/lock.json) ARE fully covered (literal+alias+deny-by-default, all verified biting). Full coverage needs function-level analysis inside the owner. Hardening-wave item, not a blocker.

task-13 triage (KEEP, distinct concern): path-based ancestor-swap residual in scripts/gen-fixtures.py PUBLICATION internals, exploitable only by an out-of-threat-model same-uid attacker who can already edit the fixture trees directly. LOW priority, unrelated to the HTTP daemon/proxy surfaces this hardening wave stabilized. Kept with its 'hardening' label for a later fixture-tooling pass; removed deferred-finding (it is already a fully-specified task with ACs).

Downgraded 2026-08-18 (COMPASS §4): the task text itself states the attacker is outside the threat model and can already edit the fixtures directly. Descriptor discipline buys nothing against that.
<!-- SECTION:NOTES:END -->
