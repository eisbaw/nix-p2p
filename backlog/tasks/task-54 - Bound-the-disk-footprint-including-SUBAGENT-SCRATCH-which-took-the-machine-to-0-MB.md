---
id: TASK-54
title: >-
  Bound the disk footprint - including SUBAGENT SCRATCH, which took the machine
  to 0 MB
status: Done
assignee: []
created_date: '2026-08-08 22:11'
updated_date: '2026-08-15 09:57'
labels:
  - tooling
dependencies:
  - TASK-42
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Disk hit 100% during task-48 (target/ got auto-nuked by a cleanup; rebuildable, no loss - but a warning). 97% used / 28G free as of 2026-08-09. Disk-heavy work ahead: container e2e (115MB big fixture + podman images), and especially S5 profiling (task-42) with 1..30 daemon-node swarms each holding a blob store. Bound it: e2e-clean should prune podman images/volumes not just pods; a just recipe to reclaim (cargo clean / fixture generations GC / podman system prune); the profiling harness should cap per-node blob-store size and clean up swarm nodes; document a disk-headroom precondition for the profiling/e2e recipes (fail-fast with a clear message if free space < N GB, rather than a mid-run 100%-full crash).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 e2e-clean and a reclaim recipe bound podman images/volumes + fixture generations; documented
- [x] #2 The profiling harness (task-42) caps per-node blob store + cleans up swarm nodes; a disk-headroom precondition fails fast with a clear message
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
## NEW DIMENSION 2026-08-10 (owner: '44GB is too large'): REVIEWER/MUTATION SCRATCH IS UNBOUNDED

This task was scoped to target/, fixtures, podman images and blob stores. It missed the biggest
consumer in practice: SUBAGENT SCRATCH. Measured today, and it took the machine down.

WHAT HAPPENED: the orchestrator created a /tmp git worktree so a codex review could run against a
pinned sha. codex ran 'nix develop -c just build' inside it. That single worktree reached 44 GB
(cargo target dir + mutation-campaign rebuilds). The filesystem hit 0 MB free, which killed ALL shell
access in the session - every command failed at output capture, including the commands that would
have freed the space. Recovery required the owner to intervene from an external terminal.

Total scratch found and reclaimed afterwards, all from completed reviews:
  scratchpad/regate-snap  44 GB   (the worktree codex built in)
  scratchpad/work         24 GB
  scratchpad/muttarget   2.7 GB
  scratchpad/repo        2.2 GB
  scratchpad/probe       2.2 GB
  /tmp/regate-hold-review 2.3 GB  (codex's own clone)
  + coldstore, t3verify, two stale registered worktrees
Reclaimed ~78 GB. Free space went 11 GB -> 53 GB.

ROOT CAUSE: every reviewer and implementer that builds gets its OWN cargo target directory. Six
concurrent reviewers = six full builds of the same tree. Nothing bounds it and nothing cleans it up,
because each agent finishes and its scratch outlives it.

THE FIX, in order of leverage:
1. SHARED CARGO_TARGET_DIR. Point every agent copy at one target directory
   (e.g. CARGO_TARGET_DIR=/home/mpedersen/.cache/nix-p2p-target). N copies of the repo then share ONE build dir,
   collapsing ~44 GB to ~3 GB. Note the tradeoff: concurrent cargo invocations lock the shared dir, so
   parallel agents serialise on it - which is arguably CORRECT here, since TASK-109 established that
   concurrent builds are what make the gate non-deterministic.
2. MANDATORY CLEANUP in every subagent brief: remove your scratch when done, and say what you removed.
3. A HEADROOM PRECONDITION that fails fast: refuse to start a build/sweep below N GB free rather than
   dying at 0 MB with the shell unusable.
4. A RECLAIM RECIPE ('just reclaim') that finds and removes stale review scratch, stale git worktrees
   (git worktree prune), and podman leftovers.

DO NOT solve this by having agents skip builds. The gate must still run; it just must not run six
times into six directories.

TASK-54 done (commit 2cff63b). Root-cause fix: SHARED CARGO_TARGET_DIR (~/.cache/nix-p2p-target) set as a QUIET devShell env attr in flake.nix (no shellHook echo) - N per-agent target dirs collapse to ONE and serialise on cargo's lock (TASK-109-correct). Only affects nix develop; nix build/flake check use crane's sandboxed target, so frozen artifacts unaffected.

AC#1: e2e-clean now prunes dangling podman images + unused volumes (not just pods/nets) via prune_images_and_volumes() in the --clean CLI path only (kept out of cleanup_pods so it cannot delete an in-use image between scenarios). New 'just reclaim' + scripts/reclaim.sh: podman system prune -f --volumes, drop unreferenced fixture generations (keep current+previous), git worktree prune, clear cargo target dir(s) with guarded rms. Documented in Justfile comments. On a real run it freed 36341 MiB (26G repo-local target + 9.7G stale shared cache; podman had 0B stale to free; fixture GC found only referenced gens). df 93G->129G.

AC#2: the profiler's headroom precondition (MIN_FREE_DISK_BYTES, profile_p2p.py:4701), SIGTERM->teardown (ss.install_sigterm_cleanup + cleanup_pods + scratch rmtree), MemStore blob + scratch-cache-deleted-with-dir caps ALREADY existed. Added an EARLIER, stricter Justfile _headroom gate (default 15 GiB, override NIX_P2P_MIN_FREE_GIB, integer math) wired FIRST into test/e2e/e2e-full/measure/scale-sweep/profile/journey - it fires before nix/python/cargo spin up and points at 'just reclaim'. Demonstrated: fires exit 1 with message at threshold 999999; passes exit 0 at default on ~93G box.

Gate: cold 'just build' into shared dir succeeds (4m05s, exit 0); ruff check+format, check-no-floats, e2e --self-test all green; reclaim exit 0. NO full e2e run (heavy). No AI/co-author credit in commit (audited).
<!-- SECTION:NOTES:END -->
