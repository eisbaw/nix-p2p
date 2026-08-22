---
id: TASK-302
title: >-
  TASK-297 hardening: global-backstop residuals (spawn-race cheap-fill, prune
  identity race, symlink existence)
status: To Do
assignee: []
created_date: '2026-08-22 05:47'
labels: []
dependencies: []
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Codex DEEP-gated TASK-297 across 8 rounds. The per-PeerId amplification cap is LIVE and SOLID (per-peer windows isolated, charge-at-spawn/no-refund, 2-pass accounting, both binaries wired, integrity intact) and the DETERMINISTIC exploits are closed (charge-at-spawn killed the cancellation-timing class; the stale-catalog deterministic attack is closed via a supply-catalog exists() probe before charge). These are the REMAINING residuals, all on the SHARED GLOBAL backstop (NOT the per-peer bound) or availability-only — none lets a single peer drive unbounded free work; they roll into the documented Sybil-global limitation (TASK-205 family).

1. HIGH-A residual (charge not perfectly atomic with Command::spawn across the supervisor async task creation). proc-supervisor stream_process queues an async task that calls start_streaming (creates the worker) BEFORE polling the job's cancel channels. A peer that half-closes early can LOSE the pre-spawn race: the worker enters the launch mutex, consults the PreSpawnGate (charges), and spawns before the job-level cancel arrives; the child is then killed. Result: charged full 2-pass declared-size for a spawn that did only exec + a brief dump prefix -> a race-dependent, per-peer-bounded way to pressure the GLOBAL byte/dump backstop below full cost. Fix candidate: poll the job's cancel channels BEFORE start_streaming (don't create the worker if already cancelled), and/or make the worker's arrival-at-gate atomic with job cancellation. proc-supervisor/src/task_supervisor.rs:~714-770, process_group.rs:~713-741. Coverage gap: only a proc-supervisor PRIMITIVE test pins the in-worker gate ordering; the serve-integration cancel-before-job-creation interleaving is untested (racy).

2. Charge-before-fallible-spawn: the ledger commits (process_group.rs:~733) just before the fallible command.spawn() (:~741), so a node-side exec failure is charged with NO process created. Node-side, not peer-inducible; doc now honest. Optional: charge only after a successful spawn syscall (but keep it before the process does real work).

3. prune_if_gone same-path re-registration race (availability, safe-direction, NOT a security HIGH). availability.rs prune_if_gone snapshots Arc E, observes absent, releases the lock; if Nix rematerializes + re-registers the SAME path (register no-op retains Arc E), drop_if_same still sees pointer equality and removes the now-LIVE registration + supply record. Make prune re-check liveness under the lock at removal, or use a generation/epoch rather than pointer identity. availability.rs:~2018-2035. Coverage gap: prune tests cover absent + live, not re-materialization between stat and removal.

4. Path::exists() follows symlinks + maps metadata errors to false: a legitimate dangling-symlink store object that nix-store --dump CAN serialize could be falsely declined/pruned (safe-direction availability loss). Use symlink_metadata / a check that matches what nix-store --dump accepts.

None blocks a normal user; all are adversarial-edge or availability. Do full just e2e for any change (shipped serve path).
<!-- SECTION:DESCRIPTION:END -->
