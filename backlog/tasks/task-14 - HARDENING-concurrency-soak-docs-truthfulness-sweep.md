---
id: TASK-14
title: 'HARDENING: concurrency soak + docs truthfulness sweep'
status: To Do
assignee: []
created_date: '2026-08-07 21:56'
updated_date: '2026-08-17 22:12'
labels:
  - hardening
dependencies:
  - TASK-21
  - TASK-36
  - TASK-113
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Wave-end hardening block, part 2. Soak: max-substitution-jobs=16 storm of parallel substitutions through the chain (architect round-2: sixteen concurrent requests is Nix default reality), plus restart-under-load. Docs: README quickstart executed verbatim on a clean machine/container; TESTING.md checked against what the harness actually does; stale claims fixed or deleted (repo cruft policy).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Concurrency soak parameterized by client knobs (TESTING.md): max-substitution-jobs and http-connections swept over {1, 16, 128}; at each point: no deadlock, fd/memory bounds asserted, S1 holds; restart-under-load recovers; results reported per knob value
- [ ] #2 Same-path dogpile at the harshest swept setting (128 jobs): concurrent cold-cache requests for ONE large NAR -> single upstream fetch (or explicitly documented safe alternative); never a partial/corrupt byte served
- [ ] #3 README quickstart executed verbatim in a clean container - every command works as written; TESTING.md drift corrected in the same commit
- [ ] #4 A repeated cross-backend soak exercises zero-injection Iroh and raw BitTorrent discovery/transfer, holder churn, dependency outages and upstream fallback; provider/upstream counters prove both backends actually ran.
- [ ] #5 Docs/PRD/status examples for Iroh, BitTorrent, participation defaults, codec arms and known unsupported cells are checked against live configuration/output; stale backend or tournament claims fail the sweep.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
forward-carry from task-10: VM truth layer exists (nixos/vm-test.nix). If concurrency/soak wants a VM data point, note the daemon runs under systemd DynamicUser (nixos/nix-p2p.nix) binding 127.0.0.1:port; max-substitution-jobs/http-connections are client nix.settings you can sweep on the client node. Same absent-before ORACLE GOTCHA as task-13: use nix-validity, not test -e.

Forward-carry from task-13 (hardening pt1): surfaces the concurrency soak + docs sweep should hit -
1) Run the fault x depth matrix AND the timeout boundary under CONCURRENCY (max-substitution-jobs {1,16,128}); task-13 pinned them at max-substitution-jobs=1 only. The per-hop header timeout composition and the fail-fast 502 paths are the concurrency-sensitive ones.
2) Soak the ENOSPC/write-failure paths: task-13 proved single-shot fail-closed (narinfo cache -> passthrough, testproxy -> 5xx+no-partial); a soak should hammer them under load to confirm no tmp-file leak / no torn cache entry accumulates (testproxy CacheWriter drop-cleanup, narinfo .tmp reap).
3) The blocking-fsync-on-async-path (task-28) is most likely to bite the daemon under a concurrent soak - worth measuring worker-stall there.
4) Docs sweep: reconcile the new TESTING.md 'Hardening: fault x depth, header hygiene, fuzz (task-13)' section against code; the daemon now has a --header-timeout-ms flag (document in any operator/NixOS docs).

Forward-carry from task-13 (VM fault re-assertion, re-deferred here with owner-visible decision): re-assert the 3 tamper narinfos AND testproxy fault modes THROUGH the systemd nix-daemon in the NixOS VM (nixos/vm-test.nix, just e2e-vm), expecting the task-5 daemon-side strings ('not signed by any of the keys in trusted-public-keys', 'hash mismatch importing path'). Reuse build_tamper_tree/build_corrupt_nar_tree; serve a key-free tamper cache from a peer node; ORACLE GOTCHA (banked): absent-before MUST use nix-VALIDITY (nix-store -q --hash fails 'not valid'), NOT test -e, because the nixos-test 9p-shared host store makes fixture files physically present on every node. Interpose testproxy for VM-level request-count/fault oracles.

SEQUENCING (owner, 2026-08-08): deprioritized - owner chose to jump to wave-2 planning before finishing wave-1 hardening. task-14 (soak + docs sweep) deferred to run alongside/after wave-2 planning, not blocking. Relabeled for later.

README drift found by mped-architect review (2026-08-08, figures commit) - README.md was committed in 0ca03b6 and already drifts; belongs to this task's docs-truthfulness sweep: (1) 'no shared crates, enforced by just independence' overstates the gate - check-independence covers only path-linked workspace crates + an HTTP-stack lockfile denylist, third-party sharing like serde would pass; also they are lib+bin crates, not bare binaries. (2) 'passes signed metadata through from cache.nixos.org' - daemon rejects https upstreams in wave 1 (task-24 open). (3) narinfo disk cache listed as current behavior but is OFF by default (task-29 open). (4) S4 listed under 'tested end-to-end' but TESTING.md marks S4 UNUSABLE at container tier (s4_usable=false). (5) S3 bullet drops 'offload = 0 by construction in wave 1'. (6) Status paragraph + S1-S4 restatement duplicate TESTING.md/backlog state and have already drifted - consider pointing at TESTING.md instead of restating. Also: TESTING.md internally inconsistent 'S1-S4' (line ~522) vs 'S1-S5' (~656). Also backlog hygiene: task-37 is Done with all 4 ACs unchecked.

Forward-carried from TASK-247: the focused real nix-daemon wide-fanout libp2p latency-hiding proof now lives in TASK-247 after TASK-57. Reuse its fixture, knob matrix, request-overlap oracle, and evidence here. Keep TASK-14 scoped to the additional restart-under-load, fault-depth, documentation, and eventual cross-backend soak; do not rebuild the core concurrency proof.
<!-- SECTION:NOTES:END -->
