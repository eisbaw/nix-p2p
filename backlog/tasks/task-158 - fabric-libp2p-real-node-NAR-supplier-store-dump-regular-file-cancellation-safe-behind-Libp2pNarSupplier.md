---
id: TASK-158
title: >-
  fabric-libp2p: real node NAR supplier (store-dump / regular-file,
  cancellation-safe) behind Libp2pNarSupplier
status: In Progress
assignee:
  - '@me'
created_date: '2026-08-12 08:38'
updated_date: '2026-08-13 11:31'
labels:
  - libp2p
  - fabric
  - serve
  - supply
  - wave-2c
dependencies:
  - TASK-151
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-151's Libp2pNarSupplier has only an in-memory source (MemoryNarSupplier, tests/inline). A real libp2p-serving node needs a supplier that regenerates a raw NAR on demand from the store (nix-store --dump) or a raw-NAR regular file, WITHOUT holding it at rest (the task-61 regenerate-on-demand model) and cancellation-safely (owned process group), mirroring fabric-iroh's SupplyPlan Process/RegularFile sources + TaskSupervisor.execute_process. Add those NarSource variants (Process/RegularFile) to fabric-libp2p/src/nar.rs behind the same NarSupplyPlan, keeping declared-size-before-produce and NO ENUMERATION. Likely reached via a CatalogProbe-style seam the daemon implements (the daemon wiring is TASK-146).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Libp2pNarSupplier has Process and RegularFile sources that regenerate on demand without holding the NAR at rest, preserving declared-size-before-produce
- [ ] #2 production is cancellation-safe (process group reaped on shutdown), no unkillable worker
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
READY FOR DEEP GATE (qa + codex). NOT self-certified Done. Implemented on top of tree f7b510a.

SUMMARY OF CHANGE (files):
- fabric-libp2p/Cargo.toml: + proc-supervisor path dep (already a workspace member; fabric-iroh depends on it too; ZERO p2p / NOT daemon-core, so scripts/check-independence.py stays green).
- fabric-libp2p/src/nar.rs: NarSource gains Process{program,args,environment} (RegularFile collapses into a helper Process, mirroring fabric-iroh SupplySource - cancellation-safety, not taste). NarSupplyPlan gains async produce_supervised(&TaskSupervisorHandle, &Blake3Digest); the sync produce() (inline swarm-worker path) stays Memory-only and errors LOUD on a Process source (worker rewire = TASK-157). Added the digest->store-path REVERSE-MAP seam: ProbedSupply / ProbedSource{Process,RegularFile,Memory} / trait CatalogProbe (NO ENUMERATION, single per-digest probe) / struct CatalogNarSupplier{catalog,helper_program} impl Libp2pNarSupplier (mirrors iroh IndexNarSupplier). + RAW_NAR_HELPER_ARG convention for the daemon helper.
- fabric-libp2p/src/lib.rs: export CatalogNarSupplier, CatalogProbe, ProbedSource, ProbedSupply, RAW_NAR_HELPER_ARG.
- Cargo.lock: proc-supervisor dep edge only (no new package).

PER-AC:
- AC#1 (Process + RegularFile, regenerate on demand, no hold at rest, declared-size-before-produce): DONE. declared_size comes from the probe (daemon's persisted NarSize, TASK-82 - UNCOMPRESSED NAR bytes, not compressed FileSize; the unit trap) so plan() never dumps. Process runs nix-store --dump/helper via execute_process; RegularFile runs the daemon helper (helper __dump-raw-nar <path>). Nothing held at rest.
- AC#2 (cancellation-safe, process group reaped, no unkillable worker): DONE. Process runs under proc_supervisor::TaskSupervisorHandle::execute_process (owned process group; SIGKILL+reap on node cancel/abandon; stdout capped at declared_size). Byte-integrity anchor kept: produce_supervised rechecks len==declared_size AND BLAKE3(RawNarV1)==content before returning (a rebuilt store path / replaced raw file fails LOUD, never ships wrong bytes under a right name).

DECLARED-SIZE-WITHOUT-DUMP: the CatalogProbe answers declared_size directly from the daemon's persisted NarSize binding (TASK-82); plan() copies it. The no-dump-at-plan test spies the dumper (marker file) and asserts it is NOT run at plan time.

REVERSE-MAP SEAM (daemon-core-free): fabric-libp2p defines trait CatalogProbe; the DAEMON implements it over its AvailabilityIndex and constructs CatalogNarSupplier::new(probe, helper_program). fabric-libp2p gains NO daemon-core edge (check-independence.py EXIT=0, self-test 10 bypasses caught).

CANCELLATION/REAP MECHANISM: execute_process starts a ProcessJob on its own process group via ProcessJobRegistry; on TaskSupervisor cancel_now()/begin_shutdown() the group is SIGKILLed and a dedicated waiter thread reaps to ECHILD, removing the job from the registry only after it proves child-free. Reap oracle in the test: process_jobs().active_len()==0 AND /proc/<pid> gone.

BITE PROOFS (by mutation, both observed to FAIL then reverted):
- AC#1 no-dump-at-plan: mutated CatalogNarSupplier::plan to run the dumper (Command::output) at plan time -> the marker appears -> assert !marker.exists() after plan() PANICS (nar.rs:873). Reverted.
- AC#2 reap: mutated produce_supervised to spawn the process UNSUPERVISED (detached std::process::Command, no execute_process) -> the sh+grandchild survived, reparented to init (PPID=1), and the pipe-holding orphan hung the test harness (the exact hazard proc_supervisor closes). Confirmed via ps (PPID 1 orphan). Killed + reverted.

BOUNDED GATE (actual):
- cargo build -p fabric-libp2p --locked: ok.
- cargo clippy -p fabric-libp2p --all-targets -- -D warnings: clean.
- cargo fmt --all --check: FMT_OK.
- python3 scripts/check-independence.py (in nix develop): EXIT=0 (no daemon<->testproxy edge; no shared crate outside empty allowlist; HTTP-stack denylist green).
- cargo test -p fabric-libp2p --locked: lib 33 passed (4 new TASK-158 tests: process_plan_learns_declared_size_without_running_the_dumper, regular_file_source_round_trips_via_helper_process, produce_rejects_bytes_that_do_not_hash_to_the_announced_content, supervised_process_source_is_reaped_on_cancel); integration bootstrap_independence 2, decentralized_discovery 1, nar_transport 6, near_key_routing_bar 1, node_locator_discovery 1, record_lifecycle 5; doctests 0. 0 failed. No orphans leaked from the reap test (the supervised path reaps).

HONEST LIMITS / GOTCHAS:
- produce_supervised is async and is NOT wired into the synchronous inline ServeGate::respond swarm-worker path this cycle. respond() stays Memory-only (existing behaviour); a Process source hitting it returns a loud typed error. Wiring supervised production into the worker serve loop (off-poll-loop) is TASK-157; the daemon end-to-end that builds CatalogNarSupplier over the AvailabilityIndex and serves a real /nix/store (replacing --libp2p-seed-nar's MemoryNarSupplier) + the container e2e is TASK-191 (FILED, deps TASK-158/178/161; iroh analogue TASK-83). Module doc + CatalogNarSupplier doc carry these pointers.
- RegularFile is served by a daemon-supplied HELPER PROCESS (never an in-process read) for cancellation-safety (D-state on broken FUSE/NFS); the helper BINARY + copy_regular_raw_nar-style stat/size-change guard live with the daemon (TASK-191), not in this library crate. The tests stand in a cat-based helper script.
- serve-time recheck currently re-hashes the whole produced buffer (buffered, not streamed); a streamed hash-on-the-fly belongs with TASK-157.

FORWARD-CARRY to TASK-191: (1) declared-size-without-dump = read the persisted NarSize (uncompressed; not FileSize). (2) reverse-map = daemon impls fabric_libp2p::CatalogProbe over AvailabilityIndex; construct CatalogNarSupplier::new(probe, helper_program); keep fabric-libp2p daemon-core-free. (3) route store-dump bytes through announce_provider_seeds/verify_provider_seeds SSOT (TASK-56) - do not add a bypass announce path. (4) supply the raw-NAR helper binary for ProbedSource::RegularFile (RAW_NAR_HELPER_ARG). (5) cancellation-safe reap already proven at the fabric layer; the daemon just needs to own a TaskSupervisor and pass its handle to produce_supervised.
<!-- SECTION:NOTES:END -->
