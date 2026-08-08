---
id: TASK-12
title: 'JOURNEY J2: measurement journey - read the baseline like a decision-maker'
status: Done
assignee: []
created_date: '2026-08-07 21:56'
updated_date: '2026-08-08 17:31'
labels:
  - journey
dependencies:
  - TASK-9
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Second interspersed journey. As the project owner: run the measurement workload (two realistic package closures, warm and cold), read the report, and answer in writing: what narinfo-to-nar gap does real traffic show (is the prefetch window real, PRD risk 3)? What would p2p have to beat? Baseline numbers land in TESTING.md and feed the re-plan task directly. If the report cannot answer these questions, that is the finding.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Baseline in TESTING.md: egress, p95 (with N and variance), gap-histogram summary; dated + fixture-workload version; report regenerated twice with agreeing results (run-to-run agreement asserted, not assumed)
- [x] #2 Written answers committed: is the prefetch window real (gap data vs 1-4s DHT lookups, PRD risk 3)? what must p2p beat? - these feed the go/no-go checkpoint directly
- [x] #3 Report gaps/friction filed as tasks
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
forward-carried from task-3 (119cbb7): the J2 baseline you write freezes against workload nix-p2p-fixture-workload-v1 (pinned in fixtures/workload.lock.json, described in TESTING.md 'Fixture workload'). Quote the version string next to every number in the baseline - a number without it cannot be compared to anything later.

Two honesty caveats to carry into how the baseline is read: (a) payloads are incompressible seeded bytes, so compression ratios are unrepresentative of real nixpkgs closures; (b) the workload is 4 paths totalling ~111 MiB, dominated by one 110 MiB uncompressed NAR - it exercises byte volume, not closure breadth or narinfo count. If the decision-maker's question is about many-small-paths behaviour, this workload does not answer it and the baseline should say so rather than imply otherwise.

If the lock ever forces a WORKLOAD_VERSION bump (e.g. a flake.lock update), the existing baseline is RETIRED, not adjusted - mark it so wherever it is quoted.

forward-carried from task-3 round 2 (9dba842): before the J2 baseline is written, 'nix develop -c just fixtures-verify-rebuild' MUST have been run and its result recorded alongside the numbers. It proves the payload derivations rebuild to identical outputs; the routine 'just test' determinism check does NOT (it re-exports already-realised store paths and would pass forever over a nondeterministic payload). A baseline taken against accidentally-unique bytes is unreproducible, which defeats the purpose of freezing a workload at all.

Word the baseline carefully on three separate claims, which task-3 now keeps apart deliberately: (a) export repeatability - proven by 'just test'; (b) build determinism - proven by 'just fixtures-verify-rebuild', on one machine only; (c) cross-host / cross-nixpkgs reproducibility - proven by NOTHING here and not to be implied.

Rebinding the workload version is now refused by the tooling unless --retire-baseline is passed, precisely so a baseline's identifier cannot be silently redefined under it. If you ever see that flag in a diff, the baseline it names is void.

forward-carry from task-10: a NixOS VM data point now exists (just e2e-vm) proving S1 byte-identity + S2 fallback on a REAL systemd nix-daemon (17.77s test). If the J2 baseline read-out wants to note VM vs container tiers: the VM is the S2 truth layer (real store-open/service ordering); the container tier owns the S3/S4 egress/latency numbers and request-count oracles. No measurement numbers are produced by the VM test - it is a correctness gate, not an instrument.

DONE 2026-08-08. Baseline recorded in TESTING.md ('J2 measurement baseline'). Ran nix develop -c just fixtures-large + fixtures-verify-rebuild (rebuild-determinism PASS, this machine) then just measure --runs 10 TWICE. Reports: scratchpad/measure-run{1,2}.json.

RESULTS: payload NAR egress 115,934,829 B identical on both arms (daemon-on/off) and byte-identical across both runs -> offload 0.0 (wave-1 BY CONSTRUCTION, no p2p; validates the instrument, not offload). narinfo 10,665 B both arms; total differs by 51 B (the nix-cache-info the daemon serves locally) - exactly why the metric is payload egress not total. gap histogram sub-millisecond (median ~0.5ms, max <2ms, all samples in [0,10)ms) on loopback. Instrument verdict both runs: instrument_trustworthy=true (4 bites pass, arms_usable=true).

TWO-RUN AGREEMENT: egress axis agreed byte-for-byte (asserted, not assumed). p95 wall-clock did NOT agree and is reported unusable.

GOTCHAS/HONEST LIMITS: (1) S4 p95 bound UNUSABLE - A/A noise floor 0.161 and 0.103, both >= 10% threshold, podman-startup jitter dominates the ~0.5s workload (task-32 fixes via inner-realise timing / VM tier). Did NOT quote a container-tier p95 bound. (2) gap is LOOPBACK, not a real-upstream verdict - sub-ms here does not prove the prefetch window is dead against cache.nixos.org RTT (filed task-35 to re-measure on a real upstream). (3) compression ratios unrepresentative (incompressible seeded payloads); workload is byte-volume not closure breadth. (4) rebuild determinism proven on THIS machine only, not cross-host.

FRICTION FILED: task-35 (re-measure gap on real upstream). Existing task-32 (S4 inner-realise timing) and task-33 (header_timeout gap ceiling) already cover the other two - strengthened task-32 with the observed A/A data point rather than duplicating. Forward-carried to task-15 (re-plan) and task-16 (checkpoint).
<!-- SECTION:NOTES:END -->
