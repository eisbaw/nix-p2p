---
id: TASK-305
title: >-
  LAN custom builds: publish locally built outputs and discover trusted peer
  narinfos
status: Done
assignee: []
created_date: '2026-09-28 19:48'
updated_date: '2026-09-28 23:15'
labels:
  - feature
  - lan
  - trust
  - e2e
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
At b980fac, lan-share peers transfer public-cache paths but a newly built custom derivation cannot be substituted: both localhost endpoints return narinfo 404 and a consumer with builders empty and max-jobs=0 fails realization. Metadata is upstream-only and fetched-only supply never registers a fresh local output. Implement explicit opt-in LAN signing/trust plus actual local-output publication and peer metadata discovery, retaining public-cache trust and private defaults. This is narrower than TASK-213 authenticated private pools.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 A real multi-node Podman or NixOS VM regression fails on b980fac: distinct stores, fresh custom derivation, same drv and builder inputs, no output copy, consumer builds disabled.
- [x] #2 Explicit LAN trust/key configuration enables newly built output discovery and authenticated metadata plus peer payload transfer without public DHT or public cache dependency.
- [x] #3 Nix realizes the exact output with signatures enforced; test verifies bytes, provider serve evidence, and consumer builder never invoked.
- [x] #4 Untrusted or tampered metadata/payload is rejected; default and public-cache trust remain safe.
- [x] #5 Regression integrated in CI; remote exact-tree just e2e and required parallel QA/architecture reviews pass before commit; docs record only observed results.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Independent baseline executed on b980fac in an isolated x86_64 remote Podman checkout, internal bridge and distinct writable stores. Fresh runtime nonce derivation built AFTER producer daemon startup, identical drv and registered builder input closure on consumer. Both local endpoints returned 404. Consumer realization with only localhost substituter, require-sigs=true, max-jobs=0 and builders empty failed with local builds disabled. Harness reported 8/9 checks, exit 1 (expected pre-fix failure). First draft compiles under pinned remote nix develop cargo check -p daemon-libp2p; no passing feature/e2e claim yet. User clarified custom-output sharing must have an explicit enable setting, default off. Added draft CLI switch and NixOS option.

First post-fix diagnostic remote Podman run realized the fresh custom derivation with builds disabled, matching bytes and NarHash, no upstream metadata dependency, and producer libp2p payload completion. Overall run was FAIL (12/13): the Nix rejection oracle expected signature but actual correct refusal said not signed by any of the keys. Assertion corrected; expanded expiry/restart/idle/toggle/tamper regression still pending. Focused remote tests passed: metadata reconnect after connection loss (1), supervised dump cancellation and reaping (1), LAN CLI configuration (2), LAN signature/URL/disabled-resharing gates (3). Pinned NixOS evaluation confirmed default cache.nixos.org trust remains alongside LAN key. Required full end-to-end gates and final reviews remain open.

Expanded isolated remote regression PASSED: nix develop --max-jobs 1 --cores 4 -c just e2e "--only libp2p-lan-custom-build"; 28/28 checks in 193.1s. Proven: first lookup after 65s idle, exact Nix realization with non-empty signed References and builders disabled, actual peer serve, expiry and warm Nix/daemon cache restart without metadata regeneration, independent Nix/daemon signer rejection, disabled consumer retains but cannot re-share custom output, producer disable/re-enable positive control, and provider content-root mismatch rejects tampered bytes. This is not final-tree completion: architecture review found equal-NAR alias GC ownership and failed-registration capacity rollback bugs; fixes and additional alias regression are in progress. Required lint currently fails only new collapsible-if warnings so far; full gates/reviews remain open.

The strengthened historical baseline on b980fac failed as intended: 9/10 checks, exit 1, both narinfo endpoints 404, Nix realization exit 100 with local builds disabled. Final expanded custom scenario passed 37/37 checks (308.5s), command: nix develop --max-jobs 1 --cores 4 -c just e2e "--only libp2p-lan-custom-build". This adds equal-NAR aliases surviving producer restart and GC of the latest backing path, with warm consumer metadata and fresh provider serve evidence. Executed code matches staged tree cca113a5f329eb07e101c550f3ea011fc81cd213; the run began before a test-only module relocation. Remote lint passed all 21 stages; architecture review found no remaining blocker on that tree. Remote full test and E2E gates remain pending; no completion claim yet.

Broader QA resource event: both required build variants passed, but just test was interrupted during test compilation as debug and incremental artifacts exhausted runner headroom. No test-suite pass was claimed. Source-path and timestamp checks established that the build cache belonged exclusively to this disposable task checkout; it was cleaned without touching unrelated work. QA restarted the same pinned just test recipe with CARGO_BUILD_JOBS=2, CARGO_PROFILE_DEV_DEBUG=0, CARGO_PROFILE_TEST_DEBUG=0, CARGO_INCREMENTAL=0. Tests and assertions are unchanged; result remains pending.

Remote pinned QA completed on staged tree cca113a5f329eb07e101c550f3ea011fc81cd213: lint 21/21 PASS; just test PASS, 1381 Rust tests passed and 12 explicitly ignored, plus Python fixture/protocol/evidence and real-Nix rewrite checks. Reduced-artifact environment from the prior note was used. The required just e2e-full gate FAILED: 45/47 scenarios passed in 1560.1s. Custom LAN passed all 37 checks again (190.2s). Failures: crash-sigstop-stall 4/7 (both frozen-daemon and fallback downloads timed out), and libp2p-concurrency-soak 6/8 (all client bytes correct, but upstream attribution inverted between provider-alive and provider-dead arms). Gate failure blocks commits; baseline investigation of these unchanged scenarios is underway.

Required remote full gate PASSED on staged tree 28a32d0b9037bb1547f0cd157d559742bf04127a: PYTHONUNBUFFERED=1 CARGO_BUILD_JOBS=2 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0 nix develop --max-jobs 1 --cores 2 -c just e2e-full; 47/47 scenarios, 1711.1s, exit 0. Custom LAN 37/37; SIGSTOP 8/8 after TASK-306 fixture repair; concurrency soak 8/8 with alive upstream=0 and dead received=6/upstream=1/cache_hits=5. Parallel QA on that tree: lint 21/21, just test 1384 Rust passed/0 failed/12 explicit ignores plus Python/real-Nix checks; architecture found no blocker. Original soak failure remains unexplained and its rate is unmeasured: one baseline sample and one diagnostic sample passed before this required full run. No claim that proxy repair fixed that separate observation. Added phase diagnostics without changing soak workload/assertions. Default just e2e and bounded proxy repeatability measurement remain pending.

Final required default gate PASSED: PYTHONUNBUFFERED=1 CARGO_BUILD_JOBS=2 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0 nix develop --max-jobs 1 --cores 2 -c just e2e; 17/17 scenarios, 861.4s, exit 0, custom LAN 37/37 in 188.0s. Exact tested staged tree fc465ea918a2195d866a7021b66e4e7d0176cfbb verified unchanged before/after; implementation/test/config/docs blobs identical to full-gate and QA tree 28a32d0b9037bb1547f0cd157d559742bf04127a. Only TASK-305/TASK-306 result/status closeout follows this gate; final commit tree is not claimed literally tested. Required parallel QA/architecture reviews passed. TASK-306 TCP repeatability: 20/20 samples under two CPU burners; broad-suite/soak flake rate remains unmeasured and earlier soak miss remains unexplained. Feature and CI regression complete on isolated branch fix/lan-custom-build-sharing; no live-host deployment.
<!-- SECTION:NOTES:END -->
