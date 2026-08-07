---
id: TASK-1
title: 'Scaffold: nix flake + Rust workspace + Justfile gates'
status: In Progress
assignee:
  - mped-architect
created_date: '2026-08-07 21:55'
updated_date: '2026-08-07 23:14'
labels:
  - foundation
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Foundation for everything. Nix flake devshell (pinned Rust toolchain, just), Cargo workspace with two independent crates: the product daemon (modular) and the test cache-proxy (simple fixture). No shared proxy/HTTP logic between them (PRD round-5/6: low-level pure-data crates only, and only when actually needed). Justfile recipes are the canonical gates per TESTING.md: build, lint (clippy -D warnings), test, e2e (may be a stub that fails loudly until the harness task lands - a silently-green stub is forbidden).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 nix develop provides pinned toolchain (rust-toolchain.toml + oxalica rust-overlay; clippy/rustfmt from the SAME toolchain derivation); just build, lint, test, fmt green
- [x] #2 Flake exposes packages.daemon and packages.testproxy via crane (not buildRustPackage cargoHash churn); nix build .#daemon green - VM tests and container images consume these
- [x] #3 Crate independence is mechanical: cargo tree -p testproxy contains no daemon crate (asserted by a lint/test); no shared crate until a second consumer actually exists
- [x] #4 just e2e, e2e-vm, measure, journey exist as stubs that exit 0 while printing '0 scenarios registered - NOT a pass' (commits stay unblocked); tasks 5/9/10/6 replace them with real gates and the stub state is forbidden after those close
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
REOPENED after codex cross-model NO-GO. F1: extract independence check into scripts/check-independence.py, invoked from BOTH just and checks.independence. F2: declaration-level via cargo metadata --no-deps (catches optional/target/dev-gated shared crates + transitive), with committed self-test bite cases. F3: per-package cargoArtifacts so packages.daemon does not depend on testproxy's dep build. F6: devshell exports NIX_P2P_TOOLCHAIN, _toolchain validates cargo/rustc/clippy/rustfmt all live inside it. F8: fix task refs in daemon/src/main.rs (task-2 -> task-4) and testproxy/src/main.rs (task-3 -> task-2).
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Landed in e9b3378.

Gotchas hit (feed-forward):
- nix flakes only see git-tracked files: 'git add' every new file BEFORE nix build/develop, or you chase phantom 'file not found'. Also true for Cargo.lock.
- crane HEAD refuses nixpkgs < 26.05 (loud eval warning). Flake pins nixos-26.05 even though the host is NixOS 25.11 - unrelated, and fine.
- 'cargo tree -p X | grep -q Y' under 'set -euo pipefail' is a SILENT FALSE NEGATIVE: grep exits early, cargo dies of SIGPIPE, pipefail makes the pipeline nonzero, and the 'if' takes the else branch. Reproduced 5/5 on a large tree. The independence recipe materialises the tree into a variable first.
- A pairwise 'does A depend on B' check is NOT enough for the PRD's separation rule: two crates sharing a third crate (the realistic 'let us factor out just the HTTP bit' move) passed green. The recipe now diffs workspace-local dependency SETS against an allowlist that starts empty.
- rust-toolchain.toml channel is an exact version (1.97.1), not 'stable': with -D warnings a floating channel lets an unrelated 'nix flake update' break a commit that changed no Rust, with nothing in the diff to review.
- Deliberate duplication: banner() exists in both crates. Do not factor it out - that is exactly the coupling PRD round 5/6 forbids until a second consumer earns it.

Deferred / known limits:
- Stub markers print on stdout, not stderr. Orchestrator/AC wording says 'printing'; stdout keeps naive 'just e2e | grep' working. If a harness only surfaces stderr, revisit.
- Nothing mechanically forbids the stub state after tasks 5/9/10/6 close; that enforcement is prose in AC#4. Their DoD should grep for the marker string and require zero hits.
- flake.nix uses craneLib.cleanCargoSource, which keeps only Cargo manifests and *.rs. On-disk test fixtures (narinfo/nar blobs, test signing keys) will be silently dropped, and 'nix build' runs cargo test in checkPhase - a fixture-less test that skips-when-absent would be a vacuous green inside nix while staying honest in nix develop. Comment left at the filter naming the hazard.
- 'just build' against a warm ./target proves little; the cold run was done by hand (rm -rf target) and 'nix flake check' covers it in the sandbox.

REOPENED after cross-model (codex) NO-GO on e9b3378; fixed in acb37f3.

What was actually wrong (all four findings confirmed, not just accepted):
- F1 the independence check lived only in the Justfile -> nix flake check never ran it. Now one script (scripts/check-independence.py) with two entry points: 'just independence' and checks.independence.
- F2 the cargo-tree guard was bypassable. VERIFIED empirically, not assumed: a workspace where both crates pull a shared crate, one via optional=true and one via [target."cfg(windows)".dependencies], made 'cargo tree -p daemon' and 'cargo tree -p testproxy' print the crate roots and NOTHING else. Now declaration-level via 'cargo metadata --no-deps'.
- F3 one workspace-wide cargoArtifacts coupled the two packages. Per-package now; proven by breaking testproxy's source and watching 'nix build .#daemon' still exit 0.
- F6 _toolchain accepted any cargo under /nix/store. Now checks all four tools resolve inside the exact toolchain derivation AND cross-checks rustc --version against rust-toolchain.toml.
- F8 task attributions corrected (task-4 owns daemon, task-2 owns testproxy).

NEW GOTCHAS (feed-forward):
- The cargo-metadata rewrite introduced a bypass of its OWN, found by review before commit: '--no-deps' describes only ONE workspace's members, so a hop through a crate outside the workspace (daemon -> ../vendor/middle -> shared, testproxy -> shared) dead-ended the closure and reported clean. The check that was REMOVED would have caught it. Lesson: when replacing a check, enumerate what the old one covered before deleting it. Fixed by following path deps wherever they resolve.
- Reproducing that case is itself a trap: cargo AUTO-PROMOTES in-tree path dependencies to workspace members, and refuses a nested [workspace] table under a workspace root. A non-member crate must live OUTSIDE the workspace root directory - the self-test harness does that deliberately.
- 'cargo metadata --no-deps' needs no network, no lockfile and no resolution, so the guard and its 12 synthetic self-test workspaces run unchanged inside the nix sandbox. That is why checks.independence can use cargoArtifacts = null and not wait on the dependency closure - which matters because a broken dep build would otherwise DESTROY the independence signal exactly when it is wanted.
- Mutation-tested the self-test itself: dropping the out-of-workspace recursion, keying on a dependency rename alias, or ignoring build-dependencies each trips it (exit 2). Before the extra cases were added, the rename mutant passed green - a self-test with holes reads exactly like a self-test without them.
- Exit codes are now distinct: 1 = coupled (real violation), 2 = could not check. CI can tell 'we broke the rule' from 'our tool broke'.

KNOWN LIMITS (stated, not fixed):
- The guard enforces 'no shared CRATE', not 'no shared code'. Source-file tricks ([lib] path pointing into the other crate, #[path] module includes, a build script copying a common file) are invisible to any manifest-level check.
- Both components independently depending on the SAME third-party crate (two copies of one HTTP stack) is NOT caught. Deliberately not mechanised: a denylist of crate names nobody has chosen yet is a gate that looks like a check and is not one. Carried forward as a hard requirement onto task-2 and task-4, which pick the stacks.
- Residual package coupling accepted and now named in flake.nix: one Cargo.lock means one vendor derivation (a crate that fails to FETCH still breaks both packages), and 'src' is the whole workspace, so editing testproxy invalidates daemon's build cache. Splitting either means two workspaces, which the PRD does not ask for.
- 'NIX_P2P_TOOLCHAIN=/nix/store just build' still exits 0 - correctly, because the toolchain actually in use IS the pinned one. The version cross-check is what closes the real hole; verified with a fake toolchain reporting rustc 1.80.0 (exit 1).
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Scaffold landed in e9b3378 (code) + follow-up tracker commit.

AC#1 nix develop provides a pinned toolchain: rust-toolchain.toml pins channel 1.97.1 (exact, not 'stable'); flake reads it via oxalica rust-overlay fromRustupToolchainFile, so rustc/cargo/clippy/rustfmt all resolve inside one derivation (/nix/store/...-rust-minimal-1.97.1). just build/lint/test/fmt all exit 0 from a cold ./target.

AC#2 flake packages via crane: packages.x86_64-linux.daemon and .testproxy, single binary each, meta.mainProgram set. nix build .#daemon and .#testproxy both exit 0. Also added checks.* (clippy/fmt/test/daemon/testproxy) so 'nix flake check' runs 5 real checks instead of rubber-stamping; verified exit 0.

AC#3 mechanical crate independence: 'just independence' (a dependency of 'just lint') diffs workspace-local dependency sets. Proven to bite on three injections in scratch copies - direct edge daemon->testproxy (exit 1), direct edge testproxy->daemon (exit 1), and a shared workspace crate pulled in by both (exit 1); the clean control exits 0. The pairwise-only version of this check passed green on the shared-crate case, which is the realistic violation, hence the set-diff plus an allowlist that starts empty.

AC#4 honest stubs: just e2e, e2e-vm, measure, journey each exit 0 and print exactly '0 scenarios registered - NOT a pass' (byte-verified). Tasks 5/10/9/6 have forward-carried notes telling them to delete their stub and add a DoD grep requiring zero hits for the marker.

Gate numbers (cold ./target): build 0, lint 0, test 0 (2 unit tests, 0 failed), fmt 0 (no diff), package 0, nix build .#daemon 0, nix build .#testproxy 0, nix flake check 0 (5 checks), 4/4 stub markers exact.

Reviewed by qa-test-runner and mped-architect before commit; one blocker (independence gate passed on the shared-crate case and its success message overclaimed) and eight should-fix findings were folded in - see task notes.
<!-- SECTION:FINAL_SUMMARY:END -->
