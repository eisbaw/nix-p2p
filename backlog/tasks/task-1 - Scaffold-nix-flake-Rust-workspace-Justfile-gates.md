---
id: TASK-1
title: 'Scaffold: nix flake + Rust workspace + Justfile gates'
status: Done
assignee:
  - mped-architect
created_date: '2026-08-07 21:55'
updated_date: '2026-08-07 22:40'
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
1) flake.nix: nixpkgs + oxalica/rust-overlay + crane; devshell w/ toolchain-from-rust-toolchain.toml (clippy+rustfmt same derivation) + just; packages.daemon/.testproxy via crane. 2) Cargo workspace: daemon/ + testproxy/, independent, unit test each. 3) Justfile: build/lint/test/fmt + independence guard (cargo tree) + honest stubs e2e/e2e-vm/measure/journey printing '0 scenarios registered - NOT a pass'. 4) .gitignore, commit Cargo.lock. 5) Gate: nix develop -c just {build,lint,test,fmt}, nix build .#daemon/.#testproxy.
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
