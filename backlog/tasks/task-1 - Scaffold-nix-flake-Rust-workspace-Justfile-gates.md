---
id: TASK-1
title: 'Scaffold: nix flake + Rust workspace + Justfile gates'
status: To Do
assignee: []
created_date: '2026-08-07 21:55'
updated_date: '2026-08-07 22:19'
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
- [ ] #1 nix develop provides pinned toolchain (rust-toolchain.toml + oxalica rust-overlay; clippy/rustfmt from the SAME toolchain derivation); just build, lint, test, fmt green
- [ ] #2 Flake exposes packages.daemon and packages.testproxy via crane (not buildRustPackage cargoHash churn); nix build .#daemon green - VM tests and container images consume these
- [ ] #3 Crate independence is mechanical: cargo tree -p testproxy contains no daemon crate (asserted by a lint/test); no shared crate until a second consumer actually exists
- [ ] #4 just e2e, e2e-vm, measure, journey exist as stubs that exit 0 while printing '0 scenarios registered - NOT a pass' (commits stay unblocked); tasks 5/9/10/6 replace them with real gates and the stub state is forbidden after those close
<!-- AC:END -->
