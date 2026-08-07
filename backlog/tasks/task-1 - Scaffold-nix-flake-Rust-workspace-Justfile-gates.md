---
id: TASK-1
title: 'Scaffold: nix flake + Rust workspace + Justfile gates'
status: To Do
assignee: []
created_date: '2026-08-07 21:55'
updated_date: '2026-08-07 22:04'
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
- [ ] #1 nix develop provides toolchain; just build, just lint, just test all green
- [ ] #2 Workspace has daemon and testproxy crates; no proxy logic shared between them
- [ ] #3 just e2e exists and fails loudly (non-zero, clear message) while unimplemented
- [ ] #4 just e2e, e2e-vm, measure, journey exist as stubs that exit 0 while printing '0 scenarios registered - NOT a pass' (commits stay unblocked); tasks 5/9/10/6 replace them with real gates and the stub state is forbidden after those close
<!-- AC:END -->
