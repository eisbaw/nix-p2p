---
id: TASK-234
title: >-
  No supply-chain advisory gate (cargo-deny/cargo-audit) in the dev shell or
  Justfile
status: To Do
assignee: []
created_date: '2026-08-16 10:20'
labels:
  - supply-chain
  - hardening
  - tooling
dependencies: []
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Surfaced by TASK-214 (added rand=0.8 as a direct edge; it resolved to already-present 0.8.7, but NO formal advisory scan could be run). cargo-deny and cargo-audit are not in the nix dev shell and there is no just audit recipe, so new/updated deps ship without an advisory/license/ban check. AC: add cargo-deny (or cargo-audit) to the dev shell, add a just audit recipe, wire it into the gate cadence (BROAD gate / pre-commit), and add a deny.toml with the project's license+advisory policy. Relates to TASK-230 (determinate-nix CI, which per its hard constraint must call only Justfile recipes - so a just audit recipe is a prerequisite there too).
<!-- SECTION:DESCRIPTION:END -->
