---
id: TASK-230
title: >-
  Add GitHub Actions CI using Determinate Nix (run the flake gate on push/PR;
  scope e2e + nat-vm-test explicitly)
status: To Do
assignee: []
created_date: '2026-08-16 04:45'
updated_date: '2026-08-16 04:46'
labels:
  - ci
  - tooling
  - infra
  - github
dependencies: []
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Add GitHub Actions CI for eisbaw/nix-p2p using Determinate Nix, so pushes/PRs run the project gate on the remote (today there is NO CI; assurance is the local gate + the codex review gate, and a green LOCAL gate is not proof of a green pipeline).

HARD CONSTRAINT (owner, 2026-08-16): the GitHub Actions workflow YAML must invoke ONLY justfile recipes - i.e. every gate step is `just <recipe>` (after the Determinate Nix install/cache setup steps). NO raw cargo / nix / clippy / python / ruff commands in the workflow. All gate logic lives in the Justfile so CI and a local run are byte-for-byte the same command surface; a developer can reproduce any CI failure with the identical `just` recipe locally. If CI needs a check that is not yet a recipe, ADD it as a Justfile recipe (or an aggregate like `just ci` composing the existing lint/test/fmt) rather than inlining it in YAML.

WHY DETERMINATE NIX: DeterminateSystems/nix-installer-action installs Nix fast with flakes + nix-command enabled by default (this repo is flake-based: flake.nix has devShell, checks, e2e-image, and a nat-vm-test), and pairs with a Determinate cache action (magic-nix-cache / FlakeHub Cache, whichever is current Determinate guidance) to cache the Rust/Nix build closure so CI is not a cold rebuild every run. The install + cache steps are the ONLY non-`just` steps allowed; the gate itself is `just` recipes.

WHAT TO RUN (all via `just` recipes, matching the local gate):
- Fast job (github-hosted ubuntu runner): the existing recipes - `just fmt`, `just lint`, `just test` - which already cover cargo fmt --check, clippy -D warnings + ruff + independence/source guards, cargo test workspace, and (fold in if not already) the standalone guards check-no-floats.py, check-discovery-no-shortcut.py --self-test, check-golden-vectors.py. If a `just ci` aggregate is cleaner, add it. `nix flake check` may be wrapped as a recipe too if wanted, but the step is still `just <recipe>`.
- Enforce the repo commit-msg policy (the hook rejects AI/co-author credit) in CI, via a recipe, so a bypassed local hook is still caught.

HEAVY SUITES - SCOPE EXPLICITLY (still via `just`), do not silently skip and call CI green:
- `just e2e`: needs rootless podman + packet-capture caps; may need a privileged or self-hosted runner. Decide: run on github-hosted (if caps work), a separate/optional job, or defer - and STATE in the workflow + task which gates CI actually covers vs not (honest-gate discipline; e2e + nat-vm-test are the integration oracles, so their absence must be visible, not implied-covered).
- nat-vm-test (nixos/nat-vm-test.nix, 6-VM NixOS test): needs /dev/kvm; heavy/slow. Wrap as a `just` recipe if not already, and decide per-push vs nightly (schedule) vs on-demand (workflow_dispatch); note runtime.
- Mind the _headroom disk guard (test/e2e fail-fast below a free-space floor); CI runners have limited disk - the Determinate cache + a `just reclaim`/prune step may be needed (also a recipe).

Reference: repo git@github.com:eisbaw/nix-p2p.git; gate recipes in the Justfile (lint/test/fmt/e2e, _headroom, reclaim); flake checks + e2e-image + nat-vm-test in flake.nix.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A GitHub Actions workflow runs on push and PR to master; every GATE step is a justfile recipe invocation (just <recipe>) - the ONLY non-just steps permitted are the Determinate Nix install + cache setup. No raw cargo/nix/clippy/python/ruff in the YAML; a CI failure is reproducible locally by the identical just recipe.
- [ ] #2 The fast gate (fmt, lint, test + the no-floats/discovery-shortcut/golden guards, folded into existing or a new just recipe) runs green on a github-hosted runner using the Determinate Nix installer + cache; local and CI command surfaces are identical.
- [ ] #3 The heavy suites (just e2e; nat-vm-test) are scoped EXPLICITLY - either run (github-hosted or self-hosted) or deferred to a separate/scheduled/on-demand job - and the workflow states clearly which gates CI covers vs does not; CI is never reported green while silently skipping an integration oracle.
- [ ] #4 If a required check is not yet a justfile recipe, it is ADDED as one (or an aggregate like just ci), never inlined in YAML.
<!-- AC:END -->
