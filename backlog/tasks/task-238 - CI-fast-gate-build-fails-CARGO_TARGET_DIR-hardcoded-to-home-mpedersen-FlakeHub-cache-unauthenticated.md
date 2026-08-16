---
id: TASK-238
title: >-
  CI fast-gate build fails: CARGO_TARGET_DIR hardcoded to /home/mpedersen;
  FlakeHub cache unauthenticated
status: Done
assignee:
  - '@claude'
created_date: '2026-08-16 19:45'
updated_date: '2026-08-16 20:04'
labels:
  - ci
  - tooling
  - portability
  - blocker
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The GitHub Actions fast-gate (TASK-230) is RED. Two issues, from run 31956611176 (master @ c2c0e1e). (1) BLOCKER: flake.nix:525 sets CARGO_TARGET_DIR = /home/mpedersen/.cache/nix-p2p-target - the author home path, baked into the devShell - so every cargo invocation on any other machine/user fails: error: failed to create directory /home/mpedersen/.cache, Permission denied (build recipe exit 101). The Justfile reclaim recipe hardcodes the same path. FIX: make it portable - HOME-based (set in the shellHook where bash expands, e.g. export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-$HOME/.cache/nix-p2p-target}) or repo-relative; update the reclaim recipe to match; keep the persistent out-of-tree target intent. Verify the local dev build still works + CI would build. (2) SECONDARY (non-blocking, continue-on-error): the FlakeHub Cache action cannot authenticate (Unable to authenticate to FlakeHub; the repo is not registered at FlakeHub.com), so it is pure noise with no cache benefit. FIX: either drop flakehub-cache-action for the plain GitHub Actions cache path, or gate it behind a registered-account condition. e2e + audit jobs are GREEN; only the fast-gate build blocks. Do NOT weaken the gate to make it pass - fix the portability.
<!-- SECTION:DESCRIPTION:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
TASK-238 progress: (1) flake.nix - removed hardcoded CARGO_TARGET_DIR="/home/mpedersen/.cache/nix-p2p-target" env attr; now set portably in devShell shellHook via export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-$HOME/.cache/nix-p2p-target} (export only, no echo, respects no-spammy-shellHook rule). (2) scripts/reclaim.sh - candidate list now falls back to $HOME/.cache/nix-p2p-target when CARGO_TARGET_DIR unset, so just reclaim clears the shared dir off-shell too. (3) .github/workflows/ci.yml - removed the always-erroring FlakeHub Cache step from all 4 jobs + dropped the now-unused id-token:write permission; kept Determinate Nix installer; builds fall back to cache.nixos.org. Local verify: fresh nix develop resolves CARGO_TARGET_DIR to /home/mpedersen/.cache/nix-p2p-target (HOME-based, existing cache preserved); just build running.

TASK-238 DONE (pending owner review). Verified: fresh nix develop resolves CARGO_TARGET_DIR to /home/mpedersen/.cache/nix-p2p-target (HOME-based; existing warm cache reused, no cold rebuild). just build succeeded inside nix develop: Finished dev profile in 6m36s, exit 0. Committed 0b525e2 (3 files: flake.nix, scripts/reclaim.sh, .github/workflows/ci.yml), author Mark Ruvald Pedersen, no AI/co-author credit, not pushed. FlakeHub: removed the always-erroring flakehub-cache-action step from all 4 CI jobs + dropped the now-unused id-token:write permission; kept the Determinate Nix installer; builds fall back to cache.nixos.org (correctness over cache speed, no external account needed). Gate recipes unchanged (build/lint/test/commit-msg/audit/e2e/vm all still run via just). HONEST: CI-green is UNPROVEN until the workflow actually runs on push/PR - cannot execute GitHub Actions locally.

DONE (LIGHT gate, orchestrator-verified). Commit 0b525e2. flake.nix: CARGO_TARGET_DIR moved from a hardcoded /home/mpedersen env attr to a portable shellHook export (${CARGO_TARGET_DIR:-$HOME/.cache/nix-p2p-target}) - fixes the CI fast-gate build Permission-denied. scripts/reclaim.sh fallback made explicit. ci.yml: removed the always-erroring flakehub-cache-action (repo unregistered) from all jobs, kept the Determinate Nix installer, no gate weakened. Verified: no hardcode remains, resolves portably, just build green. HONEST: CI-green unproven until it runs on the next push (user owns pushing).
<!-- SECTION:NOTES:END -->
