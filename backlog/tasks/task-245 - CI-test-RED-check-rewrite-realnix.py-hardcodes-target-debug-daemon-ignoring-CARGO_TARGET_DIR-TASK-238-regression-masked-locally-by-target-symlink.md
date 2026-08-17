---
id: TASK-245
title: >-
  CI test RED: check-rewrite-realnix.py hardcodes target/debug/daemon, ignoring
  CARGO_TARGET_DIR (TASK-238 regression; masked locally by target symlink)
status: Done
assignee: []
created_date: '2026-08-17 18:04'
updated_date: '2026-08-17 20:04'
labels:
  - ci
  - tooling
  - scripts
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
CI (fast gate, test step) is RED: `just test` -> scripts/check-rewrite-realnix.py FAILS with "target/debug/daemon missing". ROOT CAUSE: check-rewrite-realnix.py:228 hardcodes `daemon_bin = repo / "target" / "debug" / "daemon"`, ignoring $CARGO_TARGET_DIR. TASK-238 made CARGO_TARGET_DIR portable ($HOME/.cache/nix-p2p-target); on a dev box a `target`->cache symlink masks the hardcode, but the CI runner has no symlink so the binary is at $CARGO_TARGET_DIR/debug/daemon and the hardcoded path is missing. e2e + build + lint all pass; only this Python oracle in the test step fails. FIX: mirror the TASK-54 pattern already in shaped_compress.py:109 -- `target_dir = Path(os.environ.get("CARGO_TARGET_DIR") or (repo / "target")); daemon_bin = target_dir / "debug" / "daemon"`. Grep ALL scripts for other repo/target or "target"/"debug" hardcodes and fix comprehensively (check-rewrite-realnix.py is the one CI hit; verify no siblings). Non-invasive; add a one-line note that a dev-box target symlink can mask this locally. Verify by running with CARGO_TARGET_DIR set to a non-target path and NO symlink.
<!-- SECTION:DESCRIPTION:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
DONE (LIGHT). Fixed check-rewrite-realnix.py:228 + shaped_libp2p.py:55 + shaped_kad.py:53 to honour CARGO_TARGET_DIR (mirror shaped_compress.py TASK-54 pattern), fall back to in-tree ./target. Verified: ruff clean; check-rewrite-realnix.py rc=0 resolving the daemon via CARGO_TARGET_DIR. CI test step (just test line 221) should now go green on next push. Not pushed.
<!-- SECTION:NOTES:END -->
