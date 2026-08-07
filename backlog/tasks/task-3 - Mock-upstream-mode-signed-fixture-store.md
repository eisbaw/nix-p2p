---
id: TASK-3
title: Mock upstream mode + signed fixture store
status: To Do
assignee: []
created_date: '2026-08-07 21:55'
labels: []
dependencies:
  - TASK-2
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Test proxy standalone mode: serve a generated fixture set (small store closures) with narinfos signed by a TEST ed25519 keypair, so client nix.conf trusts only the test key (TESTING.md signing policy: require-sigs stays on, always). Includes the fixture generator (nix copy --to file:// + sign, or equivalent) producing a few closures incl. one large NAR for kill-mid-transfer scenarios.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Mock serves nix-cache-info/narinfo/nar for fixture closures; a container nix client with the test public key substitutes them successfully with require-sigs enabled
- [ ] #2 Fixture set includes a NAR large enough (>=100MB) for mid-transfer kill tests
- [ ] #3 Tampering test: flip one byte in a fixture narinfo signature field; client MUST reject (bite test)
<!-- AC:END -->
