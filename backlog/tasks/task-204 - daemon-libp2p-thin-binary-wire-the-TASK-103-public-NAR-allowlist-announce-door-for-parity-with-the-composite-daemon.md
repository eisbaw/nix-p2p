---
id: TASK-204
title: >-
  daemon-libp2p (thin binary): wire the TASK-103 public-NAR allowlist announce
  door for parity with the composite daemon
status: To Do
assignee: []
created_date: '2026-08-14 15:43'
labels: []
dependencies:
  - TASK-103
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-103 wired the PUBLIC-announce allowlist door into the COMPOSITE daemon crate (daemon/src/main.rs), which is what the s7-libp2p container e2e runs (/bin/daemon). The per-backend thin binary daemon-libp2p/src/main.rs still uses lan_share_or_refuse only + PublicNarAllowlist::disabled(), so a bootstrapped daemon-libp2p provider REFUSES to announce (fail-CLOSED/SAFE, but no public participation). Mirror the composite wiring: the same flags (--libp2p-trusted-public-key / --libp2p-public-allowlist-path / --libp2p-prove-public-narinfo), build_public_allowlist, and route seed/store announces through announce_public_seeds / announce_public_provisions in PUBLIC mode. The shared lib door already exists in daemon-libp2p/src/lib.rs. Ideally de-duplicate the near-identical install_provider between the two binaries into the lib. No container e2e exercises daemon-libp2p today, so add a unit/integration check that a bootstrapped provider WITH an allowlist announces and WITHOUT one still refuses.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 daemon-libp2p bootstrapped provider announces its allowlisted content through the typed public door; with no allowlist it still refuses (fail-closed); the composite-daemon and thin-binary policies do not drift
<!-- AC:END -->
