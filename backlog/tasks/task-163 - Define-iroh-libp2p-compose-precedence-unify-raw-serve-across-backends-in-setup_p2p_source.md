---
id: TASK-163
title: >-
  Define iroh<->libp2p compose precedence + unify raw-serve across backends in
  setup_p2p_source
status: To Do
assignee: []
created_date: '2026-08-12 11:00'
labels:
  - libp2p
  - iroh
  - daemon
  - compose
  - wave-2c
dependencies:
  - TASK-162
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Follow-up to TASK-162, which wired libp2p as the PRIMARY p2p NarSource ahead of iroh -> HTTP upstream via nested FallbackNarSource (a provisional precedence chosen at the integration site). Two open questions this task resolves: (1) is libp2p-first the RIGHT composition when BOTH backends are configured, or should it be a transport tournament / dual-stack race (see TASK-156 distinct Libp2p offer on the frozen wire)? TASK-162 added NO test for the both-configured path (only libp2p-only is integration-tested) - add one. (2) The raw-serve allowlist (task-49 compressed rewrite) is still keyed ONLY on iroh p2p_claims; libp2p-served paths resolve via the SignedNarHash correlation and get NO raw rewrite. Unify raw-serve across both backends (or document why libp2p needs none). Likely folds into the clean daemon-core/two-binary split (TASK-145/146) where the interim both-backends link is deleted.
<!-- SECTION:DESCRIPTION:END -->
