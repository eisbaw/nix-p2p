---
id: TASK-164
title: >-
  libp2p compressed-narinfo raw-serve decoupling: HIT serves raw bytes a real
  Nix client rejects
status: To Do
assignee: []
created_date: '2026-08-12 11:27'
labels:
  - libp2p
  - daemon
  - correctness
  - raw-serve
  - blocking
  - wave-2c
dependencies:
  - TASK-162
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
BLOCKING correctness gap found in TASK-162 review (mped-architect). For iroh, the raw-serve allowlist (AllowlistRawServe, task-49) and discovery are BOTH seeded from --p2p-claim, so discovery-hit <=> allowlist-hit: the daemon serves RAW p2p bytes ONLY for a NarHash whose narinfo it rewrote to raw (Compression: none, FileHash=NarHash, FileSize=NarSize) - compression domains match, a real Nix client accepts. For libp2p, discovery is DYNAMIC (kad find_providers) while the raw-serve allowlist is EMPTY (no libp2p claim flag). server.rs::respond_narinfo records the token->(NarHash,NarSize) correlation on the NON-rewritten path too (server.rs ~314), so a compressed narinfo (served verbatim, still Compression: xz) has its token correlated -> GET /nar/<token> becomes NarKey::SignedNarHash -> Libp2pNarSource serves the RAW NAR -> raw bytes under an xz narinfo -> a real Nix client's FileHash/FileSize/decompress gate REJECTS them. So a libp2p-only production node serves un-usable bytes for any compressed upstream (the norm). The in-process TASK-162 test masks it (NoRawServe + a plain HTTP client asserting raw==raw, not a Nix client). FIX OPTIONS: (a) a DYNAMIC raw-serve decision that probes the provider directory at narinfo time (rewrite to raw iff a p2p provider is discoverable), or (b) gate Libp2pNarSource to fail-closed (clean miss -> HTTP fallback) when the correlated narinfo was compressed (needs the compression domain plumbed to the NarSource seam), or (c) decompress-on-serve. Likely folds into the clean daemon-core split (TASK-145/146). Add a compression-aware oracle (a Nix-client-style FileHash/decompress check, or an explicit non-modeling disclaimer) to the libp2p e2e. BLOCKS the podman libp2p e2e (TASK-161) using compressed fixtures and the cold journey (TASK-132) with a real Nix client.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 libp2p HIT never serves bytes whose compression domain disagrees with the narinfo the client received
- [ ] #2 an oracle bites by mutation: a Nix-client-style FileHash/Compression check (or documented non-modeling) covers the libp2p serve path
<!-- AC:END -->
