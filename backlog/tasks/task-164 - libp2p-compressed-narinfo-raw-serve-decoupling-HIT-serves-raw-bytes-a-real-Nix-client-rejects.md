---
id: TASK-164
title: >-
  libp2p compressed-narinfo raw-serve decoupling: HIT serves raw bytes a real
  Nix client rejects
status: Done
assignee:
  - '@claude'
created_date: '2026-08-12 11:27'
updated_date: '2026-08-12 12:25'
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

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Root cause: raw_serve (RawServeDecision) is built ONLY from iroh --p2p-claim (static AllowlistRawServe). libp2p discovery is DYNAMIC (kad find_providers), so a libp2p HIT under a compressed (xz) upstream narinfo is NOT in the allowlist -> narinfo served verbatim (Compression: xz) while the correlated GET /nar/<token> resolves via Libp2pNarSource to RAW bytes -> a real Nix client rejects (FileHash/Compression mismatch).

Fix (option a: dynamically couple the libp2p discovery HIT to the narinfo rewrite, mirroring how iroh's static claim allowlist couples to its discovery):
1. rewrite.rs: make RawServeDecision::will_serve_raw ASYNC (#[async_trait]). The decision "will I serve raw" was always an availability question; async lets it consult the network. Update NoRawServe + AllowlistRawServe. Add AnyRawServe combinator (serve raw iff ANY inner decision says so; short-circuits).
2. source_libp2p.rs: add Libp2pRawServe { fabric, discovery_budget } impl RawServeDecision: probe the SAME kad find_providers as resolve()'s discovery leg; true iff Found & non-empty. build_libp2p_nar_source ALSO returns the Libp2pRawServe (one builder -> source + its raw-serve from ONE fabric+budget, so they cannot drift).
3. server.rs: await the decision.
4. main.rs setup_p2p_source: compose raw_serve = AnyRawServe(iroh AllowlistRawServe, libp2p Libp2pRawServe) so a libp2p HIT triggers the same task-49 rewrite. Iroh-only and pure-HTTP paths unchanged.

Invariant restored: libp2p-serves-raw(h) <=> narinfo-rewritten-to-raw(h), both gated on the same find_providers probe. TOCTOU (provider vanishes narinfo->nar) fails closed: rewrite-to-raw then miss -> 502 -> nix falls back (same as AllowlistRawServe's documented dead-holder behaviour). No corruption.

Pass bar test (new tests/libp2p_raw_serve.rs): COMPRESSED upstream narinfo (xz, FileHash!=NarHash, NarHash = REAL sha256 of the raw NAR), libp2p HIT -> narinfo rewritten to raw, served bytes ACCEPTED by a modeled Nix client (gate1 sha256(served)==FileHash & len==FileSize; gate2 decompress-none sha256==NarHash & len==NarSize). Oracle bites by mutation: proves it REJECTS the raw bytes under the ORIGINAL compressed narinfo. MISS arm: narinfo byte-verbatim (xz). Iroh path proven unchanged by existing narinfo_rewrite.rs + s6-p2p e2e 5/5.

Known follow-ups: probe = 2 kad lookups per served path (narinfo + nar); discovery-outcome caching deferred (TASK-163). Compose precedence unchanged.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Green + Done. A libp2p HIT now rewrites the upstream narinfo to declare the raw NAR it serves (Compression:none, FileHash/FileSize = raw), mirroring the iroh allowlist path; passthrough stays byte-verbatim. Root fix in daemon/src/rewrite.rs (to_raw/RawServeDecision) wired through server.rs + source_libp2p.rs.
Gate (orchestrator-verified): cargo build -p daemon exit 0; just lint GREEN; cargo test --workspace = 49 test-binaries ok / 0 failed; new bar daemon libp2p_raw_serve 1/1 (compressed-narinfo -> raw), narinfo_rewrite 1/1, passthrough 3/3, libp2p_production_path 8/8; just e2e = 5 scenarios PASS incl s6-p2p 11/11 (iroh peer-served real nix build stayed green -> no serving-layer regression). Provenance in git notes ref=verification on 51c70c3.
Commits: a3dec79 (code) + 51c70c3 (tracker).
<!-- SECTION:NOTES:END -->
