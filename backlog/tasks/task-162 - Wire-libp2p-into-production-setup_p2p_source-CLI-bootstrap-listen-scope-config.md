---
id: TASK-162
title: >-
  Wire libp2p into production setup_p2p_source (CLI bootstrap/listen/scope
  config)
status: Done
assignee:
  - '@claude'
created_date: '2026-08-12 10:22'
updated_date: '2026-08-12 11:42'
labels:
  - libp2p
  - daemon
  - integration
  - wave-2c
dependencies:
  - TASK-160
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Follow-up to TASK-160. The Libp2pNarSource seam piece exists and is proven through the serving stack (daemon/src/source_libp2p.rs), but production main.rs setup_p2p_source (daemon/src/main.rs:~1041) still builds ONLY the iroh source. Add CLI/config (libp2p bootstrap peers, listen addr, network scope, discovery/announce budgets, fetch envelope) so the binary can construct a Libp2pFabric + Libp2pNarSource and compose it into the FallbackNarSource chain additively (iroh path intact). Precursor is really the clean daemon-core/two-binary split (TASK-145/146); this interim wiring enables the podman libp2p e2e.
<!-- SECTION:DESCRIPTION:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. CLI config (main.rs hand-rolled parser, mirroring --iroh-peer style): --libp2p-bootstrap <PeerId@multiaddr> (repeatable), --libp2p-provider-addr <PeerId@multiaddr> (repeatable, TASK-159 basic-dial shim), --libp2p-listen <multiaddr>, --libp2p-scope <str>, --libp2p-identity-seed <64hex> (optional; else /dev/urandom). Unit test for parse. Commit.
2. Lib seam in source_libp2p.rs: pub Libp2pSourceConfig + pub async build_libp2p_nar_source -> (Arc<Libp2pFabric>, Arc<dyn NarSource>): start fabric, listen, add_address+dial+bootstrap each bootstrap peer, add_address each provider-addr, wrap in Libp2pNarSource. main.rs setup_p2p_source builds Libp2pSourceConfig from Config and composes: libp2p PRIMARY -> iroh (if configured) -> HTTP upstream (nested FallbackNarSource). iroh path intact/additive. Commit.
3. Integration test daemon/tests/: stand up B+P libp2p nodes (TASK-160 harness pattern), drive C through the PRODUCTION build_libp2p_nar_source from a Libp2pSourceConfig, serve byte-identical NAR via spawn_app; MISS fallback arm. Commit.
Gate before each commit; e2e once at end (iroh s6-p2p 5/5). Follow-ups: iroh<->libp2p compose precedence + libp2p raw-serve (TASK-145/146), podman e2e (TASK-161).
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
LANDED (code commits, separate from tracker md; no Cargo.lock change - fabric-libp2p was already a normal dep):
- 64d0779 daemon: wire libp2p source into production setup_p2p_source (CLI config). Adds --libp2p-bootstrap/--libp2p-provider-addr (repeatable <PeerId@multiaddr>), --libp2p-listen <multiaddr>, --libp2p-scope <str>, --libp2p-identity-seed <64hex> to the hand-rolled parser (mirrors --iroh-peer style). New lib seam source_libp2p::{Libp2pSourceConfig, build_libp2p_nar_source}: starts Libp2pFabric, listens, add_address+dial+kad-bootstrap each bootstrap peer, add_address each provider dial addr (TASK-159 basic-dial shim), wraps in Libp2pNarSource. setup_p2p_source composes libp2p PRIMARY -> iroh -> HTTP upstream via nested FallbackNarSource; signature transport: IrohTransport -> Option<IrohTransport> so a libp2p-only node runs with NO iroh runtime. 6 parse unit tests.
- 94e82f2 daemon: integration test daemon/tests/libp2p_production_path.rs. Drives C through the PRODUCTION build_libp2p_nar_source from a Libp2pSourceConfig (bootstrap=B, provider dial addr=P, listen, scope) - the exact seam main.rs calls. C (only B configured) discovers P via kad (record kad-produced NOT injected; asserts discovered==P signed record), fetches raw NAR, gate-1 BLAKE3, daemon serves BYTE-IDENTICAL (0 upstream fallbacks); un-announced NarHash -> clean kad miss -> HTTP fallback (1 fallback).

GATE (inside nix develop, ACTUAL numbers):
- just build: green (cold rebuild 3m51s).
- just lint: green (clippy -D workspace + evidence-fixture, independence self-test 10/2, HTTP denylist 18 crates, fmt --check, source-guard 107 .rs, lock-sources).
- just test: workspace green EXCEPT known pre-existing flake fabric-iroh iroh_node_lookup::synchronous_replay_validation_cannot_return_success_after_absolute_deadline (passed in isolation; TASK-84/108/160 timing-oracle family, NOT my change). New: 6 parse unit tests pass; production-path integration test passes (1/1, ~1.1s).
- just e2e: 5/5 scenarios PASS incl s6-p2p 11/11 (iroh path intact, no regression). No podman pod / background job left running.

DESIGN DECISIONS / HONEST LIMITS:
- Compose precedence (documented in setup_p2p_source): libp2p PRIMARY -> iroh -> HTTP upstream, nested FallbackNarSource (clean miss/Unreachable falls through; TooLarge propagates). Whether libp2p-first is RIGHT (vs a transport tournament/dual-stack race) is deferred to the clean daemon-core split (TASK-145/146) - filing a compose follow-up.
- raw-serve allowlist still keyed ONLY on iroh p2p_claims; libp2p-served paths resolve via the SignedNarHash correlation and get NO task-49 raw rewrite (matches TASK-160's NoRawServe). Unifying raw-serve across backends is part of the compose follow-up.
- Production-path COVERAGE split: the CLI parse (flags->Config) is unit-tested in main.rs; the config->running-source construction is the integration test via the shared lib seam build_libp2p_nar_source. The two together cover the production path; there is NO single test that runs the literal binary argv->serve (main.rs::from_args is binary-private). Honest.
- NAT still injected (provider dial addr out-of-band via --libp2p-provider-addr) per TASK-159; node_locator() is None. Discovery is the decentralized part.
- No test asserts the iroh+libp2p BOTH-configured composition (only libp2p-only path is integration-tested); filed as a gap in the compose follow-up.

REVIEW ROUND (qa-test-runner + mped-architect, both reproduced all gates green independently; codex-cadence not triggered this cycle):
- Both converged on ONE material gap: the precedence/composition in setup_p2p_source was an un-probed inline decision (oracle didn't bite by mutation - swapping libp2p/iroh layers would pass every test). FIXED (f01332e): factored into pure compose_nar_chain(libp2p, iroh, upstream); unit tests drive it with fake sources asserting libp2p->iroh->HTTP order + each-layer-optional, so a layer swap/drop now fails a test.
- mped #6 idempotency: libp2p_source_config() minted /dev/urandom entropy per call (shared-identity footgun). FIXED: seed resolved ONCE in from_args, stored in Config; libp2p_source_config() is now a pure read. Idempotency test added.
- mped #3 bootstrap dial resilience: was fatal on the FIRST dial error; a bootstrap set is plural for resilience. FIXED: fatal only when EVERY bootstrap dial fails; partial failures logged.
- mped #4 + qa #3 honesty/coverage: softened the 'polled by the caller' comment (test-only) and the 'wired' log -> 'started, discovery converging'; added asserts that the PRODUCTION default DiscoveryBudget/SafetyEnvelope are non-degenerate.
- mped #1 (MAJOR correctness, elevated by mped): libp2p's DYNAMIC kad discovery is decoupled from the iroh-claim-keyed AllowlistRawServe. server.rs::respond_narinfo records the token correlation on the NON-rewritten path too, so a compressed upstream narinfo (served verbatim, still Compression: xz) has its token -> NarKey::SignedNarHash -> Libp2pNarSource serves the RAW NAR -> a real Nix client REJECTS raw bytes under an xz narinfo. iroh is safe (discovery-hit <=> allowlist-hit, both from --p2p-claim); libp2p has no such coupling. The in-process test masks it (NoRawServe + plain HTTP client asserting raw==raw). FILED as BLOCKING TASK-164 (blocks TASK-161 podman e2e w/ compressed fixtures + TASK-132 cold journey w/ real Nix); documented in code + the integration test doc-comment. NOT fixed this cycle: a robust fix (dynamic raw-serve, or compression domain plumbed to the NarSource seam) is a serving-layer change out of this cycle's bounded scope and risky to the iroh e2e - honest deferral, not a workaround.

FINAL GATE (all inside nix develop, ACTUAL, on the review-fix commit f01332e):
- just build: green. just lint: green (clippy -D workspace+evidence-fixture, independence, source/lock guards, fmt). just test: green - main.rs 28 tests incl 8 libp2p (6 parse + idempotent + compose) + 2 compose-precedence; production-path integration test 1/1 (~1.1s); no flake this run.
- just e2e: 5/5 PASS incl s6-p2p 11/11 (84.8s) - iroh intact after the compose refactor. No podman pod / container / background job left running.

COMMITS (code, separate from tracker/lock; no Cargo.lock change): 64d0779 (wiring+CLI), 94e82f2 (integration test), f01332e (review fixes).
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Production setup_p2p_source now builds a working libp2p decentralized NarSource from CLI config (interim both-backends wiring ahead of the daemon-core split TASK-145/146). Added libp2p Node-A flags (--libp2p-bootstrap/-provider-addr/-listen/-scope/-identity-seed) to the hand-rolled parser; a lib seam source_libp2p::{Libp2pSourceConfig, build_libp2p_nar_source} starts a Libp2pFabric (listen + bootstrap dial/kad self-lookup + TASK-159 basic-dial shim) and wraps it in Libp2pNarSource; a pure compose_nar_chain nests it as PRIMARY ahead of iroh -> HTTP upstream (iroh path untouched/additive; libp2p-only runs with no iroh runtime). PROVEN by an integration test driving the exact production builder from a Libp2pSourceConfig: consumer configured with only a bootstrap peer DISCOVERS the provider via libp2p-kad (record kad-produced, not injected), fetches the raw NAR, gate-1 BLAKE3-verifies, serves byte-identical (0 upstream fallbacks); un-announced NarHash -> clean kad miss -> HTTP fallback. Plus 8 parse/idempotency + 2 compose-precedence unit tests. Gate green (build/lint/test); iroh e2e 5/5 incl s6-p2p 11/11 (no regression). Commits 64d0779/94e82f2/f01332e. HONEST LIMITS: (1) BLOCKING correctness gap TASK-164 - libp2p's dynamic kad discovery is decoupled from the iroh-claim-keyed raw-serve allowlist, so a libp2p HIT under a compressed upstream narinfo serves RAW bytes a real Nix client rejects; blocks the podman libp2p e2e (TASK-161) and cold journey (TASK-132) until fixed. (2) iroh<->libp2p compose precedence (libp2p-first) is provisional - TASK-163. (3) NAT still injected: provider dial addr out-of-band per TASK-159 (node_locator None); discovery is the decentralized part. (4) No libp2p SERVING daemon CLI path yet (consumer only) - TASK-146. (5) Both-backends composition is unit-tested via compose_nar_chain but not end-to-end. Forward-carried to 132/161/163/164.
<!-- SECTION:FINAL_SUMMARY:END -->
