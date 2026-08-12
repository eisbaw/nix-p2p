---
id: TASK-162
title: >-
  Wire libp2p into production setup_p2p_source (CLI bootstrap/listen/scope
  config)
status: In Progress
assignee:
  - '@claude'
created_date: '2026-08-12 10:22'
updated_date: '2026-08-12 11:00'
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
<!-- SECTION:NOTES:END -->
