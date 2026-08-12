---
id: TASK-178
title: >-
  daemon: expose a libp2p SERVING/provider mode (announce + serve NARs over
  libp2p from store/seed)
status: Done
assignee:
  - mped
created_date: '2026-08-12 21:21'
updated_date: '2026-08-12 21:49'
labels:
  - libp2p
  - daemon
  - serving
  - fabric
  - core
  - wave-2c
dependencies: []
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-161 (multi-daemon libp2p e2e) needs a daemon that can be the PROVIDER container, but the daemon only CONSUMES via libp2p today: build_libp2p_nar_source uses Libp2pFabric::start() (no supplier), and nothing in daemon/src wires Libp2pServer / Libp2pAvailabilityAnnouncer / a supplier. This is the SERVING half of the libp2p primary path and it is missing. Expose it via CLI, mirroring the iroh serving mode (--iroh-provider / --iroh-seed-nar / --iroh-print-peer-address in daemon/src/main.rs): a --libp2p-provider (or equivalent) mode that starts Libp2pFabric::start_with_supplier(config, supplier) with a supplier serving the seeded/store NAR(s), calls .server().serve(budget) to install the serve gate, and .announcer().announce(record) for each served ContentKey so a consumer can discover it via kad. Reuse fabric-libp2p's Libp2pNarSupplier/MemoryNarSupplier + the serving APIs proven in fabric-libp2p/tests/node_locator_discovery.rs (start_serving_node). Add --libp2p-seed-nar (like --iroh-seed-nar) and/or wire the AvailabilityIndex (see TASK-83 for the iroh /nix/store analogue) + a --libp2p-print-peer-address for the harness to read the provider's PeerId+listen addr. This is a CORE capability (rung 2), not hardening. Deps: TASK-151 (libp2p NarServer/transfer), TASK-103 (announcer/directory).
<!-- SECTION:DESCRIPTION:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Extract start_and_join_libp2p + wrap_consumer_source in source_libp2p.rs (SSOT for connectivity); add build_libp2p_provider_source (start_with_supplier).
2. Daemon CLI: --libp2p-provider, --libp2p-seed-nar <narhash>=<path> (repeatable), --libp2p-print-peer-address; companion validation (seed/print require provider; provider requires >=1 seed + listen + bootstrap).
3. install_libp2p_provider: MemoryNarSupplier from seed files, ServeBudget reused from --iroh-max-* knobs (with the same footgun guards), serve gate, sign+announce a ProviderRecord per seed (ContentKey from NarHash, content=BLAKE3 raw), print LIBP2P-PROVIDER-ADDR/SEED/SERVE-BUDGET. One fabric serves AND consumes.
4. Keep serve gate + fabric alive via Libp2pProviderGuard held by main.
5. Add ed25519-dalek as normal dep (record signing).
6. Test: in-process provider (daemon flags path) + consumer (build_libp2p_nar_source) via shared bootstrap; consumer discovers via kad (no injection) + fetches byte-identical.
7. Gate: build -p daemon, just lint, cargo test -p daemon, cargo test --workspace.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
IMPLEMENTED (commit 38d5d5b). Provider mode works + discover->fetch integration proves it.

FLAGS ADDED (mirror iroh provider):
  --libp2p-provider                       enable serving mode
  --libp2p-seed-nar <narhash>=<path>      raw NAR to serve+announce (repeatable). NarHash REQUIRED: discovery ContentKey a consumer derives from a narinfo is derive_from_signed_nar_hash(NarHash); provider must announce under that same key, and the raw file alone does not carry it (unlike --iroh-seed-nar whose NarHash comes from node A's --p2p-claim).
  --libp2p-print-peer-address             print LIBP2P-PROVIDER-ADDR for a harness.
Companion validation: seed/print require --libp2p-provider; --libp2p-provider requires >=1 seed + --libp2p-listen + --libp2p-bootstrap.

WHAT IT DOES: install_libp2p_provider() builds a MemoryNarSupplier from the seed files, starts build_libp2p_provider_source (start_with_supplier + join), installs the serve gate under the daemon serve budget, and announces a SIGNED ProviderRecord per seed. ONE fabric serves AND consumes (the provider builder returns the same fabric's consumer source), so no second same-identity swarm. Serve gate + fabric held alive by Libp2pProviderGuard in main.

PRINTED CONTRACT (stdout): 'LIBP2P-PROVIDER-ADDR peer_id=<PeerId> listen=<addr1,addr2>' (when --libp2p-print-peer-address); 'LIBP2P-SEED narhash=.. content=<blake3hex> content_key=.. bytes=..' per seed; 'LIBP2P-SERVE-BUDGET max_nar_bytes_uncompressed_nar=.. max_inflight_bytes_uncompressed_nar=.. max_serve_duration_ms=..'.

TEST (daemon/tests/libp2p_provider_path.rs, PASSES): provider stood up via the lib provider builder serves+announces; consumer built by build_libp2p_nar_source, told ONLY the bootstrap (provider_addrs empty), discovers via kad, resolves the provider's REAL listen addr via peer-routing (no injection), and resolve() returns byte-identical bytes. Plus main.rs unit tests for the flags + companion validation.

GATE (actual): cargo build -p daemon = ok; just lint = ok (all green incl clippy -D warnings, independence, source-guard); cargo test -p daemon = ok (all binaries 0 failed; lib 138 passed incl 4 new CLI tests; new provider test 1 passed); cargo test --workspace = ok on a clean run (54 test-binary 'ok' lines, 0 failed). NOTE: one earlier --workspace run had a single load flake in daemon/tests/iroh_runtime.rs:688 offline_runtime_has_only_loopback... (asserts 2 loopback sockets); PASSES in isolation + on clean re-run; unrelated to this change (no libp2p code path touches iroh socket binding).

FROZEN: peer-fabric/ 0 lines in diff. The frozen record codec is CONSUMED (sign_provider_record) not changed.

GOTCHAS:
  * ServeBudget type collision: daemon::ServeBudget (transport_iroh) and peer_fabric::ServeBudget are DISTINCT types with identical fields; NarServer::serve wants the peer_fabric one - construct peer_fabric::ServeBudget explicitly.
  * daemon re-exports transport_iroh's MemoryNarSupplier; use fabric_libp2p::MemoryNarSupplier explicitly for the libp2p supplier.
  * Provider announce is ONE-SHOT at startup and needs a non-empty kad routing table; build_libp2p_provider_source now WAITS (bounded 20s) for routing_peers>=1 before returning, else announce fails Unavailable(InsufficientRouting). Consumer path does NOT wait (it retries find_providers).
  * ed25519-dalek promoted dev->normal dep (already in closure) to mint records.

FOLLOW-UPS (filed as forward note on TASK-161): backend-specific --libp2p-max-* serve-budget knobs (currently reuses --iroh-max-*); AvailabilityIndex-from-/nix/store provider (TASK-83 analogue) instead of explicit seed files.
<!-- SECTION:NOTES:END -->
