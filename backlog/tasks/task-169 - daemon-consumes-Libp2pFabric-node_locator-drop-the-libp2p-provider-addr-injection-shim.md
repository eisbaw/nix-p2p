---
id: TASK-169
title: >-
  daemon consumes Libp2pFabric::node_locator - drop the --libp2p-provider-addr
  injection shim
status: Done
assignee:
  - mped
created_date: '2026-08-12 15:32'
updated_date: '2026-08-12 17:20'
labels:
  - libp2p
  - daemon
  - discovery
  - fabric
  - wave-2c
dependencies:
  - TASK-159
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-159 landed Libp2pFabric::node_locator (kad peer-routing resolves a provider PeerId -> dialable Multiaddr through the DHT). The daemon does NOT yet use it: source_libp2p.rs still takes provider_addrs (PeerId,Multiaddr) injected via the --libp2p-provider-addr CLI shim (main.rs:337/639), and the code comments mark this as 'the TASK-159 basic-dial shim: node_locator() is still None'. Now that node_locator exists, wire the daemon's setup_p2p_source / Libp2pNarSource to resolve a discovered provider's dial address via node_locator().locate() instead of the injected map, so the PRODUCTION path is fully decentralized (discover WHO via kad get_providers + resolve WHERE via kad peer-routing, zero injection). Keep --libp2p-provider-addr only as an explicit optional fallback/bootstrap hint (or remove it) - do not require it for a dial. Update the in-process production-path test (daemon/tests/libp2p_production_path.rs) so the daemon dials a provider it never had an injected address for. This is the precursor to TASK-161 (podman multi-daemon libp2p cold-journey e2e). Feature/LIGHT gate.
<!-- SECTION:DESCRIPTION:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Libp2pNarSource::resolve: per discovered record, call self.fabric.node_locator().locate(&record.provider, PublicInfrastructure) BEFORE trying the record's offers. locate() is the side-effecting consult - get_closest_peers populates the shared swarm's kad routing table with the provider's DHT-learned address, so the request-response fetch (same swarm) dials it with no injection. Found -> proceed to offers; Miss/Unavailable -> record last_failure + skip to next record (upstream fallback). node_locator()==None -> proceed (no regression for a locator-less fabric).
2. Libp2pSourceConfig.provider_addrs + --libp2p-provider-addr: demote to OPTIONAL override hint (no longer required for a dial). Keep the add_address loop in build_libp2p_nar_source as an override. Update ALL doc comments claiming node_locator() is None (source_libp2p.rs struct/builder, main.rs parse_libp2p_peer + startup print).
3. daemon/tests/libp2p_production_path.rs: set provider_addrs: vec![] (NEVER inject P's address); add a readiness poll on locate() (mirror node_locator_discovery.rs) so resolve()'s single locate Founds; keep HONEST-SCOPE note (no claim locate() is sole connectivity path; prove no-injection + resolve consulted node_locator). Assert discover->resolve->fetch->serve byte-identical + clean miss->upstream fallback.
4. Gate: cargo build -p daemon; just lint; cargo test -p daemon (esp libp2p_production_path); cargo test --workspace. Commit per green increment.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
DONE (reopened design implemented). The resolve-then-dial now lives INSIDE the fabric; the daemon no longer calls locate() and no longer relies on any locate side effect.

WHAT LANDED
- Libp2pTransport now holds Arc<Libp2pNodeLocator> (the SAME instance the fabric exposes on node_locator(), one shared ExposureLedger). Libp2pTransport::fetch, BEFORE fetch_nar, calls locator.locate(node, PublicInfrastructure); Found -> parse each DialInfo location back to Multiaddr and add_address(peer, addr) EXPLICITLY; Miss / Unavailable / Found-with-zero-parseable -> typed TransferError::Unavailable (fall through to next offer/record -> upstream). No silent dial on stale routing state.
- fabric.rs builds ONE Arc<Libp2pNodeLocator>, clones it into the transport and into the node_locator() axis (single source of truth; exposure accounting preserved, not re-threaded). Libp2pNodeLocator + node_locator() axis STAY (TASK-159).
- daemon/src/source_libp2p.rs resolve(): REMOVED the node_locator().locate() block. Daemon = discover (find_providers) -> for each record/offer -> transfer.fetch(). DialInfo never crosses the seam into the serving layer.
- Tests: fabric-libp2p/tests/nar_transport.rs reworked onto a shared-bootstrap DHT topology (the old bare 2-node add_address no longer resolves: get_closest_peers returns the target with no address unless a SHARED peer learned it via identify - this is the "basic dial shim" the task removes). node_locator_discovery.rs + libp2p_production_path.rs kept green; the latter's hit_delta==miss_delta+1 ledger oracle STILL holds and now bites the transport's locate on the shared ledger.

GATE (pinned dev shell, all ACTUAL): cargo build -p fabric-libp2p -p daemon = ok. just lint = ok (clippy -D + rustfmt + ruff + independence + source-guard). cargo test -p fabric-libp2p = 19 passed / 0 failed (nar_transport 6/6, node_locator_discovery 1/1, lib 11, decentralized_discovery 1). cargo test -p daemon = all suites 0 failed (libp2p_production_path 1/1). cargo test --workspace = green on re-run; one flake seen once: fabric-iroh iroh_node_lookup::tests::synchronous_replay_validation_cannot_return_success_after_absolute_deadline (10ms real-time deadline test, passes 5/5 in isolation, unrelated - fabric-iroh does not depend on fabric-libp2p/daemon).

REVIEW: mped-architect (Mark-emulator) + qa-test-runner both ran. QA all green. mped raised one BLOCKING honesty finding: provider_addrs override doc overclaimed. FIXED (commit c156eea): since the transport dials only off a successful resolution, provider_addrs (add_address) only seeds the local kad routing table and does NOT independently enable a dial to a provider the DHT cannot resolve; corrected the field + builder + in-body docs and pointed the real static per-peer dial override (ExplicitPeersOnly book) at TASK-168. Also softened the overstated transport sentence to match the honest-limit note.

HONEST LIMITS (do not overclaim)
- Loopback: add_address feeds the SAME shared kad routing table fetch_nar auto-dials off, so the byte path cannot attribute the dial to THIS resolution. Proven: no injection, resolution CONSULTED before every dial, typed fall-through on no-address. NOT proven: resolution is the sole/load-bearing dial mechanism (real-network proof carried to TASK-161).
- Resolution runs per-fetch (per-offer). libp2p is one offer per record today, so once-per-provider in practice.
- Transport hard-codes ResolutionPolicy::PublicInfrastructure (same as the old daemon path). Threading policy down + honouring an ExplicitPeersOnly static address book (so provider_addrs becomes a real transfer-honoured dial override, and a zero-disclosure explicit-peers fetch becomes possible) is TASK-168.

FORWARD-CARRIED to TASK-161 (real-network load-bearing proof): on a real multi-node (podman) network where the fetch cannot reuse a discovery connection, assert the DHT-resolved address is the load-bearing dial. AND drop --libp2p-provider-addr from the consumer container (provider_addrs should be empty in production; it is now only a kad-convergence seed, not a dial override).

COMMITS: edbb554 (core move), 1426b56 (nar_transport topology + truthful comments), c156eea (provider_addrs honesty + transport tightening). Committed, NOT pushed.
<!-- SECTION:NOTES:END -->
