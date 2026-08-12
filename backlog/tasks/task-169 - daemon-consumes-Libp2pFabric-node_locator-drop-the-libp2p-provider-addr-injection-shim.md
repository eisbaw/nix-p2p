---
id: TASK-169
title: >-
  daemon consumes Libp2pFabric::node_locator - drop the --libp2p-provider-addr
  injection shim
status: In Progress
assignee:
  - mped
created_date: '2026-08-12 15:32'
updated_date: '2026-08-12 16:57'
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
REOPENED design (owner: no side effects). Implementation:
1. Libp2pTransport now holds Arc<Libp2pNodeLocator> (the SAME instance the node_locator() axis exposes - single source, shared ExposureLedger). In fetch(), BEFORE fetch_nar: locator.locate(node, PublicInfrastructure); Found -> parse each DialInfo location back to Multiaddr and add_address(peer, addr) EXPLICITLY (DHT-resolved, not injection); Miss/Unavailable/zero-parseable -> typed TransferError::Unavailable (fall through to next offer/record -> upstream). Exposure (OurNodeId->DhtNode) recorded by the reused locator, not re-threaded.
2. fabric.rs assemble: build one Arc<Libp2pNodeLocator>, clone into both the transport and the node_locator() axis. Libp2pNodeLocator + node_locator() STAY (TASK-159).
3. daemon source_libp2p.rs resolve(): REMOVE the node_locator().locate() block; daemon goes back to discover(find_providers) -> for each record/offer -> transfer.fetch(). DialInfo never reaches the serving layer. Update stale doc comments.
4. Tests stay green. Ledger oracle in libp2p_production_path.rs (hit_delta == miss_delta+1) STILL holds: the +1 OurNodeId disclosure just moves from daemon into the transport's fetch (same shared ledger); MISS still bails at find_providers before any fetch. Update stale comments that said resolve() calls locate.
HONEST LIMIT preserved: loopback DHT can reuse an earlier query's connection, so byte-path arms alone do not prove resolution is load-bearing; carry real-network proof to TASK-161.
<!-- SECTION:NOTES:END -->
