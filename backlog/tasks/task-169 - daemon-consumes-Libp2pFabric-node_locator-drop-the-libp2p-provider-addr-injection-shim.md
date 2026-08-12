---
id: TASK-169
title: >-
  daemon consumes Libp2pFabric::node_locator - drop the --libp2p-provider-addr
  injection shim
status: Done
assignee:
  - mped
created_date: '2026-08-12 15:32'
updated_date: '2026-08-12 15:54'
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
DONE. The daemon production path resolves a provider's dial address via node_locator (kad peer-routing); the --libp2p-provider-addr injection shim is no longer required for a dial.

COMMITS (on master, base 94e2dd0/TASK-159): a3bc9f9 (resolve wires node_locator + doc updates), 378ecbe (test: zero-injection + locate readiness oracle), 48186ce (test: exposure-ledger HIT-vs-MISS oracle), eb812bc (review hardening F2+F4).

WHAT CHANGED:
1. Libp2pNarSource::resolve (daemon/src/source_libp2p.rs): per discovered record, calls self.fabric.node_locator().locate(&record.provider, PublicInfrastructure) BEFORE its offers. locate() is the side-effecting consult - get_closest_peers teaches the shared swarm kad routing table the provider address (a shared bootstrap learned it via identify), so the request-response fetch on the SAME swarm dials with ZERO injection. Miss/Unavailable -> record last_failure + skip record -> clean upstream fallback (S2). node_locator()==None -> proceed unchanged (seam generality; Libp2pFabric always Some).
2. --libp2p-provider-addr / Libp2pSourceConfig.provider_addrs DEMOTED to optional override hint (kept, not removed = lower-risk per task; F3 tracks convergence into TASK-168 ExplicitPeersOnly). --libp2p-bootstrap still required. ALL doc comments claiming node_locator() is None updated (source_libp2p flow+struct+builder; main.rs parse_libp2p_peer + startup print).
3. daemon/tests/libp2p_production_path.rs: provider_addrs=[] (P address NEVER injected). Oracles: (a) locate() readiness poll asserts the DHT-resolved addr carries P's REAL listen addr (no-injection proof); (b) exposure-ledger EXACT delta hit==miss+1 proves resolve CONSULTED node_locator.

CRITICAL GOTCHA (mutation-characterized, honest limit carried from TASK-159 into TASK-161 F1): in a small loopback kad the fetch REUSES a connection an earlier discovery query opened to P, so the byte-path HIT serves byte-identical EVEN IF resolve skips locate() (verified: bypassing locate -> byte test still passes 3x). The byte arms do NOT bite the resolve->locate consult; the exposure-ledger delta oracle is what does (find_providers records a provider-count-INDEPENDENT 2, locate 1; HIT=3, MISS=2). Whether locate()'s ROUTING-TABLE SIDE EFFECT is the load-bearing dial mechanism is UNPROVABLE on loopback and is a NAMED RISK carried to TASK-161 (real multi-container e2e is where to verify it) - see F1 below. resolve DISCARDS locate()'s returned DialInfo (seam returns OPAQUE strings; seam-level code cannot reparse them) and relies on the side effect.

REVIEW (mped-architect + qa-test-runner, LIGHT tier, both green): F2 (oracle tightened to exact hit==miss+1 + pinned the find_providers-records-2 assumption) FIXED in eb812bc. F4 (terminal Unreachable no longer misframes an unlocatable skip as an offer failure) FIXED in eb812bc. F1 (MEDIUM/HIGH: locate side-effect coupling unprovable on loopback + silent-degradation risk) carried to TASK-161. F3 (provider_addrs = untested second injection channel) carried to TASK-168 for convergence into ExplicitPeersOnly.

GATES (ACTUAL): cargo build -p daemon exit 0; just lint exit 0 GREEN (clippy -D + rustfmt + ruff + independence + source-guard, zero findings); cargo test -p daemon libp2p_production_path 1/1 (stable 5/5 per QA); cargo test --workspace exit 0, 50 test-binaries ok / 0 failed (node_locator_discovery 1, daemon lib 128 + main 28). Mutation re-verified against the exact oracle (hit=2 miss=2 trips). NAT traversal explicitly OUT OF SCOPE (TASK-168). Not faked.
<!-- SECTION:NOTES:END -->
