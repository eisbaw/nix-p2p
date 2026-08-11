---
id: TASK-139
title: Iroh explicit relay transport capability
status: In Progress
assignee:
  - claude
created_date: '2026-08-11 06:01'
updated_date: '2026-08-11 23:03'
labels:
  - iroh
  - discovery
  - node
  - relay
  - transport
  - privacy
  - wave-2c
dependencies:
  - TASK-114
  - TASK-115
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Implement the explicit default-off relay transport capability for the shared TASK-115 endpoint. Configure a deliberate relay URL or map and expose direct hole-punched or relayed connection provenance. Do not publish or look up NodeId records discover content use LAN or select operator policy. This mandatory Iroh component must emit a passing iroh-relay-capability-v1 artifact for TASK-89; unsupported relay does not complete the task.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Relay is a separate typed default-off capability and no Iroh preset/default relay is inherited. Enabling it performs no DNS/pkarr publication, NodeId lookup or content lookup; disabling it produces zero relay packets. Source and packet mutations prove the boundary.
- [ ] #2 A configured local relay carries a real Iroh connection across routed namespaces where the direct path is deliberately blocked; the trace proves relay attribution. A direct-positive control stays direct and is not falsely credited to relay.
- [ ] #3 Relay connect has a 10000 ms total deadline. Relay outage, wrong URL/certificate/identity, half-open stream and forced direct-path failure remain distinct typed unavailable/path outcomes within the bound; monotonic tests allow at most 1000 ms scheduler grace.
- [ ] #4 Status/preflight records configured relay recipients, NodeId/IP exposure, authentication/trust, health and bytes without full NodeId/IP labels by default. Relay use never implies serving, node publication or a production default.
- [ ] #5 External n0/public relay contact, accounts, credentials, cost or infrastructure require a named owner and explicit authorization. Otherwise only a locally operated routed relay is used and evidence is labelled production-shaped.
- [ ] #6 Emit iroh-relay-capability-v1 verdict=pass with final tree evidence and configuration hashes plus all required direct forced-relay outage deadline privacy and mutation results. Unsupported no-go or ordinary defects keep TASK-89 and global qualification blocked.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
## Implementation Plan (TASK-139)

Reality check: the two template tasks (137 publication, 138 lookup) are each a ~2000-line routed podman evidence harness + ~100KB finalizer + new binaries + a nix docker image, producing the artifact from a REAL routed run. That full routed relay harness for iroh-relay-capability-v1 cannot be built AND given a real, verified routed run within one session without fabrication (the contract forbids a hand-written verdict=pass with no real routed run).

Scope this session (verifiable, deterministic, green):
1. daemon/src/iroh_relay.rs — the explicit default-off relay TRANSPORT capability building on the existing RelayCapability::Enabled(RelayMode). Concrete relay-mode SELECTION/EXPOSURE (RelayMode::Custom(RelayMap) built from a validated local relay URL; never inherits presets::N0 / RelayMode::Default). Typed authorization gate (LocalProductionShaped / ExternalAuthorized) mirroring iroh_node_lookup; ExternalAuthorized/public-n0 rejected -> local routed relay only, evidence labelled production-shaped. Typed RelayTransportUnavailable taxonomy (outage/wrong-url/wrong-cert/wrong-identity/half-open/forced-direct/deadline/...). RELAY_CONNECT_DEADLINE=10000ms, RELAY_SCHEDULER_GRACE=1000ms. Pure connection-path classifier (IncomingAddr -> Relayed/Direct) for attribution. Privacy-preserving preflight/status (no full NodeId/IP labels by default). Fully unit-tested.
2. Wire into lib.rs.

Deferred (BLOCKED, honest, filed as follow-up with dep edge -> this task):
- scripts/iroh_relay_capability_evidence.py + finalize_iroh_relay_capability.py, docs schema + md, artifacts/iroh-relay-capability-v1.json, the local relay-server + relay-client binaries, the nix docker image, and the REAL routed run that blocks the direct path at L3 and proves relay attribution + direct-positive control. This is AC#2 (routed attribution proof), AC#6 (artifact), AC#5 (production-shaped label in artifact), and the evidence-binding of AC#1/#3/#4.

Gate before commit: just build / lint / test all green with real numbers.

## Progress (session 1) — cornerstone landed, artifact BLOCKED (leaving In Progress)

Committed 5f750cc: daemon/src/iroh_relay.rs + lib.rs re-exports. Full gate GREEN (build, lint incl. clippy -D + rustfmt + ruff + independence + source-guards, test: 14 new iroh_relay unit tests + 224-pass daemon lib suite). Reviewed by mped-architect + qa-test-runner; qa GREEN, architect's one BLOCKING item fixed pre-commit.

### Per-AC status
- AC#1 (default-off, no preset inherited, no publish/lookup/content on enable): PARTIAL-MET in code + unit tests (RelayTransportConfig only ever builds RelayMode::Custom; test local_routed_relay_selects_a_custom_map_not_an_n0_default asserts none of RelayMode::Default's URLs leak; module has no publish/lookup/content/LAN code path). The routed zero-relay-packet / packet-mutation EVIDENCE is deferred (TASK-142).
- AC#2 (routed real relayed connection across L3-blocked namespaces + direct-positive control): BLOCKED. Pure attribution primitive (classify_connection_path) shipped + tested, but the real routed run is TASK-142. In-process attribution is deliberately NOT claimed: iroh's remote_addr lives on Connecting/Accepting, an established Connection can upgrade relay->direct after holepunch, and loopback cannot block the direct path — so strong "relay carried it" attribution genuinely requires the L3-blocked routed harness.
- AC#3 (10000ms deadline, distinct typed outcomes, monotonic + 1000ms grace): PARTIAL. Constants + full typed taxonomy shipped; the deadline is NOT yet enforced by a live connect path (no producer for most kinds). Enforcement + the typed-failure matrix run are TASK-142.
- AC#4 (privacy status/preflight, no full NodeId/IP by default): MET in code + strengthened oracle (asserts a known peer NodeId hex + peer IP are absent from the status dump). Note: relay_recipient may be the daemon's OWN configured relay IP literal — that is the daemon's own relay, not a peer; the invariant is about peer identities.
- AC#5 (external n0/public needs named owner + explicit authz; else local routed only, labelled production-shaped): MET at config layer (ExternalAuthorized records a redacted reference then returns ExternalRelayUnsupported; LocalProductionShaped rejects public hosts; n0 markers rejected). The evidence LABEL in the artifact is TASK-142.
- AC#6 (emit iroh-relay-capability-v1 verdict=pass bound to a REAL routed run): BLOCKED — not produced. A hand-written verdict=pass with no routed run is forbidden; not faked.

### Why the artifact is blocked (precise cause — NOT a missing kernel capability)
The environment CAN create rootless-podman internal networks (verified). The blocker is SCOPE/honesty, not capability: the template harnesses (scripts/iroh_node_lookup_evidence.py ~2000 lines + finalize ~95KB; the publication pair similar) are each a multi-file infrastructure with a nix docker image and new daemon binaries (relay server + relay client). Building that AND giving it a real, verified routed run cannot be honestly completed in one session. Filed as TASK-142 (dep edge -> 139; referenced in iroh_relay.rs module doc).

### Debt from mped-architect review (fold into TASK-142)
- N2 (SSOT): ip_is_public in iroh_relay.rs duplicates iroh_node_lookup.rs::is_public_ip byte-for-byte; owner 1..=128 validation and a hand-rolled hex are also duplicated. NOT extracted this commit to avoid destabilising the DONE node-lookup module right before commit. TASK-142 (or a small refactor task) should extract a shared iroh net-policy helper both import. Security direction confirmed sound (fails closed; no public addr accepted as local).
- N1/N3: 9/12 typed kinds and both deadline constants have no producer yet (speculative seam, sanctioned interface-first). TASK-142 must PRODUCE these (real outage/wrong-cert/wrong-identity/half-open/forced-direct/deadline arms) or prune them; #[non_exhaustive] + stable as_str tokens mitigate drift.
- N5: host_is_local_only allow-list omits .internal and .home.arpa (RFC 8375) and rejects real internal FQDNs (split-horizon). Fails closed (safe) but the error advertises a suffix set missing the two commonest private conventions. Consider adding .internal/.home.arpa in TASK-142.

### Rejected approaches
- In-process real relayed-connection integration test via iroh test_utils::run_relay_server (feature "test-utils" is available): rejected as an AC#2 proof because loopback cannot block the direct path, so it would prove "a relay connection established" but NOT relay attribution — the exact thing AC#2 demands. Left to the routed harness. (Also avoids pulling a hyper-based relay server into daemon dev-deps + Cargo.lock churn.)
<!-- SECTION:NOTES:END -->
