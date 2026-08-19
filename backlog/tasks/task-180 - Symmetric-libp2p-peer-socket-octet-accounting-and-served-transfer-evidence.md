---
id: TASK-180
title: Symmetric libp2p peer-socket octet accounting and served-transfer evidence
status: To Do
assignee: []
created_date: '2026-08-12 23:03'
updated_date: '2026-08-19 16:50'
labels:
  - libp2p
  - daemon
  - e2e
  - wave-2c
  - measurement
dependencies:
  - TASK-179
  - TASK-219
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Build independent symmetric peer-byte evidence for the libp2p path at two explicitly named boundaries. First, provider and requester Nar-stream instrumentation records application transfer payload/control only when successful reads/writes cross the metered libp2p transfer protocol. Second, the isolated E2E network namespace captures actual peer-connection/interface octets per direction and connection provenance, including transport, security, mux, relay, and control overhead that application instrumentation cannot decompose. Raw NarSize, queued/materialised buffers, attempted writes, interface totals without connection attribution, and one endpoint inferred from the other are not evidence.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Provider and requester independently emit monotonic application-transfer read/write octets and completed/aborted transfer counts keyed by bounded run-local connection/transfer provenance; counters advance only by successful read/write results, with checked overflow and no StorePath/NarHash/full NodeId labels.
- [ ] #2 A scenario-isolated network-namespace capture attributes actual peer connection/interface octets independently at provider and requester by declared endpoint/connection provenance and direction. Background, DHT, relay, transport/security/mux, and transfer traffic are retained or explicitly classified; whole-interface totals without attribution fail.
- [ ] #3 The report retains peer_socket_total_bytes_compressed_wire, peer_socket_payload_bytes_compressed_wire, peer_socket_protocol_control_bytes_compressed_wire, payload_bytes_uncompressed_nar, and application raw-NAR octets as distinct observations. Control is never computed as total minus payload when framing attribution is unavailable; it is recorded unknown with a reason.
- [ ] #4 The positive real-Nix libp2p arm requires nonzero independently observed provider upload and requester download, requester peer-source attribution, exact signed NarHash, and zero/reduced upstream payload. A raw fixture where values happen to coincide cannot derive one field from another.
- [ ] #5 A mid-stream disconnect mutation records only successfully crossed octets on each side, marks the transfer aborted, and cannot count it as a completed peer delivery. A pre-send bytes.len(), attempted-write, or mirrored-endpoint meter fails the oracle.
- [ ] #6 TASK-247 and TASK-237 consume the symmetric machine-readable evidence with direction, transport, codec, confirmed path, capture/config hashes, and missing-attribution reason codes; normal operator status remains bounded-cardinality and privacy-safe.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
The former ServeGate bytes.len() turnkey design is superseded and intentionally removed: it measured produced uncompressed NAR bytes before send. Implement both metered transfer events and isolated connection/interface capture; neither substitutes for the other.

256 DOWNSCOPE 2026-08-19 (COMPASS): 180 largely feeds the synthetic value-thesis chain (237/247) that TASK-256 pre-empted and that is now Low. Symmetric octet accounting has some standalone wire-honesty value but is not out-of-box-critical; priority->Low, revisit if a served-transfer accounting gap surfaces on the shipped path.
<!-- SECTION:NOTES:END -->
