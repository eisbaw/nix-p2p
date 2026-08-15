---
id: TASK-224
title: >-
  Unknown-KIND transport offer can name content identities on the wire
  (no-enumeration residual; forward-compat tension)
status: To Do
assignee: []
created_date: '2026-08-15 20:17'
labels:
  - irreversible
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
codex DEEP gate (TASK-110 re-gate) proved with an executable probe that a SINGLE unknown-KIND offer smuggles content identities the asker never named and is ACCEPTED (decoded to empty, but accepted on the wire): {"transport":"future_bulk","content_ids":["blake3:bbbb...","blake3:cccc..."]}. ROOT: the tolerate-but-drop deserializer reads ONLY the transport tag and discards the rest as an opaque serde_json::Value (deserialize_known_transports ~daemon-core/src/claim.rs:409-431 for the single-key/Claim path, deserialize_transport_slots ~claim.rs:692-714 for the batch path). deny_unknown_fields rejects extra fields inside a KNOWN transport, but an unknown KIND is accepted-and-dropped - the exact also_held enumeration defect the KNOWN-transport rule at claim.rs:332 forbids, on the unknown-KIND path. This is a real no-enumeration-invariant gap (PRD privacy invariant, no-enumeration section) and it is SHARED by the single-key (decode_hold_response) and batch (decode_batch_hold_response) paths - PRE-EXISTING in both, NOT introduced by TASK-110 (TASK-110 closed only the KNOWN-offer count/enumeration, <=1 identity per transport kind). NOT the same as TASK-223 (per-offer byte cap): codex showed a byte cap still permits several SHORT identities in one opaque slot. THE TENSION to resolve: accept an unknown FUTURE transport opaquely (forward compat, AC#4 of TASK-110) while forbidding it from naming content identities. Candidate approaches: constrain an unknown-kind offer object to a whitelisted minimal shape (transport tag + at most one bounded SCALAR locator field), or reject unknown-kind offers whose body contains any array / nested object / digest-shaped string. This is a further FROZEN decoder-acceptance narrowing -> DEEP/irreversible. Parity + residual pinned by daemon-core/src/claim.rs::an_unknown_kind_offer_still_carries_content_ids_on_the_wire_on_both_paths.
<!-- SECTION:DESCRIPTION:END -->
