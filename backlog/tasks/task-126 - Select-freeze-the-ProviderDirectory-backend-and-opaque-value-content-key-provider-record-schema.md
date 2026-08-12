---
id: TASK-126
title: >-
  Select + freeze the ProviderDirectory backend and opaque-value
  content-key/provider-record schema
status: In Progress
assignee:
  - '@claude'
created_date: '2026-08-10 22:51'
updated_date: '2026-08-12 02:45'
labels:
  - iroh
  - discovery
  - dht
  - decentralized
  - cornerstone
  - implementation
  - blocking
  - wave-2c
dependencies:
  - TASK-114
  - TASK-115
  - TASK-140
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Implement the cornerstone decentralized exact-key discovery core now. Build a bounded Kademlia-style overlay carried over an explicit Iroh ALPN on the shared TASK-115 endpoint. The domain-separated NAR content key resolves to signed provider records containing Iroh NodeIds and bounded transport offers but no dialable addresses. Multiple configurable bootstrap NodeIds are allowed but no tracker registry server or single operator is required. This task owns the protocol codec routing record store and multi-node core proof; TASK-103 later wires it behind ContentDiscovery and TASK-102 gates real daemon publication.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Freeze versioned domain-separated NarHash-to-DHT-key and provider-record codecs with golden cross-version and one-byte namespace mutation vectors.
- [ ] #2 Provider records are signed by the provider Iroh identity and contain exact content key provider NodeId bounded transport offers sequence issued-at and expiry but no IP port relay address StorePath or unasked key.
- [ ] #3 Enforce monotonic provider sequence idempotent refresh explicit signed withdrawal expiry replay rejection concurrent-provider merge and no expired-record resurrection.
- [ ] #4 Requests responses provider counts record bytes routing buckets concurrency work amplification and deadlines are bounded and malformed bad-signature wrong-key unknown-version stale and oversized messages fail closed.
- [ ] #5 SPIKE GATE (first): decide the ProviderDirectory backend with evidence, not faith. Confirm the substrate can store an OPAQUE signed value (our ContentKey -> signed ProviderRecord bytes) so the frozen codec does NOT leak into the substrate's own record wire; if iroh-dht-experiment exposes only its typed records, libp2p-kad put_record/get_record becomes the freeze target and primary/fallback flips. Primary iroh-dht-experiment / fallback libp2p-kad; the in-progress hand-rolled Kademlia is salvaged as a FakeProviderDirectory in-memory test oracle, not shipped infra.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Re-gate round-2 (Workflow wsgcxn3uy): qa GO, codex NO_GO but confirms frozen bytes SOUND + all 6 prior findings resolved. Round-3 (FINAL freeze-proof hardening) queued: (1) fix release-red test (cfg-gate the debug-only assert; cargo test --release must be green); (2) python anchor must reject small-order A and R to match Rust verify_strict + add an identity-forgery reject vector exercised by BOTH impls + document the normative canonical-signature policy so a second implementation agrees; (3) golden error_tag must compare FULL typed error payload not variant name; (4) reject_iroh_node_not_provider must use a VALID alt ed25519 key (genuine offer!=provider). Positive frozen bytes must NOT change (codex confirms sound). After round-3: mark Done on GO, or accept-with-justification if only minor proof-nits remain (bytes sound across 3 rounds).

## ROUND 3 - codex proof-hardening (final) resolved

Frozen POSITIVE bytes verified BYTE-IDENTICAL (ContentKey 4e61db15...; full/no_offers/withdrawal/bittorrent_v1 wire unchanged - diffed old vs new before install). This round is oracle/test hardening only. peer-fabric: 68 unit (debug) / 67 (release) + 8 golden; anchor: 4 records decoded + 8 rejects independently reproduced (pure-python ed25519). build/lint/test/release/anchor/e2e (5/5, 74.3s) all green.

#1 RELEASE-RED -- FIXED. sign_helpers_reject_a_mismatched_provider_in_debug asserts a debug_assert! (off under --release). Gated it #[cfg(debug_assertions)]. `cargo test --release -p peer-fabric` now GREEN (67 lib + 8 golden).

#2 Python small-order acceptance split -- FIXED (blocker). Replaced the `cryptography` verify delegation with a FROM-SCRATCH pure-python ed25519 verifier (_ed25519_verify + _pubkey_from_seed): decompress, cofactorless [S]B = R + [k]A, reject small-order A AND R (8*P == identity), reject S>=L. Now no crypto library is trusted for the acceptance policy. Added reject_identity_forgery vector (provider A = small-order identity point 01||00x31, sig R=identity S=0 - a no-secret-key forgery). REJECTED by BOTH Rust golden (BadSignature, via verify_strict small-order-A) AND the python anchor. Documented the NORMATIVE canonical-signature policy (reject small-order A and R; cofactorless; S<L; the identity-forgery it prevents) in record_codec.rs module docs. Added inline Rust bite test identity_forgery_small_order_key_is_rejected. PROVEN TO BITE: disabling the python small-order check makes the anchor ACCEPT the forgery -> FAIL.

#3 Golden error_tag payload -- FIXED (major). provider_record_golden.rs now compares the FULL typed error format!("{:?}") against a per-vector reject_debug (e.g. "BadInfoHash { version: 3 }"), not just the variant name, so BadInfoHash{version:4} cannot satisfy a version-3 vector. Dropped the variant-only error_tag helper.

#4 Delegation vector -- FIXED (minor). reject_iroh_node_not_provider now uses a VALID alternate ed25519 key (alt_provider, seed 0x43) as the offer node, so it is a genuine single-fault (offer node != provider), not conflated with a malformed/undecompressible locator.

#5 Optional -- BOTH done. (a) The python anchor now HARD-FAILS if a `fields` entry is deleted (asserts the field key SET equals the exact schema per kind). (b) It mechanically asserts the committed malleable vector's S == positive full-record S + L.

Vectors changed: positives UNCHANGED (byte-identical). Negatives: added reject_identity_forgery; reject_iroh_node_not_provider now uses a valid alt key; reject_debug added to all 8 negatives; alt_provider_hex added to identities. 12 vectors total (4 positive + 8 reject). Every new/changed guard has a biting test in BOTH Rust and Python.
<!-- SECTION:NOTES:END -->
