---
id: TASK-103
title: >-
  Implement the selected ProviderDirectory backend (adopt iroh-dht-experiment /
  fallback libp2p-kad) behind the PeerFabric seam
status: To Do
assignee: []
created_date: '2026-08-10 10:04'
updated_date: '2026-08-12 01:06'
labels:
  - iroh
  - discovery
  - dht
  - decentralized
  - blocking
  - implementation
  - wave-2c
dependencies:
  - TASK-83
  - TASK-100
  - TASK-102
  - TASK-115
  - TASK-126
  - TASK-140
  - TASK-141
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Implement TASK-126s frozen decentralized exact-key content discovery behind ContentDiscovery. A query for one NAR identity returns bounded signed provider NodeIds and transport offers while tracker LAN and dialable-address resolution remain disabled. If Iroh has no native content DHT use the selected decentralized discovery substrate from TASK-126 while keeping Iroh NodeId identity transport and transfer. Unsupported or central-only behavior is a blocking failure rather than a completed capability. TASK-89 later resolves returned NodeIds to dialable locations and TASK-132 later proves the real-Nix journey.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Implement the frozen versioned NarHash-to-key and signed multi-provider record contract exactly and reject incompatible vectors versions signatures namespaces and malformed records.
- [ ] #2 All daemon-originated publication passes TASK-102 and unsigned private stale replayed expired or ineligible offers never enter accepted DHT state.
- [ ] #3 A cold run-unique multi-node test starts from absent content state and only provider daemons publish. Harness insertion prior rendezvous named candidates tracker and LAN invalidate evidence.
- [ ] #4 Exact-key lookup returns bounded provider NodeIds and transport offers with no IP port relay location or unasked holdings and preserves ContentDiscovery positional batch semantics.
- [ ] #5 At least three independently operated bootstrap or routing nodes are configurable. Loss of any one does not prevent an already admitted healthy network from resolving content and no single central service is required.
- [ ] #6 Tests cover concurrent providers idempotent refresh explicit withdrawal expiry restart replay rollback corrupted state partition and rejoin without lost updates or expired-record resurrection.
- [ ] #7 Return typed MISS only after a healthy completed lookup and typed UNAVAILABLE for bootstrap partition or dependency failure within the 15000 ms total deadline.
- [ ] #8 Resource tests enforce record provider request response storage concurrency rate and work bounds plus poisoning amplification Sybil and eclipse assumptions without compromising integrity.
- [ ] #9 Packet and source guards prove tracker LAN implicit public presets and out-of-band address injection are disabled during qualification. A mutation enabling any substitute makes the proof fail.
- [ ] #10 Emit decentralized-content-discovery-v1 verdict=pass bound to TASK-126 final tree manifests timings packet evidence and mutations. TASK-132 accepts no unsupported tracker-backed or fabricated substitute.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Mandatory production capability. There is no unsupported-completion branch. This task ends at content key to provider NodeId and offer resolution; TASK-89 owns NodeId to address and TASK-132 owns connection transfer and real-Nix proof.

Forward-carry from TASK-141 inc 1 (commit d01fb42): the shared value types are now single-sourced in the peer-fabric seam crate (peer_fabric::ids: NodeId, Blake3Digest incl the frozen BLAKE3(RawNarV1) recipe, TransportTag, InfoHash/TransportOffer; peer_fabric::content: ContentKey, ProviderRecord, DialInfo). The selected ProviderDirectory backend this task implements will live in the fabric-iroh crate (extracted by TASK-144), behind peer_fabric::ProviderDirectory, and construct into IrohFabric's Option<Arc<dyn ProviderDirectory>> field. It depends ONLY on peer-fabric value types - do not reach for daemon-internal types. NOTE: peer_fabric::content (ContentKey/ProviderRecord) is deliberately serde-FREE precisely so THIS task/TASK-126 choose the opaque-value codec against the adopted backend without a churn dep; the ids DO carry frozen serde codecs. Backend crate = fabric-iroh (peer-fabric + iroh + iroh-blobs), never in peer-fabric or daemon-core.

## Forward-carry from TASK-126 (the FROZEN codec you consume)

SPIKE DECISION (evidence-based, primary/fallback FLIPPED):
- iroh-dht-experiment stores a FIXED typed Value enum {Blake3Provider, ED25519SignedMessage, Blake3Immutable}, NOT a generic opaque store; each opaque carrier binds the key to value-hash or signer-pubkey, so it CANNOT store `content-derived ContentKey -> mutable multi-provider signed record`. => PRIMARY = libp2p-kad put_record/get_record (Record{key:arbitrary, value:opaque Vec<u8>}). FALLBACK = iroh-dht-experiment (blocked today; 1024B ED25519SignedMessage.data carrier could fit if it later grows content-keyed opaque values). Freeze is backend-agnostic: codec emits ContentKey->signed opaque bytes.

FROZEN RECIPE (do NOT re-derive; import from peer_fabric):
- ContentKey = blake3::derive_key("nix-p2p/discovery/ContentKey/v1", <32-byte sha256 signed NarHash>). Fn: ContentKey::derive_from_signed_nar_hash(&[u8;32]).
- ProviderRecord/ProviderWithdrawal opaque value: canonical fixed-layout binary, ed25519 sig over SIGNING_DOMAIN(b"nix-p2p/discovery/ProviderRecord/v1\0")||body; provider NodeId IS the verifying key (self-verifying).

DECODE / ENCODE ENTRY POINTS (peer_fabric public API):
- decode_provider_assertion(bytes, expected_key: &ContentKey, now: u64) -> Result<ProviderAssertion, RecordDecodeError>  [fail-closed: Oversized/Truncated/TrailingBytes/UnknownVersion/UnknownKind/UnknownOffer/BadInfoHash/TooManyOffers/BadProviderKey/BadSignature/WrongKey/Stale]
- encode_provider_record / encode_provider_withdrawal / encode_provider_assertion -> Result<Vec<u8>, RecordEncodeError>
- provider_record_signing_bytes / provider_withdrawal_signing_bytes (the exact preimage to sign with YOUR key material), sign_provider_record / sign_provider_withdrawal (convenience; overwrites provider with signer id, debug-asserts on mismatch).
- Validation oracle to wire behind ProviderDirectory: ProviderRecordSet::{apply(&assertion, now)->ApplyOutcome, find_providers(&key, now)->Vec<ProviderRecord>}. Salvaged FakeProviderDirectory-grade; enforces monotonic seq / idempotent refresh / signed withdrawal / expiry / replay / concurrent-provider merge / no resurrection.
- Bounds: MAX_PROVIDER_RECORD_BYTES=1024, MAX_OFFERS_PER_RECORD=4.

GOLDEN / EVIDENCE PATHS (re-freeze = network split; bump PROVIDER_RECORD_SCHEMA_VERSION / CONTENT_KEY_CONTEXT and move goldens):
- peer-fabric/tests/golden/provider_record_v1.json (byte-pinned wire + structured fields + content-key + mutation/cross-version)
- peer-fabric/tests/provider_record_golden.rs (encoder-emits + decoder-accepts + reject vectors)
- scripts/check-content-key-derivation.py (INDEPENDENT: python blake3 derive_key recompute + independent layout parse + ed25519 verify; wired into `just test`)

OBLIGATIONS YOU MUST HONOR (from TASK-126 deep review, NOT enforced by the frozen oracle):
1. DURABLE monotonic sequence per (key, provider): persist the counter (or derive from monotonic clock) or a provider restart is a self-inflicted RejectedStale outage.
2. PER-KEY PROVIDER CAP: providers-per-key is unbounded in the oracle; a shipped directory needs a DoS cap (a TASK-120/103 policy number).
3. RECONCILE expiry with the substrate record TTL: effective lifetime = MIN(record.expiry, store TTL) (AC#6).
4. Unknown offer tags / versions are FAIL-CLOSED by design; a genuinely new transport is a VERSIONED evolution, not a tolerated field.
5. issued_at is INFORMATIONAL; never order on it (sequence orders, expiry gates).
<!-- SECTION:NOTES:END -->
