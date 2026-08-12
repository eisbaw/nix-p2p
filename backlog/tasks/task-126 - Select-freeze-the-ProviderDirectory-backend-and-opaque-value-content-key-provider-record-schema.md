---
id: TASK-126
title: >-
  Select + freeze the ProviderDirectory backend and opaque-value
  content-key/provider-record schema
status: Done
assignee:
  - '@claude'
created_date: '2026-08-10 22:51'
updated_date: '2026-08-12 01:13'
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
2026-08-12 orchestrator re-scope: removed the runtime-DHT ACs (old #3 exact-key lookup, #5 bootstrap nodes, #7 cold multi-node test, #8 dht-core-v1 evidence) — they are redundant with TASK-103 (#3/#4/#5/#7/#10, the RUNNING adopted DHT) and the dht-core-v1 artifact is obsolete now we adopt not hand-roll. TASK-126 is now SPIKE + CODEC FREEZE only: freeze the peer-fabric ProviderRecord/ContentKey codec + golden vectors + fail-closed decode + record-validation rules, and decide primary/fallback backend. Freeze is safe even if the iroh-dht-experiment eval is inconclusive because libp2p-kad put_record guarantees opaque-value storage (the fallback); the spike refines primary vs fallback, it does not block the freeze.

## Implementation Plan (2026-08-12)

SPIKE (AC#5) — DONE, evidence-based, FLIPS primary/fallback:
- iroh-dht-experiment (github.com/n0-computer/iroh-dht-experiment) stores a FIXED
  typed `Value` enum { Blake3Provider, ED25519SignedMessage, Blake3Immutable }, NOT
  a generic opaque Vec<u8> store. Its opaque carriers bind the STORAGE KEY to the
  value: Blake3Immutable key MUST == blake3(data) (immutable, no refresh/sequence);
  ED25519SignedMessage key == SIGNER PUBKEY (keyed by provider identity, not by
  content); Blake3Provider is a bare {timestamp,node_id} (no offers/sig/sequence).
  None can key `content-derived ContentKey -> mutable multi-provider signed record`.
  Also experimental (validation TODO), data<=1024B.
  => DECISION: libp2p-kad put_record/get_record is PRIMARY freeze target (Record
  { key: arbitrary, value: opaque Vec<u8> } is exactly our model). iroh-dht-experiment
  = FALLBACK/future candidate (blocked today for our keying model). Freeze is SAFE
  regardless: our codec emits ContentKey -> signed opaque bytes; libp2p-kad guarantees
  opaque-value storage. 1024B record cap chosen to also fit iroh-dht-experiment's
  ED25519SignedMessage.data carrier, keeping the fallback viable if it matures.

FREEZE (AC#1-4):
- ContentKey::derive_from_signed_nar_hash = BLAKE3 derive_key(context="nix-p2p/discovery/ContentKey/v1", sha256 NarHash). DOMAIN-SEPARATED (opposite of Blake3Digest's plain-unkeyed recipe) + compile-assert + golden + namespace-mutation control + independent python-blake3 cross-check script.
- ProviderRecord/ProviderWithdrawal: versioned CANONICAL fixed-layout BINARY opaque value (record_codec.rs). Fields: version,kind,key,provider,seq,issued_at,expiry,[content,offers],sig64. ed25519 sig over domain||body; provider NodeId IS the verifying key (self-verifying). NO ip/port/relay/StorePath/unasked field possible (fixed layout).
- Fail-closed decode: Oversized/Malformed/TrailingBytes/UnknownVersion/UnknownKind/WrongKey/BadSignature/Stale/TooManyOffers, each a surgical negative test that BITES.
- Validation oracle (record_store.rs, salvaged FakeProviderDirectory logic): monotonic sequence, idempotent refresh, signed withdrawal, expiry, replay rejection, concurrent-provider merge, no expired/withdrawn resurrection.

FORWARD-CARRIED NOTES resolved: (1) key SSOT — keep record.key, sig binds it, decode rejects WrongKey vs storage key. (2) .content NOT redundant — content is BLAKE3 (fetch id), ContentKey derives from sha256 NarHash; asker cannot derive one from other, so content is LEARNED; keep. (3) privacy — routing-only nodes see only derived key; storing nodes learn content BLAKE3 (narrows not hides); full analysis = TASK-132.

New dep: ed25519-dalek 3 (already in lock via iroh; not a p2p stack). Gate + golden byte-pin + bite-proof before commit.

## FINAL SUMMARY — freeze complete (commits 0d67282 code, b6d34b4 lock, 14d5799 tracker)

FROZEN (byte-pinned, every rule bites, independently anchored):
- ContentKey::derive_from_signed_nar_hash = blake3::derive_key("nix-p2p/discovery/ContentKey/v1", sha256 NarHash); compile-assert + golden + one-byte namespace-mutation + cross-version controls.
- ProviderRecord/ProviderWithdrawal: canonical fixed-layout binary opaque value, ed25519 over SIGNING_DOMAIN(b"nix-p2p/discovery/ProviderRecord/v1\0")||body; provider NodeId IS the verifying key. decode_provider_assertion is fail-closed (11 typed rejections, each proven to bite by guard removal).
- record_store ProviderRecordSet oracle: monotonic seq, idempotent refresh (record + withdrawal), signed withdrawal, expiry, replay rejection, concurrent-provider merge, no resurrection.
- Goldens: peer-fabric/tests/golden/provider_record_v1.json + tests/provider_record_golden.rs (encode-emits/decode-accepts/reject); scripts/check-content-key-derivation.py = INDEPENDENT second impl (python blake3 derive_key + independent layout parse of every field + ed25519 verify), wired into `just test` and proven to bite.

SPIKE DECISION: iroh-dht-experiment exposes only fixed typed records (opaque carriers bind key to value-hash or signer-pubkey) -> cannot key content-derived ContentKey -> PRIMARY = libp2p-kad put_record/get_record; FALLBACK = iroh-dht-experiment. Freeze is backend-agnostic (opaque-value model).

FORWARD-CARRIED NOTES resolved: key SSOT (kept + sig-bound + WrongKey check); .content non-redundant (BLAKE3 fetch id vs sha256-derived key; LEARNED, kept); privacy (routing-only nodes see separate keyspace; storing nodes learn content; TASK-132 owns adversarial analysis).

REVIEW: qa-test-runner GREEN; mped-architect NO network-splitting blocker. All mped should-fix applied: (#1) hardened python anchor to independently PARSE the layout field-by-field (was self-referential); (#2) sign_* fail-fast on mismatched provider; (#3) provide_body offers-cap debug_assert on the signed preimage; (#4) version-consistency test; (#5) SIGNING_DOMAIN NUL-terminated per repo convention; (#6) softened "provably disjoint" wording; (#7) idempotent re-broadcast withdrawal. Forward-carried to TASK-103: (#8) durable monotonic sequence, (#9) per-key provider DoS cap, plus expiry-TTL MIN reconciliation and issued_at-informational.

GATES (actual): just build OK; just lint OK; just test OK (workspace 512 tests; peer-fabric 61 unit + 7 golden; check-content-key-derivation OK); just e2e ALL 5 scenarios PASSED (74.4s). Cross-model DEEP review remains the orchestrator's gate.

HONEST LIMITS: (a) unknown-offer-tag / new-transport is FAIL-CLOSED (versioned evolution, not tolerated) — deliberate for a signed opaque value, unlike the daemon claim wire. (b) The iroh-dht-experiment fallback fit is size-only-plausible (1024B carrier) but blocked by its keying model today; does not affect any frozen byte. (c) e2e is unaffected by this change (peer-fabric is consumed by nobody yet); the one earlier e2e failure was the pre-existing TASK-143-class flaky fixed-port bind in daemon/tests/iroh_node_lookup.rs, which passed on re-run.
<!-- SECTION:NOTES:END -->
