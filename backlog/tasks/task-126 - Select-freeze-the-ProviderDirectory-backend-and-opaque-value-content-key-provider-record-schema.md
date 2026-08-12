---
id: TASK-126
title: >-
  Select + freeze the ProviderDirectory backend and opaque-value
  content-key/provider-record schema
status: In Progress
assignee:
  - '@claude'
created_date: '2026-08-10 22:51'
updated_date: '2026-08-12 02:05'
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
DEEP gate (Workflow wiba389dr) = NO_GO via cross-model codex (qa+mped were GO). Round-2 fixes required before this irreversible freeze counts. Freeze-blocking: (1) pin ed25519 canonicality policy + add malleable S+L negative vector; (2) canonicalize offer ordering (or explicitly pin order-significant + reject dup tags); (3) resolve provider-vs-offer-locator identity (require iroh offer node==provider, or document delegation; validate offer node is a valid point); (6) replace debug_assert! in provide_body with a real fail-closed check (release must not sign over-cap/>255 offers). Proof-hardening: (4) python anchor must reject unknown infohash versions {only 1,2}, parse no_offers, add a rejection vector; (5) golden rejection tests must assert the SPECIFIC typed error (not just is_err) with each vector's ONLY fault being the guard under test + a positive BitTorrent-v1 vector + BadInfoHash bite. Fixing #2/#3 may change frozen bytes/goldens - that is correct NOW (nothing consumes them; freeze is v1 pre-adoption).

## ROUND 2 - codex NO_GO (6 findings) resolved

Frozen POSITIVE bytes did NOT move (ContentKey unchanged 4e61db15...; full/no_offers/withdrawal wire unchanged - they were already canonical + self-serve). Added enforcement, new negative/positive vectors, and an independent decoder. peer-fabric: 67 unit + 8 golden; anchor: 4 records decoded + 7 rejects independently reproduced. build/lint/test/e2e (5/5, 74.9s) all green.

#1 Ed25519 canonicality/malleability -- FIXED + honest correction. codex's premise ("verify_strict only does the cheap S<2^253 check, would ACCEPT S+L") is OUTDATED for ed25519-dalek v3: I empirically confirmed v3 verify_strict ENFORCES S<L and REJECTS S+L (my first "load-bearing" test asserting verify_strict accepts S+L FAILED, proving dalek rejects). So the malleability was already foreclosed by the verifier. I nonetheless added an EXPLICIT signature_scalar_is_canonical (S<L) check with L pinned in-code -> distinct typed NonCanonicalSignature, version-independent, documents the policy for a second impl. DOCUMENTED the canonical-signature policy (S<L; cofactorless verify; reject small-order A/R). Added golden reject_malleable_signature (S+L) vector; python anchor re-derives L from RFC 8032 and rejects S>=L AND fails cryptography verify. Corrected all my round-1 false "load-bearing / dalek would accept" claims in code+docs.

#2 Non-canonical offer ordering -- FIXED (option a). Offers MUST be STRICTLY ASCENDING by wire encoding (forbids duplicates -> one signed encoding per set). encode rejects OffersNotCanonical; sign_* canonicalizes (sorts) + asserts no dups; decode rejects OffersNotCanonical. Bites: offers_out_of_canonical_order, duplicate_offers, golden reject_offers_not_canonical.

#3 provider-vs-offer identity -- FIXED. v1 iroh offers are SELF-SERVE: an iroh offer node MUST equal provider (decode -> IrohNodeNotProvider; encode + sign enforce). This transitively validates the node is a valid point (provider is validated, node==it). Delegation deferred to a later version, documented. Bites: iroh_offer_node_not_provider, golden reject_iroh_node_not_provider.

#6 provide_body debug_assert -> real assert! -- FIXED. The offers-cap narrowing is now a real assert! (release too); encode returns typed TooManyOffers before reaching it, so only the raw signing-bytes path can trip, and only on the signer's own over-cap input.

#4 python anchor -- FIXED (now a COMPLETE independent decoder). Accepts ONLY infohash versions {1,2} (was silently treating unknown as 32 bytes); parses ALL 4 positives (incl bittorrent_v1) asserting fields; INDEPENDENTLY re-derives every reject vector's fault and asserts it matches reject_reason; re-derives L from RFC 8032. Proven to bite by mutation (wrong reject_reason -> FAIL; wrong positive field -> FAIL). Missing vector/field -> KeyError or coverage-floor fail.

#5 golden reject tests -- FIXED. every_reject_vector_is_refused_for_its_named_reason asserts the SPECIFIC typed error (error_tag == reject_reason), not just is_err(). Each negative is re-signed so its ONLY fault is the guard under test (reject_wrong_version now re-signs the version-2 body, etc.). Added positive provider_record_bittorrent_v1 (byte-pinned) and a BadInfoHash bite.

New RecordDecodeError variants: OffersNotCanonical, IrohNodeNotProvider, NonCanonicalSignature. New RecordEncodeError: OffersNotCanonical, IrohNodeNotProvider. Every new guard has a biting test (disable it -> a test's exact-match fails).
<!-- SECTION:NOTES:END -->
