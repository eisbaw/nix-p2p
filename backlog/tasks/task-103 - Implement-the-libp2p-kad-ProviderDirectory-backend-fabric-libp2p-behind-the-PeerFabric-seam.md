---
id: TASK-103
title: >-
  Implement the libp2p-kad ProviderDirectory backend (fabric-libp2p) behind the
  PeerFabric seam
status: In Progress
assignee:
  - '@claude'
created_date: '2026-08-10 10:04'
updated_date: '2026-08-12 07:58'
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

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
KAD-MAPPING DECISION: HYBRID (provider-records for the multi-provider SET + opaque value store for the per-provider signed record).

Why not pure opaque-value (put_record at key=ContentKey): libp2p-kad MemoryStore holds ONE value per key per node, and all put_records for a ContentKey converge on the SAME k-closest nodes, so provider B's put overwrites provider A's -> multi-provider (AC#5/#6 concurrent providers) is structurally broken. get_record cannot return a multi-provider set.

Why not pure provider-records (start_providing/get_providers alone): get_providers returns PeerIds only, no offers/sequence/expiry/signature, and the frozen ProviderRecord must be learnable WITHOUT the provider online (AC#6). Insufficient by itself.

HYBRID (chosen):
- announce = start_providing(RecordKey=ContentKey bytes) for the multi-provider INDEX (native TTL/republish, exact-key, no enumeration) + put_record(RecordKey=derive_key('nix-p2p/libp2p-kad/provider-record-value/v1', ContentKey||PeerId.to_bytes()) -> frozen encode_provider_record bytes). One provider per composite key => no collision; stored on k-closest => learnable offline (AC#6).
- find_providers = get_providers(ContentKey) -> {PeerId}; for each PeerId, get_record(composite) -> decode_provider_assertion(value, expected_key=ContentKey, now) with FROZEN codec (self-verifying ed25519, SSOT key check, expiry). Collect Vec<ProviderRecord>.
- Lookup arms: Found=non-empty healthy hit; Miss=healthy get_providers empty with populated routing table; Unavailable=InsufficientRouting (empty kbuckets) / DeadlineExceeded (budget elapsed) / bootstrap/partition.
- Node identity = the provider ed25519 key: libp2p ed25519 Keypair built from the same 32 secret bytes that sign the record, so NodeId(verifying key)==provider and PeerId corresponds. Composite key uses PeerId.to_bytes() (returned by get_providers) so the resolver needs no ed25519<-PeerId extraction.

Honors the frozen seam rationale (signed record in the value store, learnable offline) while adding get_providers ONLY as the multi-provider index the value store cannot provide without enumeration. request-response (TASK-151) is the online alternative for carrying the record; value-store is primary for offline-learnability.

Increments (commit each green): 1) crate skeleton builds; 2) directory+announcer+swarm worker compiles; 3) >=3-node decentralized test (Found/Miss/Unavailable, no injection); 4) Libp2pFabric exposes directory (transport=TASK-151 None).
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
ELEVATED to critical-path PRIMARY 2026-08-12 (owner: libp2p-primary): libp2p-kad ProviderDirectory in fabric-libp2p is THE mandatory decentralized content-discovery cornerstone. get_providers/start_providing storing the frozen ContentKey->signed ProviderRecord (TASK-126) as an opaque value. Discovery is libp2p-kad regardless of which transport (libp2p or iroh) a build uses. Pair with TASK-151 (libp2p transport) to make daemon-libp2p a full pure-libp2p product.

---

CORNERSTONE CORE LANDED (increments, each committed green under just build/lint/test):
- 106360a fabric-libp2p crate skeleton (empty lib + libp2p 0.54 deps: kad,tcp,quic,identify,request-response,tokio/macros,noise,yamux) + f548b99 lock.
- ff82f09 kad-backed Libp2pProviderDirectory + Libp2pAvailabilityAnnouncer + Libp2pFabric:PeerFabric (directory+announcer exposed; transport/locator/serve/hold/LAN = None -> TASK-151).
- 0677f51 multi-node decentralized-discovery test + 79e23f2 lock. 4 in-process nodes (bootstrap B, router R, provider P, consumer C); R/P/C know ONLY B; P announces, C resolves P through the DHT with NO injected answer (get_providers -> per-provider get_record -> frozen decode_provider_assertion; asserts provider==P, key SSOT, record==announced). MISS + UNAVAILABLE both arms (InsufficientRouting, DeadlineExceeded) proven. 5x stable ~1.4s.

KAD-MAPPING DECISION: HYBRID. provider-records (start_providing/get_providers) = multi-provider INDEX; opaque value store (put_record/get_record) at composite key derive_key('nix-p2p/libp2p-kad/provider-record-value/v1', ContentKey||PeerId) = per-provider signed record (offline-learnable). Neither primitive alone fits: value-store at key=ContentKey collides across providers (MemoryStore single-valued, puts converge on same k-closest); provider-records carry no offers/expiry/signature. Composite uses PeerId.to_bytes() (what get_providers returns). Node identity = record-signing ed25519 seed so NodeId==provider. Custom /nix-p2p/<scope>/kad protocol keeps nodes off the public IPFS DHT.

HONEST LIMITS: withdraw is best-effort (stop_providing + TTL; signed tombstone = TASK-152); DeadlineExceeded enforced at the async boundary (kad query not explicitly cancelled); empty-records-after-nonempty-providers -> Miss; discovered-PeerId<->record.provider binding not yet enforced (TASK-152); NOT wired into the daemon (just e2e unaffected; daemon-libp2p = TASK-146).

FOLLOW-UPS FILED: TASK-152 (record lifecycle/withdrawal/expiry/replay/partition + PeerId binding, AC#6), TASK-153 (bootstrap independence >=3, AC#5), TASK-154 (resource bounds + sybil/eclipse + packet/source guards, AC#8+#9), TASK-155 (decentralized-content-discovery-v1 evidence, AC#10). AC#3 cold journey = TASK-132; transport = TASK-151.
<!-- SECTION:NOTES:END -->
