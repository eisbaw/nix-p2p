---
id: TASK-212
title: >-
  Blinded rendezvous keys + self-certifying provider records — offline
  liar-rejection + NAR-hash privacy on the DHT (GH #2)
status: To Do
assignee: []
created_date: '2026-08-14 21:56'
updated_date: '2026-08-14 22:20'
labels:
  - privacy
  - discovery
  - anti-false-claim
  - frozen-surface
  - from-github-issue
dependencies: []
references:
  - 'https://github.com/eisbaw/nix-p2p/issues/2'
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Imported verbatim from GitHub issue #2 (eisbaw/nix-p2p, owner Mark Ruvald Pedersen, 2026-08-14). Full text below.

# Blinded rendezvous keys + self-certifying provider records

## Problem

Provider discovery for private NARs over an untrusted DHT has two flaws:

1. **False availability claims.** DHT announcements are unauthenticated. Any peer can claim to provide any NAR hash. Content verification (bao) catches liars only *after* connecting — so a querier must dial and audit up to n claimants: O(n) connections, wasted RTTs, and liars learn which content is in demand.
2. **NAR hash leakage.** Announcing under the raw NAR hash publishes it to every DHT node and crawler. For private, self-built derivations the NAR hash is effectively a bearer capability (Tahoe-LAFS model: the name is the credential). It must never appear in the DHT — not as key, not in the value.

## Proposed solution

Derive two purpose-bound keys from the NAR hash; publish a MAC-authenticated record that any hash-holder can verify **offline**, before dialing anyone.

### Key derivation (both sides, locally)

```
K_r    = HKDF(nar_hash, "rendezvous-v1")   // public: DHT key
K_auth = HKDF(nar_hash, "auth-v1")         // secret: never transmitted
```

HKDF is one-way: DHT nodes and crawlers see only `K_r`, and cannot recover the NAR hash from it.

### Announce (per republish interval)

```
epoch = floor(unix_time / REPUBLISH_INTERVAL)
tag   = HMAC(K_auth, epoch || peer_id)     // blake3::keyed_hash

DHT.put(K_r, { addr, epoch, tag })
```

### Query

1. Derive `K_r` from the locally known NAR hash; one DHT lookup returns all records.
2. For each record: recompute `HMAC(K_auth, epoch || peer_id)`, compare to `tag`. Accept epochs `{current, previous}` (clock skew / republish jitter).
3. Drop non-matching records. Dial one surviving peer; fetch via verified bao stream.

Critical path: **1 lookup, n local MAC checks (ns each), 1 dial.** No connection to any unverified peer; liars never receive a packet.

## Security argument

- **Forgery:** a liar knows at most `K_r`; forging `tag` for its own `peer_id` requires `K_auth` -> 2^-256, not a truncation-sized bound.
- **Replay:** copying an honest record verbatim only re-advertises the honest peer (tag binds `peer_id`). Old records expire (tag binds `epoch`), so third parties cannot resurrect departed peers, and freshness is authenticated end-to-end — no trust in DHT-node TTL housekeeping.
- **Oracle-freeness:** no message ever contains the NAR hash or any substring of it. Honest peers cannot be farmed for secret bits (unlike truncated-hash / plaintext-suffix schemes).
- **Query privacy:** DHT sees only `K_r`; rejected liars don't even observe demand.

## Limitations

- Proves **knowledge of the hash within ~2 epochs**, not current possession of bytes. A peer that GC'd the content still verifies; the first verified bao chunk settles possession at the cost of one aborted stream.
- DHT nodes can't validate records (no `K_auth` by design) -> spam under `K_r` forces cheap local MAC checks on the querier. Graceful; cap records per key if it ever matters.
- `tag` deliberately does **not** bind `addr` (laptops roam). Address swap in a replayed record fails at dial time because the iroh peer ID is the node's public key, authenticated by the QUIC handshake. If ported off iroh, move `addr` into the MAC.
- Assumes queriers pre-know the NAR hash (private pool). For semi-public content, swap HMAC for a signature under a hash-derived key; record shape unchanged.
- Content misbehavior is detected only by requesters (bao), and is handled by local reputation rather than protocol-level proofs; fraud proofs were considered and rejected because they conflict with NAR-hash privacy and require non-repudiable transfers

## Implementation notes

- `REPUBLISH_INTERVAL` = the DHT's native re-announce period (~1 h): epoch costs zero extra messages, just a fresh 32-byte MAC per republish.
- Verify step is a `retain()` over the lookup result — natural hook for local peer reputation later.
- Prior art: BEP44 signed mutable items, Tor v3 blinded descriptors, TOTP (epoch-as-nonce). Symmetric setting here is cheaper: no signatures needed.
- Optional follow-up: convergent encryption of stored blobs under a third HKDF label -> storage peers learn nothing about content they hold. Reserve the label now.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 K_r = HKDF(nar_hash, rendezvous-v1) is the DHT key and K_auth = HKDF(nar_hash, auth-v1) is never transmitted; the raw NAR hash appears NOWHERE in the DHT (not as key, not in any value/substring)
- [ ] #2 Records are MAC-authenticated (tag = keyed-hash(K_auth, epoch||peer_id)) and a hash-holder verifies them OFFLINE (n local MAC checks) before dialing any peer; no packet is sent to an unverified/lying claimant
- [ ] #3 Epoch freshness: accept {current, previous} epochs; a replayed record only re-advertises the honest peer (tag binds peer_id) and expires (tag binds epoch) with no trust in DHT-node TTL
- [ ] #4 Security properties demonstrated by test/oracle: forgery bound ~2^-256 (not truncation-sized), replay-safe, oracle-free (honest peers cannot be farmed for secret bits), query-privacy (DHT sees only K_r)
- [ ] #5 Per-key record cap against K_r spam; the verify step is a retain() over the lookup result (reputation hook)
- [ ] #6 Frozen-surface discipline: any change to the discovery key derivation / provider record is a VERSIONED format change with new golden vectors and a version bump, reconciled against the PRD irreversibility map — not an in-place edit of the frozen surface
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
PROVENANCE: GitHub issue #2 https://github.com/eisbaw/nix-p2p/issues/2 (OWNER, 2026-08-14). No comments on the issue. Imported by the phase3 loop on 2026-08-14 per owner instruction "check the github issues and check all comments; add as backlog tasks in full."

ORCHESTRATOR GOTCHAS / RELATION TO EXISTING CODE (not from the issue — added for the implementer):
- TOUCHES A FROZEN SURFACE. The discovery key + provider record are FROZEN and pinned by golden vectors (README "Frozen surfaces"; PRD irreversibility map): today ContentKey is derived from the signed NarHash and the ed25519-signed ProviderRecord is stored as an opaque value. This proposal CHANGES the key derivation (blinding: K_r = HKDF(nar_hash,"rendezvous-v1") so the raw NarHash never appears) AND the record contents (epoch + K_auth-HMAC tag). Implementing it is a versioned wire/format change requiring the freeze process (new golden vectors, a version bump), NOT an in-place edit. Confirm against PRD irreversibility map + docs/peer-fabric-seam.md.
- OVERLAPS existing work: TASK-102 (PublicNarAllowlist) already does per-record keyed-blake3 MAC + ed25519 verify_strict for the PUBLIC allowlist; TASK-126/103 froze the ContentKey/ProviderRecord + libp2p-kad ProviderDirectory. This issue is the PRIVATE-pool analogue: offline liar-rejection BEFORE dialing (current path dials then bao-verifies) + NAR-hash blinding (current ContentKey is NarHash-derived but the issue's threat model wants HKDF-one-way so the hash cannot be recovered/farmed). Reconcile: is the current ContentKey derivation already one-way? If not, this is the privacy gap.
- BASICS-FIRST: this is private-pool privacy, beyond the public cache.nixos.org facade. Sequence after the proven public trunk + the connectivity keystones unless owner reprioritizes.
- RELATED: issue #1 "Pools" (separate task) extends this — the owner notes #2 alone still lets anybody pull private NARs to index for PII/IP, so pools add disjoint DHTs or NAR encryption on top. See the reserved third-HKDF-label convergent-encryption follow-up in this issue's implementation notes.

VERIFIED against the code (2026-08-15, replaces the earlier 'is ContentKey one-way?' question with facts):
- BLINDING IS ALREADY SHIPPED + FROZEN. peer-fabric/src/content.rs: ContentKey = blake3::derive_key(CONTENT_KEY_CONTEXT, signed_nar_hash) — a domain-separated one-way KDF (TASK-126 freeze, golden-vectored, second-impl anchor scripts/check-content-key-derivation.py). A node ROUTING a lookup sees only an opaque key, NOT the NarHash. This IS issue #2's K_r = HKDF(nar_hash,'rendezvous-v1'). Done.
- SELF-CERTIFYING / REJECT-BEFORE-DIAL IS ALREADY SHIPPED. peer-fabric/src/record_codec.rs: ProviderRecord is ed25519-SIGNED and SELF-VERIFYING (provider NodeId IS the verifying key), domain-separated signing preimage, strict non-malleable canonicality (verify_strict). A forged record fails verification OFFLINE, so liars are dropped before any dial. Issue #2 proposes a symmetric K_auth HMAC for this; the project chose signatures (issue #2 itself notes 'swap HMAC for a signature under a hash-derived key' as the semi-public option). Functionally the offline-liar-rejection goal is met — arguably better (no pre-shared secret needed).
- THE REAL RESIDUAL GAP (this is where #2/#1 add value): content.rs is explicit the design is NARROWS-NOT-HIDES — a k-closest STORING node holds the ProviderRecord and therefore learns its  Blake3Digest. For PRIVATE content that storing node learns content identity. Issue #2's 'NAR hash never in the VALUE' requirement + issue #1's disjoint-DHTs / encrypted-NARs are what close THIS. The code defers the adversarial exposure analysis to TASK-132 (now deprioritized) — the live home for the private-content exposure work is here (TASK-212) + TASK-213.
- REVISED SCOPE: the discovery-layer CRYPTO of #2 (blinded key + self-certifying offline-verifiable records) is essentially DONE. The genuine new work is (a) epoch-freshness binding if wanted (records already have monotonic-sequence replay/rollback + tombstones, so re-check whether an epoch adds anything), and (b) the VALUE-SIDE / storing-node content-exposure leak for private pools — really one workstream with TASK-213. Do NOT re-implement the shipped blinding/signing; target the residual exposure + pool isolation. Basics-first: still deferred behind the public trunk + connectivity keystones.
<!-- SECTION:NOTES:END -->
