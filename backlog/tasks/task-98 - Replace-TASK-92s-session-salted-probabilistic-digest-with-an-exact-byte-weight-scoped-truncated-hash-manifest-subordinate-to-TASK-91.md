---
id: TASK-98
title: >-
  Replace TASK-92's session-salted probabilistic digest with an exact
  byte-weight-scoped truncated-hash manifest, subordinate to TASK-91
status: To Do
assignee: []
created_date: '2026-08-10 08:43'
labels:
  - wave-2b
dependencies:
  - TASK-91
  - TASK-92
  - TASK-95
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
REFINES TASK-92 by changing three things it currently gets wrong: the baseline it is measured against, the false-positive rate it selects, and the privacy property it claims.

BASELINE ERROR. TASK-92 declares TASK-91 as a dependency but quotes its benefit against the pre-TASK-91 world ('a 200-path closure against 8 peers is 1,600 probes'). Against the batched hold-query it actually ships on top of, the delta is one round trip per peer per build going to zero — and TASK-91's own text argues that round trip is free because it lands inside the narinfo->NAR gap (median 300 ms, tail 3.08 s). On bytes, with 12-byte truncated keys a 200-path batched query is ~2.4 kB against a 9.1 kB digest at n=6,311, so the digest LOSES below roughly a 760-path closure. Measured drift on this machine is 10 of 2,854 closure paths across 5 system generations, so the typical query is tens of paths, not thousands. TASK-92 cites low drift to defend its publication cost and high query volume to defend its amortisation; it cannot have both.

EPS ERROR. TASK-92's eps=1/1024 rationale ('a false positive costs one wasted dial, ~0.07 ms at a 70 ms mean NAR fetch') is wrong twice. The wasted-dial bound in this codebase is DIAL_TIMEOUT = 10 s (daemon/src/transport_iroh.rs:135) against a dead or NAT'd peer, not 70 ms; and 70 ms is derived from the MEAN NAR size while the median servable NAR is far smaller. More importantly the filter is amortised over thousands of tests while each false positive costs a full dial, so minimising total cost gives eps* near 1e-6 — at least as strict as BIP158, not 1000x looser. Break-even for the stricter filter is roughly 13 lookups.

WHICH MAKES THE FILTER THE WRONG TOOL. A sorted array of 8-byte truncated NarHashes is ~50.5 kB at n=6,311: ZERO false positives (collision probability n^2/2^65), safe deletes, real byte-range deltas, no salt, no rebuild, no cuckoo-delete false-negative hazard. It costs ~41 kB more than the GCS the entire encoding debate is about. Scope it by byte weight and it collapses further: the top 500 servable paths hold 89.1% of all servable NAR bytes, which is ~4 kB of truncated hashes, exact. Fetch time is a function of bytes, so scope by bytes.

PRIVACY. Session-salting does NOT defeat offline testing: the receiver must hold the salt to test the structure, so (manifest, salt) forwards perfectly to any third party, and re-hashing a ~5M-hash public universe under a fresh salt is sub-second in Rust. More fundamentally it is a logical impossibility — any structure a peer can test locally with zero round trips IS an offline oracle over the whole public hash universe for whoever holds it. 'Zero round trips' and 'no offline enumeration' cannot both be true, and TASK-92 currently promises both. Serving a manifest is a deliberate disclosure of inventory to anyone who mints a free ed25519 NodeId and dials; the mitigation 'only to a peer that already dialled you' is not an access control in a public swarm (PRD.md settles the deployment model as a public global swarm).

WIRE. daemon/src/claim.rs:103 pins MAX_CLAIM_WIRE_BYTES = 64 KiB on the documented premise that 'a claim is tiny' (claim.rs:60). A byte-weight-scoped manifest fits; a whole-store manifest does not, and needs a chunked/streamed message class that the codec's smallness safety story does not currently cover. Also note the DoS asymmetry: a request costs the asker one handshake and costs the server a manifest build plus tens of kB of egress, with no rate limiting anywhere in the design.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Byte-and-round-trip comparison against TASK-91's batched hold-query, measured over the REAL closure-size distribution from a cold nixos-rebuild rather than an assumed 200 paths, reporting the crossover closure size at which the manifest starts winning. BITE: the report must show the manifest LOSING below the crossover — if it wins at every closure size, the batched-query baseline was not actually implemented or was costed at the wrong key width.
- [ ] #2 Wasted-dial cost is MEASURED: instrument dials to a dead peer and to a NAT-blocked peer and report the observed latency distribution against DIAL_TIMEOUT = 10 s. BITE: a report quoting 70 ms, or quoting a mean NAR fetch time, means the measurement did not happen and fails.
- [ ] #3 The manifest is exact truncated hashes, scoped by byte weight to cover >=85% of servable NAR bytes, and fits in one message under MAX_CLAIM_WIRE_BYTES with the cap enforced at encode time. BITE: attempt to encode 100% of a 100k-path store and confirm the encoder REFUSES or chunks rather than emitting an oversized frame — verify by asserting on the error/chunk boundary, not by inspecting the happy path.
- [ ] #4 Zero false positives demonstrated over >=10^6 membership tests against hashes known absent from the manifest. BITE: run the identical harness against a GCS or Bloom filter at eps=1/1024 and confirm it produces roughly 1,000 hits — if both structures report zero, the negative-test corpus is not actually absent and the oracle proves nothing.
- [ ] #5 Staleness is bounded and observed: after a garbage collection removing >=10% of the manifest's entries, measure wasted dials for a peer still holding the stale manifest, and confirm every manifest miss still resolves through the TASK-91 hold-query. BITE: disable the hold-query fallback and confirm the build FAILS to obtain content the stale manifest denies; re-enable it and confirm the build succeeds — this is what makes 'accelerant, never authority' bite instead of being a comment.
- [ ] #6 TASK-92's acceptance criterion promising zero round trips AND non-enumeration is struck and replaced with 'fewer peers dialled per closure', and the offline-oracle property is written down as an explicit, owner-signed disclosure or the manifest is not served at all. BITE: grep TASK-92 for 'zero round trips' returns nothing uncorrected, and the served-manifest path is gated behind an explicit config flag that defaults to off until the owner signs.
<!-- AC:END -->
