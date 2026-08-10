---
id: TASK-101
title: >-
  Adopt n0's iroh-content-discovery tracker (vendored) as the first non-LAN
  mechanism
status: To Do
assignee: []
created_date: '2026-08-10 09:27'
updated_date: '2026-08-10 22:44'
labels:
  - wave-2b
dependencies:
  - TASK-82
  - TASK-89
  - TASK-100
  - TASK-102
  - TASK-115
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Owner asked directly why we cannot use https://github.com/n0-computer/iroh-experiments/tree/main/content-discovery. ANSWER: WE CAN, and an earlier note in TASK-73 saying otherwise was WRONG - it described the OLD crates.io crate iroh-mainline-content-discovery 0.6.0 (published 2025-04-04, pinning iroh 0.34) and conflated it with the CURRENT directory, which is a different thing.

VERIFIED 2026-08-10 from the workspace Cargo.toml: content-discovery pins iroh 1.0.0-rc.1, iroh-base 1.0.0-rc.1, iroh-blobs 0.102, iroh-mainline-address-lookup 0.3. We are on iroh 1.0.3 / iroh-blobs 0.103. That is an rc-to-release bump and ONE minor version of iroh-blobs - adoption work, not a rewrite.

WHAT IT GIVES US:
  * iroh-content-discovery - the announce/query protocol plus a client
  * iroh-content-tracker  - a working tracker server (~1,200 lines)
  * iroh-content-discovery-cli - announce/probe from the command line
  * Announce VERIFICATION we should keep: the tracker downloads a random 2 KiB blake3 chunk from the announcer and checks it (partial content -> unverified size only; hash sequences -> a random chunk of a random child). This is TASK-90's design, already implemented by someone else.

WHAT IT DOES NOT GIVE, so plan for it:
  * NO public or default tracker. The CLI's --tracker is required with no built-in value; we must run one (or point at a peer's).
  * NO DHT content announce. That layer was deliberately removed upstream ('Purge all but the iroh connection option', 'Remove everything but iroh connections'), so this is tracker-over-iroh only. Global DHT discovery stays TASK-73 and is gated by TASK-96.
  * It lives in a repo self-described as 'very low level and unpolished' where 'most will not' graduate, with low lifetime download counts. n0 may abandon it.

THEREFORE VENDOR IT, do not depend on it. Copy the tracker and client into the workspace under a clearly-marked upstream-derived directory recording the exact upstream commit and its licence, so a version bump upstream cannot break our build and an abandonment costs us nothing. It is small enough that this is cheap, and the alternative - a dependency on a pre-1.0 experiment - is the kind of debt this project files tasks about.

WHY A TRACKER IS ACCEPTABLE HERE, when it would not be for most p2p systems: our daemon and peers are OUTSIDE the trust base and nix re-verifies signature and NarHash, so a lying or compromised tracker costs a wasted dial and never a bad store path. It is a HINT PROVIDER, not an authority. And trackers are cheap at real scale - opentrackr runs ~10M torrents and ~200k connections/s on a ten-year-old server.

Slot it behind TASK-100's seam as one mechanism among several; it must not become the only path, and a dead tracker must surface as UNAVAILABLE rather than as 'nobody has it'.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The vendored tracker and client build against our iroh 1.0.3 / iroh-blobs 0.103, with the upstream commit hash and licence recorded in-tree; the version delta we had to close is written down
- [ ] #2 Two daemons that share a tracker but were given NO peer addresses complete a real peer-served nix build: one announces, the other resolves via the tracker and fetches - proven end to end, with peer bytes counted at the provider
- [ ] #3 It is one mechanism behind the TASK-100 seam, not a special case: with the tracker stopped, resolution reports UNAVAILABLE and the build falls back to upstream; bites by mutation (a test fails if a dead tracker reads as a clean miss)
- [ ] #4 The announce verification (random 2 KiB blake3 chunk) is retained and shown to bite: a node announcing content it does not have is rejected at the probe - this closes TASK-90 or explicitly supersedes it, say which
- [ ] #5 Honest limits recorded: no default tracker (we run one), no DHT announce, and what our exposure is if upstream abandons the experiment
- [ ] #6 The tracker is operable as a configured service with health, rate/work limits, restart persistence and explicit endpoint ownership; daemon restart preserves offers and a tracker outage remains visible.
- [ ] #7 The end-to-end proof supplies no peer address, claim or per-content locator; all currently known transport offers round-trip exactly. Unknown future-offer byte preservation is explicitly deferred to TASK-55 once real relay/storage paths exist.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
## Forward-carried from TASK-91 (batched hold-query)

* A tracker answers "who has X". The unit of the QUESTION is now a closure, not a
  path (TASK-91): the daemon knows every NarHash the moment it has proxied the
  narinfos, ~300 ms before Nix asks for any NAR (task-35). If n0's tracker
  protocol only accepts one hash per request, the adapter should batch at OUR
  seam and pipeline, and the round-trip cost of doing so should be MEASURED with
  `just discovery`'s instrument rather than assumed - it is exactly the cost
  TASK-91 removed from direct probes and it would be a shame to reintroduce it
  one layer up.
* NO-ENUMERATION IS A PROPERTY OF THE MECHANISM, not just of our types. A tracker
  that can be asked "what does node N have" (or that returns holdings the asker
  did not name) violates the invariant even if our own API cannot express it.
  Check that explicitly against the vendored protocol before adopting, and record
  the finding either way.
* Half the servable bytes here carry no upstream signature, so they can never be
  published to a tracker/DHT under the publication rule (TASK-102) and are
  reachable ONLY by direct hold-query. The batched direct probe is therefore not
  a fallback the tracker replaces - both are load-bearing.

## CARRIED FORWARD from TASK-91 round 6 (the batch call shape you inherit)

A TRANSPORT OFFER IS NOT ALWAYS PEER-SCOPED, and assuming it is produced a live
bug. Iroh's locator is the holder NodeId - one value for a whole batch -
but BitTorrent's is an infohash, which addresses one piece of CONTENT. The
first batch response hoisted ONE offer list to the envelope and let every Have
share it; key 2's claim silently received key 1's infohash. The fix:
BatchHoldResponse carries an offer DICTIONARY and each Have names its own entries
BY INDEX (claim.rs BatchHoldAnswer::Have::offer_indices), with every index in
range, no index repeated inside one answer, and every dictionary entry referenced
by at least one Have - so an all-Absent response cannot carry a locator at all.
DO NOT re-introduce a response-wide offer list in any new mechanism.

TWO RULES THAT COST NOTHING TO KEEP AND ARE EXPENSIVE TO RE-DISCOVER:
  * Unknown transport kinds are tolerate-but-drop. On an INDEXED list that means
    the decoder must keep position-preserving SLOTS, validate against the RAW
    positions, then compact and RE-INDEX together. BatchHoldResponse deliberately
    has no derived Deserialize so this cannot be bypassed.
  * serde deny_unknown_fields on an internally-tagged enum is honoured for STRUCT
    variants and SILENTLY INERT for UNIT variants. Any new answer enum must use
    empty struct variants (`Absent {}`), which emit identical bytes.

BOUNDS ARE TYPE INVARIANTS, NOT CALLER PRECONDITIONS: the cap is applied to the
caller-supplied asked-count itself, the responder hard-checks it (it was a
debug_assert, i.e. absent in release), the compatibility shim checks it before
issuing any probe, and every encoder gates its OUTPUT length so this node cannot
emit a message it would itself refuse.
<!-- SECTION:NOTES:END -->
