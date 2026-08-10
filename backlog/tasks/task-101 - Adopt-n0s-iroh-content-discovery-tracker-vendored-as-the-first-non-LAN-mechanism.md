---
id: TASK-101
title: >-
  Adopt n0's iroh-content-discovery tracker (vendored) as the first non-LAN
  mechanism
status: To Do
assignee: []
created_date: '2026-08-10 09:27'
updated_date: '2026-08-10 09:27'
labels:
  - wave-2b
dependencies:
  - TASK-100
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
<!-- AC:END -->
