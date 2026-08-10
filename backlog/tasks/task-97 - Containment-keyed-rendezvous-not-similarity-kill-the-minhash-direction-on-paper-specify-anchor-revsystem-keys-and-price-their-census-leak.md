---
id: TASK-97
title: >-
  Containment-keyed rendezvous, not similarity: kill the minhash direction on
  paper, specify anchor/(rev,system) keys, and price their census leak
status: To Do
assignee: []
created_date: '2026-08-10 08:43'
labels:
  - wave-2b
dependencies:
  - TASK-93
  - TASK-73
  - TASK-96
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
REFINES TASK-93. TASK-93 already frames revision-correlation as the granularity fix; this task pins the mechanism, kills the similarity-sketch alternative before anyone builds it, and puts the resulting privacy price in front of the owner.

WHY MINHASH IS REFUTABLE ON PAPER. MinHash collision probability equals Jaccard J = |A intersect B| / |A union B|. The retrieval predicate here is CONTAINMENT — 'does this peer hold the paths I want' — not similarity, and Jaccard collapses under set-size asymmetry, which is the normal laptop-versus-seeder condition. With this machine's measured 6,311-path publishable set as the asker and a seeder that is a STRICT SUPERSET holding 100% of what the asker wants: at a 60,000-path seeder J = 0.105, so bottom-k with k=8 gives E[overlap] = 0.84 and P(at least one key collides) = 1-(1-J)^8 = 58%; at a 500,000-path mirror P is around 5%. The design's stated behaviour — 'a large-store seeder matches many askers, which is the behaviour you want' — is inverted: the more useful the seeder, the more invisible it is. Compensating needs k around 110-730 keys, which is both the per-path publication regime the sketch existed to avoid and, at that size, an inventory in its own right.

SECOND, INDEPENDENT, ALSO FATAL. The publish-side sketch is over the whole store while the query-side sketch is over the closure being substituted; those differ by one to three orders of magnitude, so the same collapse fires between otherwise identical machines. A 20-path `nix shell` closure against a 6,311-path store gives P around 2%. And the daemon cannot compute a closure sketch when it needs one: it proxies narinfos incrementally as Nix walks References (daemon/src/narinfo_cache.rs parses `References:`), so at first-NAR time it holds a fraction of the closure and its bottom-k keeps changing as new minima arrive.

WHAT TO BUILD INSTEAD — both are containment tests with no size-asymmetry penalty. (a) A REVISION KEY: H("nix-p2p/v1" || nixpkgs-rev || system), supplied by the NixOS module, or derived by the daemon from a closure fingerprint it already holds (the glibc/stdenv store hash appearing in narinfo References). (b) ANCHOR KEYS: per-path keys on ubiquitous public NarHashes (glibc, bash, stdenv) drawn from the closure currently being substituted, which is exactly the set the asker already possesses at query time.

THE PRICE, WHICH MUST BE PAID EXPLICITLY AND NOT BURIED. Anchor keys ARE per-path keys. Anyone with the same nixpkgs can compute the anchor for glibc-<version>-<rev> and get_peers it, obtaining a package-version census of the entire user base with zero interaction and no crawling. That is a STRONGER leak than the minhash sketch, not a weaker one, and it belongs in front of the owner in the same packet as the BEP51 sweep result from the mainline-participation task.

SATURATION TRAP. libtorrent caps dht_max_peers at 500 per infohash and, at the cap, DROPS new announces with no eviction — only already-present peers can refresh. get_peers returns at most 100 peers (25 for IPv6). A single well-known 'nix-p2p universal' key therefore saturates at ~500 first-come registrants per storing node and FAILS CLOSED for newcomers, which is precisely the 'daemon started with empty state' case the PRD requires to work.

WHAT FALSIFIES THIS TASK'S DIRECTION: if the measured rendezvous rate for a revision key across two hosts of very different store sizes is not near 1.0, containment keying is mis-specified and the whole rendezvous idea needs rethinking rather than re-keying.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A checked-in, reproducible artifact tabulating P(rendezvous) against asker/holder store-size RATIO for bottom-k minhash at k in {8, 64, 256} under strict containment, using the measured 6,311-path asker. BITE: the table must show P < 0.6 at a 10x size ratio for k=8, and the generator must self-check against the closed form P = 1-(1-J)^k — a model that reports P near 1.0 at every ratio is computing Jaccard wrong and must fail that check.
- [ ] #2 The same table computed for the revision key and the anchor keys, showing P = 1 independent of size ratio, with the ratio column present so the contrast is measured rather than asserted. BITE: if the containment column also degrades with ratio, the key derivation has accidentally been made set-dependent and the design is not containment-shaped.
- [ ] #3 Two hosts on the SAME nixpkgs revision but with deliberately asymmetric store sizes (roughly 6k paths versus 60k paths) rendezvous on the revision key in >=19 of 20 trials, while the SAME pair rendezvous on bottom-8 minhash in fewer than 15 of 20. BITE: the harness must assert the store-size ratio is >=8x before running — if minhash also scores 19/20 the stores were not actually asymmetric and the trial is void.
- [ ] #4 Adjacent-revision behaviour is measured (hosts one channel bump apart): the exact revision key MUST fail to rendezvous, and anchor keys drawn from the closure being substituted MUST recover it. BITE: if both succeed the two hosts are not actually on different revisions — assert the revisions differ before scoring.
- [ ] #5 The 500-peer saturation is exercised directly: fill a test infohash to dht_max_peers and confirm a fresh announcer is silently dropped and is absent from a subsequent get_peers. BITE: if the new announcer appears, the storage model assumed an eviction policy that does not exist, and any universal-key fallback in this design is invalid as specified.
- [ ] #6 A written privacy note quantifies the anchor-key census: how many distinct IPs a single get_peers on a glibc anchor recovers, and how often it can be refreshed. Delivered to the owner together with the BEP51 sweep result before any key derivation is frozen. BITE: TASK-73's freeze depends on this note existing, verified by the tracker edge.
<!-- AC:END -->
