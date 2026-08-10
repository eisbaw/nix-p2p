---
id: TASK-92
title: Set-digest exchange (Bloom/GCS) so most content lookups need ZERO round trips
status: To Do
assignee: []
created_date: '2026-08-10 07:24'
updated_date: '2026-08-10 22:58'
labels:
  - wave-2b
  - deferred-post-holdout
dependencies:
  - TASK-91
  - TASK-124
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The accelerant layer above batched queries (TASK-91). A peer periodically publishes a compact probabilistic digest of what it can serve; the asker tests hashes against the digest LOCALLY and only dials peers that plausibly have the content. Discovery cost drops from a round trip to a memory lookup.

SIZE: the owner's store is 108,401 paths. A Bloom filter at ~10 bits/element is ~135 KB; a Golomb-coded set at a 1-in-1000 false-positive rate is comparable. That is small enough to gossip (TASK-74) or attach to a peer record, and it covers the WHOLE store rather than the handful of paths anyone bothered to announce.

FALSE POSITIVES ARE CHEAP FOR US and this is the reason the technique fits: a false positive costs one wasted dial, and the daemon and peers are outside the trust base so nix still re-verifies sig+NarHash. Tune the rate for dial cost, not for correctness.

THE PRIVACY CONSTRAINT AND ITS RESOLUTION - read this before building. A digest IS enumerable by guessing: anyone can test any hash against it. That collides head-on with the owner's no-enumeration rule ('we shall only respond yes or no to a query, not allow listing what we have - which could be secrets'). The resolution is to scope WHAT GOES IN: include a path only if its NarHash is already PUBLIC - i.e. it appears in a signed narinfo from the upstream cache. Those hashes are guessable by anyone with the same nixpkgs anyway, so the digest leaks nothing new. NEVER include locally-built or private paths; for those, keep the ask-me-directly yes/no path. This split must be enforced in code and tested, not left as a convention - it is the difference between a public-content accelerant and a secret leak.

Note this also gives leech mode (TASK-78) a precise meaning: publish no digest.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A peer can publish a compact set digest of its PUBLIC servable content, and an asker uses it to skip peers that certainly lack a hash; digest size and false-positive rate are measured against a realistic path count (~100k)
- [ ] #2 The public/private split is ENFORCED and TESTED: a path whose NarHash does not appear in a signed upstream narinfo is never included, and the test bites by mutation (include a local-only path and the check must go red)
- [ ] #3 False-positive cost is measured as wasted dials per lookup and reported; the rate is tuned against that cost, not guessed
- [ ] #4 Digest staleness is handled: a hash absent from a stale digest must still be reachable via the batched hold-query path, so the digest is strictly an accelerant and never the authority
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
## CENSUS CORRECTION 2026-08-10 (re-derived by the orchestrator from /nix/var/nix/db/db.sqlite)

Any figure in this task quoting 108,401 paths / 155,621 MiB / "mean NAR 1.44 MiB" is WRONG and must
not be used. The original numbers came from `nix path-info --all`, which counts .drv files. Those are
local evaluation artifacts cache.nixos.org does not serve; they are 85.6% of all paths while holding
0.2% of the bytes, so they inflated the path count ~7x and deflated the mean NAR ~6x.

AUTHORITATIVE (measured 2026-08-10, independently re-derived - not taken from a subagent report):
  valid paths                85,808
    .drv                     73,412 (85.6%), only 263 MiB   <- never publish these: useless AND a privacy leak
    SERVABLE output paths    12,396, 105,713 MiB
      signed by cache.nixos.org   6,769 paths / 53,854 MiB = 50.9% of bytes
      locally built (ultimate)    2,250 paths / 35,870 MiB
  size distribution (servable): mean 8.53 MiB, p50 0.10 MiB, p90 4.48 MiB, p99 151.06 MiB, p100 3186.03 MiB
  byte concentration: top 151 paths = 73.5% of bytes, top 691 = 91.7%, top 1,243 = 95.5%

THREE CONSEQUENCES that change reasoning, not just arithmetic:
1. The publishable set (signed, hence already-public) is ~6,769 paths, not 108,401 - a ~16x reduction.
   Every per-path cost model shrinks by that factor.
2. HALF THE SERVABLE BYTES (49.1%) carry no upstream signature and therefore can NEVER be published
   under the no-enumeration rule. They stay reachable only by direct hold-query, which makes TASK-91
   (batched hold-query) load-bearing rather than an optimization.
3. The distribution is far more extreme than "mean 1.44 MiB" implied: the MEDIAN is 100 KiB (~5 ms
   from a 21 MB/s upstream) while 151 paths hold three quarters of all bytes. Any claim that a
   discovery round trip amortises against a download must be checked against the MEDIAN, not the mean.

Note also 1.44 MiB was a MEAN misdescribed as a median in places; the servable mean is 8.53 MiB.
Canonical source of truth going forward: TASK-95 (reproducible store census).
<!-- SECTION:NOTES:END -->
