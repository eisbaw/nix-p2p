---
id: TASK-82
title: >-
  Persist the immutable NarHashKey -> (StorePath, Blake3Digest, NarSize) binding
  to close the task-61 seeding gap
status: To Do
assignee: []
created_date: '2026-08-09 21:25'
updated_date: '2026-08-10 09:29'
labels:
  - forward-carried-from-task-61
dependencies:
  - TASK-72
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
FORWARD-CARRIED FROM TASK-61 (supply-model decision, 2026-08-09).

Task-61 chose regenerate-on-demand and accepted a REAL cost: a restart empties the availability index's in-memory digest cache, so a claim already published to the DHT naming a digest this node can no longer REVERSE-MAP is undiallable until a hold-query re-derives it. Bounded failure (the fetcher falls back to upstream), never an integrity problem - but it is the 'seeding gap' the PRD irreversibility map warned about, now real.

THE CHEAP FIX, with its number: persisting the derived digest+size alongside the registration costs about 40 bytes per path beyond what JsonFileStore already writes - ~4.3 MB for the owner's 108,401 paths, 0.003% of content. Compare the rejected alternative (persisting bao outboards, ~0.4% of content = ~0.6 GiB, which does NOT remove the dump).

WHY IT IS SAFE TO PERSIST DERIVED STATE HERE, and why that argument must be made explicitly in the change: availability.rs deliberately does NOT persist the digest ('caching a derived value invites staleness'). The exception is earned by Nix's own invariant - a /nix/store path's content is IMMUTABLE, so BLAKE3(dump(path)) cannot go stale for a given path. If that argument is not written down at the site, this is just a cache with a bug waiting.

TRAP: the registration binding is NOT verified at the source (availability.rs register() takes the caller's word that key -> store_path is true, and blake3_for computes only BLAKE3, never re-deriving sha256(dump) to assert it equals key). Persisting the digest makes a MIS-registration durable. Consider closing the source-side sha256 check in the same change, or state loudly why not.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The NarHashKey -> (StorePath, Blake3Digest, NarSize) binding survives a restart, so a node can serve a previously-announced digest immediately after boot with no hold-query first
- [ ] #2 The immutability argument (Nix store paths are content-immutable, so the digest cannot go stale) is written at the site, and a bite proves a CHANGED path invalidates rather than serving stale bytes
- [ ] #3 The on-disk cost is measured, not asserted: bytes per path, and the total for a 108k-path store
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
