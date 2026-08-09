---
id: TASK-82
title: >-
  Persist the immutable NarHashKey -> (StorePath, Blake3Digest, NarSize) binding
  to close the task-61 seeding gap
status: To Do
assignee: []
created_date: '2026-08-09 21:25'
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
