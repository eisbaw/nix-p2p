---
id: TASK-46
title: 'HARDENING (wave-2a): claim-schema conformance + NarSize-abort spam defense'
status: To Do
assignee: []
created_date: '2026-08-08 20:13'
updated_date: '2026-08-09 14:03'
labels:
  - hardening
dependencies:
  - TASK-41
  - TASK-44
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Wave-2a hardening block, deep-gated (runs against stabilized wave-2a surfaces). Claim-schema conformance/versioning fuzz (unknown variants, version skew, malformed claims - forward-compat holds, malformed rejected fail-closed); the NarSize/FileSize abort against claim-spam (PRD risk 6: a lying claim pointing at an attacker-chosen huge blob must be aborted at the signed NarSize, not downloaded in full before the gate - the daemon is outside the TCB but wasted-dial DoS is real); wasted-dial bounding on lying claims. Plus deferred findings wave-2a filed along the way.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Claim-schema fuzz: malformed/version-skewed/unknown-variant claims handled per spec (forward-compat parses, malformed fail-closed) - each bite shown
- [ ] #2 NarSize-abort: a claim pointing at a blob exceeding the signed NarSize is aborted before full download (bite: without the abort, the huge blob downloads; with it, aborted early)
- [ ] #3 deferred-finding label for wave-2a is empty (closed or converted to explicit tasks)
- [ ] #4 Cheap measured win pulled in from TASK-61: remove the gratuitous clone at transport_iroh.rs:350 (add_bytes(raw_nar.to_vec()) takes a borrowed slice and copies it into the store, on top of the file buffer read at main.rs:243). Take Vec<u8> by value or use add_path/add_stream. This is roughly HALF the measured 2.15x holder multiplier and is NOT the architecture question (that is TASK-61); measure the before/after
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
REVIEW REVISION (qa#6/codex#5): (1) task-51 owns the DEFAULT NarSize abort; task-46 HARDENS/fuzzes it + adds the HOSTILE-provider fixture (a peer that claims NarHash X but serves an oversized/wrong blob - no task owned this; task-41's bite is only corrupted bytes). (2) State the TRUST PRECONDITION: the NarSize-abort is valid ONLY because the narinfo (hence signed NarSize) comes from cache.nixos.org in wave-2a; the claim schema carries NO size field; v2 signed-narinfo-relay would break this - document it. (3) Claim-schema conformance fuzz stays.

## Forward-carried from TASK-64: the seed clone now has a number

`IrohProvider::seed`'s `raw_nar.to_vec()` (daemon/src/transport_iroh.rs) costs,
measured: 819 MB/s for a 110 MiB payload = ~141 ms and one full extra resident
copy, holder-side, per seed. Instrument: daemon/examples/iroh_throughput.rs, arm
`provider_seed`, run it with `just iroh-bench`. Use that arm to pin your
before/after rather than inventing a new harness.

Caveat on interpreting it: the arm times the WHOLE `seed` call, which is the
`to_vec` clone AND iroh-blobs' bao outboard computation over the payload. So
141 ms is an upper bound on what removing the clone can save, not the clone's
own cost. `blake3_oneshot` in the same run is 49 ms over the same bytes, which
is roughly what the outboard's hashing must cost - so the clone is plausibly
most of the remainder, but that split is not measured and you should measure it
rather than quote 141 ms as the clone.
<!-- SECTION:NOTES:END -->
