---
id: TASK-46
title: 'HARDENING (wave-2a): claim-schema conformance + NarSize-abort spam defense'
status: To Do
assignee: []
created_date: '2026-08-08 20:13'
updated_date: '2026-08-09 23:07'
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

## Forward-carried from TASK-65: the before/after measurement for the to_vec clone

You own removing `self.store.add_bytes(raw_nar.to_vec())` in
daemon/src/transport_iroh.rs (IrohProvider::seed) - a borrowed slice CLONED into
the store, on top of the file buffer read at main.rs.

THE BEFORE NUMBER, and how to reproduce it. `just profile` now fits HOLDER peak
RSS against >=5 uncompressed NAR sizes and returns a slope with a 95% CI. On a
five-size smoke grid (8/16/24/32/40 MiB, one replicate each):

    holder  2.0363 bytes RSS per byte of NAR  [95% CI 1.9852 .. 2.0873]  R^2 0.9998

Dev loop: `nix develop -c just profile --skip-speedup --swarm 1 --repeats 1
--size-repeats 1 --concurrency 1,2`. The slope is at
models['size.holder_rss_hwm_bytes_ram']['slope_ci95'].

WHAT TO CLAIM. The clone is worth ~1.0x of the payload, so removing it should
move the holder slope from ~2.04 toward ~1.04. Judge it by whether the two
CONFIDENCE INTERVALS SEPARATE, not by two point estimates: the interval is
narrow (+/-0.026 at one replicate per size, narrower at three), so a real 1.0
shift is unmissable and a fake one is not claimable. That is the whole reason
this axis exists.

TASK-64 already timed the same code path: provider_seed runs at 819 MB/s for
110 MiB, i.e. ~141 ms and a full extra copy. So there is a LATENCY claim
available too, but it is holder-side seeding, not fetch latency.

DO NOT use peak RSS to argue the store 'released' anything - VmHWM is monotone
and cannot. If you need a residency statement, IrohProvider::store_residency()
is the oracle (task-65), proven by mutation in
daemon/tests/store_residency_oracle.rs.

## Forward-carried from TASK-72: the to_vec is still yours, and the boundary is now sharp

TASK-72 rewrote the SUPPLY path and it takes its buffer by value:
`materialise()` in transport_iroh.rs calls `store.blobs().add_bytes(raw)` with an
owned `Vec<u8>`, so that call site never had a borrowed slice and pays no copy.

`IrohProvider::seed(&self, raw_nar: &[u8])` is UNCHANGED and still does
`add_bytes(raw_nar.to_vec())`. Its `&[u8]` signature is what forces the copy, so
your fix is exactly: change the signature (or add an owned-Vec sibling) and move
the callers. There is no overlap with task-72 and no risk of both claiming the
same win - the site is now commented to say so.

MEASUREMENT NOTE: `seed` is only on the in-process test path now (the daemon uses
the supplier), so removing its clone will NOT move the profiler's holder slope.
If you want a number, measure it where `seed` is actually called - or state
plainly that the fix is a code-quality one whose runtime effect is confined to
tests. Do not quote the size-axis slope as evidence for it.

## Second thing forward-carried from TASK-72: the decline log is a NEW spam surface

This task already owns 'NarSize-abort spam defense'. Task-72 added a sibling on
the SERVE side: every declined get-request now prints one line,

    IROH-SERVE-DECLINED reason=<category> hash=<hex> why=<cause>

on stderr, from the provider's per-request task. That line is the fix for a real
problem (a bare counter could not distinguish a permissions error from a GC'd path
from a digest mismatch), and it is deliberately one line per DECLINE and never per
serve - but it is still unbounded in a peer's control. A peer that asks repeatedly
for digests we do not have gets us to write a line per request, at whatever rate it
can dial.

Severity is the same class as the abort spam you already own: log volume and I/O,
not integrity, and the daemon is outside the TCB either way. Treat them together
rather than inventing a second rate-limiter - and note the counters
(IROH-SERVE-COUNTERS, logged only when they MOVE) already carry the aggregate, so
whatever suppression you choose can drop repeats without losing the signal.

Suggested shape, not prescribed: rate-limit per (reason, peer) with a periodic
'suppressed N' line, so a burst costs one line and the count survives.
<!-- SECTION:NOTES:END -->
