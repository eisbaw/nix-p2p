---
id: TASK-61
title: >-
  SUPPLY MODEL (wave-2a, load-bearing): regenerate-on-demand vs holding what we
  announce
status: In Progress
assignee:
  - '@me'
created_date: '2026-08-09 13:24'
updated_date: '2026-08-09 23:12'
labels: []
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
DEFERRED TO WAVE-2B by Mark-emulator review - re-scoped from the original 'swap MemStore for FsStore', which quietly decided a PRD-level question as if it were a dependency change.

MEASURED FACT (TASK-42): IrohProvider uses iroh_blobs::store::mem::MemStore (transport_iroh.rs:273), so served content lives in RAM; a holder peaked at 2.15x the held NAR size. Per-peer ON-DISK footprint was 4096 B, flat.

BUT 2.15x IS NOT A LAW - roughly HALF of it is a five-line code artifact, not architecture: transport_iroh.rs:350 'self.store.add_bytes(raw_nar.to_vec())' takes a borrowed slice and CLONES it into the store, on top of the file buffer read at main.rs:243. So the multiplier is file buffer (1.0x) + gratuitous to_vec clone (1.0x) + outboard + ~17 MiB baseline. The to_vec removal (take Vec<u8> by value, or add_path/add_stream) is a measured non-architectural win and has been pulled into TASK-46. The residual ~1.0x is the actual design question, and that is what this task is.

THE DECISION (not an implementation): the PRD's seeding model is 'nix-store --dump on demand - no second copy of the store, no retention policy problem', and the irreversibility map lists 'whether a local blob copy exists at all' as a deliberate decision with a stated cost (re-hashing, seeding gap). Swapping MemStore->FsStore MAKES that decision by importing a different store type. The honest wave-2b framing is a supply-model choice: (a) regenerate-on-demand via --dump while PERSISTING only the bao outboards (about 0.4% of content at 16 KiB chunk groups - that is the artifact actually worth keeping on disk), versus (b) a bounded, evicting FsStore holding real content. This belongs with TASK-50 (availability index) and TASK-54 (footprint), routed through the TASK-47 wave-2b re-plan.

WHY IT IS NOT A WAVE-2A BLOCKER: the owner goal asks wave-2 to CHARACTERIZE RAM/disk and derive policy from what the models show. TASK-42 did that - root cause named at a specific line, per-peer disk 4096 B flat, PRD MVP promise (bandwidth offload) demonstrated at offload=1.00. What wave-2a must NOT do is publish a resource envelope while hiding this multiplier.

ORACLE WARNING for whoever implements the outcome: peak RSS ALONE cannot verify this. glibc does not return freed arenas to the OS, so VmHWM may not drop even when the store correctly releases the NAR - the AC can fail on a correct fix and pass on a wrong one. Needs TASK-65's residency oracle.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The supply-model DECISION is written down with its cost: regenerate-on-demand + persisted bao outboards vs a bounded evicting content store. Records what it does to the PRD's 'no second copy of the store' position and to the seeding gap / re-hash cost
- [ ] #2 Whatever is chosen, holder RSS is gated on a FITTED SLOPE over >=5 NAR sizes with CI (TASK-65's axis), not a single-point comparison, and the residency oracle is not VmHWM alone
- [ ] #3 If an on-disk store is chosen: a numeric budget knob, an eviction bite (fill past budget -> evicts rather than grows), and a kill-9-mid-serve-then-restart bite proving reclamation. 'Bounded' without a budget and an eviction rule is not an acceptance criterion
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Read the two arms against the owner's MEASURED store (108,401 paths / 155,621 MiB NAR; TASK-65 slope 2.0033 B RAM per B NAR) and write the verdict + its costs into PRD.md (the 'no second copy of the store' bullet and the irreversibility map entry it decides) and into this task's notes. AC#1 is prose with numbers, not code.
2. Capture the BEFORE fitted slope with 'just profile --skip-speedup --swarm 1 --repeats 1 --concurrency 1 --size-repeats 3' (>=5 NAR sizes, slope + 95% CI from scalefit), and record which oracle produced each number: peak RSS (VmHWM) for the slope, IROH-STORE-RESIDENT for residency. Never VmHWM for residency.
3. Hand the implementation to TASK-72; re-measure the SAME axis after and report both intervals. A single-size comparison is not admissible.
4. AC#3 is conditional on choosing an on-disk store. If arm (a) wins, say so explicitly and say what replaces it (a RAM budget knob + an eviction bite), rather than leaving the criterion silently unmet.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
## Forward-carried from TASK-65: your AC#2 oracle exists now, and one upstream trap

AC#2 IS SATISFIABLE NOW. `just profile` fits holder peak RSS against >=5 NAR
sizes and returns a SLOPE WITH A 95% CI
(models['size.holder_rss_hwm_bytes_ram']['slope_ci95']). Measured on a five-size
smoke grid: 2.0363 [1.9852 .. 2.0873] bytes of RSS per byte of uncompressed NAR,
R^2 0.9998 - consistent with task-42's single-point 2.15x and now falsifiable.
Whatever supply model you choose, gate it on that interval moving, not on a
single size.

THE RESIDENCY ORACLE THE TASK ASKED FOR: IrohProvider::store_residency() asks the
blob store what it currently HOLDS (blobs().list() + status(), in NarSize units),
logged as IROH-STORE-RESIDENT. It is NOT VmHWM and NOT VmRSS, and the
discrimination is proven by mutation in daemon/tests/store_residency_oracle.rs.
Rejected alternatives, with reasons, are in that file's module doc - note
especially that malloc_trim is NOT available: the workspace sets
unsafe_code = 'forbid'.

STATED LIMIT that bears directly on your decision: store residency answers 'does
the STORE hold this'. With MemStore that IS RAM residency by construction. If you
choose option (b) - a bounded evicting FsStore - that equivalence BREAKS and the
oracle stops being a RAM oracle. You would need to re-derive the mapping, and the
AC#3 'kill-9-mid-serve-then-restart proves reclamation' bite is about DISK, not
RAM, under that choice. Say which one each criterion is about.

THE PRIMITIVE FOR EVICTION, and the upstream race that shapes it. Landed:
StoreRetention::ReleaseOnRequest { sweep_interval } plus
IrohProvider::release_all(). The daemon default is UNCHANGED (RetainAll) - the
supply-model decision is yours, not made here.

  MEASURED TRAP: the sweep is ARMED BY release_all(), one sweep per request, NOT
  by the clock, and that is not a style choice. iroh-blobs' gc calls
  clear_protected() before it marks, so a free-running sweep can delete a blob
  whose named tag is not written yet. Measured: a 50 ms gc alongside 512
  concurrent seeds kept 501 of them - i.e. it silently ate 11 blobs. A BACKGROUND
  EVICTOR for this store is therefore not a policy option until that race is
  solved. iroh-blobs itself keeps Blobs::delete private for exactly this reason
  ('it does not work as expected when called manually').

BUDGET KNOB (your AC#3): if you go with a bounded store, the residency reading is
what the eviction bite should assert on - fill past budget, then residency must
DROP rather than the process growing. The profiler deliberately does NOT assert
'residency == seeded' precisely so a correct eviction change does not fail
`just profile`; it RECORDS resident_over_seeded_ratio instead.

## DECISION (AC#1), 2026-08-09/10 - written into PRD.md 'Supply model'

VERDICT: arm (a) - regenerate on demand via nix-store --dump, hold only the
in-flight serve. NO local blob copy exists at rest. Bao outboards are NOT
persisted. Commit e01b934 (PRD), implementation in task-72 (d83dd97 + follow-up).

THE NUMBERS THAT FORCED IT (owner's real store, nix path-info --json --all):
108,401 paths / 155,621 MiB NAR / p100 3186.03 MiB. At task-65's holder slope of
2.0033 B RSS per B NAR that is ~304 GiB of RAM to hold everything, and ~6.2 GiB
for ONE p100 serve (model output, extrapolated past the 8..128 MiB fitted grid).
A full FsStore copy is 152 GiB of disk - which does not fit on this project's own
development host (43 GiB free). A BOUNDED FsStore fits but caps supply at the
budget, discarding the property the whole-store --dump decision bought.

COSTS ACCEPTED, all three written into the PRD rather than implied:
  1. Re-hash per cold serve: one full dump (a read of the path off disk) + one
     BLAKE3 pass. The dump dominates - task-64 put the peer path at ~204 MB/s
     CPU-bound with 72% of the work below our code.
  2. A REAL, bounded seeding gap: a restart empties the in-memory digest binding,
     so a published claim can be undiallable until a hold-query re-derives it.
     Bounded failure (fetcher falls back upstream), never an integrity one.
  3. In-flight memory becomes the ENTIRE memory cost, hence must be bounded -
     which is task-72, not a follow-up.

BAO OUTBOARDS REJECTED WITH A REASON: ~0.4% of content (~0.6 GiB here) removes
the tree recomputation but NOT the dump, which is the part that costs; and
iroh-blobs 0.103 ships exactly two writable stores (mem, fs), each owning its
content, with no public way to serve a blob whose outboard is persisted while its
content is regenerated. Implementing it means a custom Store against an unstable
trait.

BETTER CANDIDATE, FILED AS TASK-82: persist the 32-byte digest binding instead -
~40 B/path beyond the existing registration, ~4.3 MB for 108k paths, 0.003% of
content - which closes cost #2 outright, because a /nix/store path's content is
immutable by Nix's own invariant. Not done here: it reverses availability.rs'
stated 'persist only the source of truth' position and deserves its own review.

## AC#3 IS N/A AS WRITTEN, and that is stated rather than silently skipped

AC#3 ('a numeric budget knob, an eviction bite, a kill-9-mid-serve-then-restart
bite') was conditioned on choosing an ON-DISK store. Arm (a) was chosen, so:
  * numeric budget knob -> DELIVERED, in RAM: --iroh-max-serve-nar-bytes
    (default 256 MiB) and --iroh-max-inflight-nar-bytes (default 1 GiB), both in
    NarSize units, logged at startup as IROH-SERVE-BUDGET.
  * eviction bite -> DELIVERED, in RAM: task-72's residency assertions, proven by
    mutation (disabling the post-serve arming leaves 67,108,976 B resident).
  * kill-9-then-restart reclamation -> VACUOUS under arm (a) and NOT faked: there
    is no on-disk blob store to reclaim. Per-peer on-disk state was measured flat
    at 4096 B (task-42) and is unchanged. If task-82 or a future FsStore lands,
    this criterion becomes live again and must be written then.

## AC#2: the FITTED SLOPES, before and after, with 95% CIs and the oracle named

Instrument: `just profile --skip-speedup --swarm 1 --repeats 1 --concurrency 1
--size-repeats 3` (TASK-65's size axis). Five NAR sizes (8/16/32/64/128 MiB) x 3
replicates = 15 points, 15/15 VALID in both runs, honesty.compliant true,
red_flags 0, size_axis_usable true in both.

  size.holder_rss_hwm_bytes_ram        (oracle: VmHWM, peak RSS)
    BEFORE  2.004426  [2.000129 .. 2.008723]  R2 0.999987
    AFTER   1.020232  [1.009284 .. 1.031180]  R2 0.999679
    -> THE INTERVALS ARE DISJOINT. Not a single-point comparison, and not a
       claim that could have been made either way.

  size.holder_store_resident_bytes_uncompressed_nar  (oracle: IROH-STORE-RESIDENT,
    what the blob store SAYS IT HOLDS - NOT VmHWM, which is monotone and cannot
    observe a release at all)
    BEFORE  1.000000  [1.000000 .. 1.000000]  (resident_over_seeded_ratio 1.0)
    AFTER   0.000000                          (resident_over_seeded_ratio 0.0)
    -> a node held one byte for every byte it announced, for the life of the
       process; it now holds none.

  size.fetcher_rss_hwm_bytes_ram       (the CONTROL)
    BEFORE  1.018814  [1.009204 .. 1.028424]
    AFTER   1.018838  [1.007846 .. 1.029831]
    -> UNCHANGED, as it must be: the fetcher's whole-NAR buffer is TASK-62 and
       this cycle did not touch it. A holder-side change that had moved the
       fetcher slope would have been evidence of something unintended.

ATTRIBUTION, and it needs care. The holder drop from ~2.00 to ~1.02 is NOT the
supply model saving memory by itself - it is that the supply path hands the store
an OWNED Vec, so there is no separate file buffer and no clone, where the old
eager path did `std::fs::read` then `add_bytes(raw_nar.to_vec())`. TASK-46 still
owns removing the `to_vec` from `IrohProvider::seed`, which is a DIFFERENT call
site (its `&[u8]` signature forces the copy) and is now test-only. Task-46's notes
say so, and say not to quote this slope as evidence for that fix.

HONEST LIMIT ON THE RUN ITSELF: `just profile` exited 1 in BOTH runs, and for the
same reason in both - `--swarm 1` gives the swarm axis one distinct n, below
scalefit's MIN_POINTS of 5, so it refuses to fit and marks the whole report
`usable: false`. That verdict is about the SWARM axis; the size axis is
`size_axis_usable: true`, honesty-compliant and red-flag-free in both. A full
`just profile` should be run before anything OTHER than these size-axis slopes is
quoted.
<!-- SECTION:NOTES:END -->
