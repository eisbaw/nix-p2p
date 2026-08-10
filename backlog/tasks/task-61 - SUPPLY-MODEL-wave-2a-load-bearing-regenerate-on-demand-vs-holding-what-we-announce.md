---
id: TASK-61
title: >-
  SUPPLY MODEL (wave-2a, load-bearing): regenerate-on-demand vs holding what we
  announce
status: Done
assignee:
  - '@me'
created_date: '2026-08-09 13:24'
updated_date: '2026-08-10 09:29'
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
- [x] #1 The supply-model DECISION is written down with its cost: regenerate-on-demand + persisted bao outboards vs a bounded evicting content store. Records what it does to the PRD's 'no second copy of the store' position and to the seeding gap / re-hash cost
- [x] #2 Whatever is chosen, holder RSS is gated on a FITTED SLOPE over >=5 NAR sizes with CI (TASK-65's axis), not a single-point comparison, and the residency oracle is not VmHWM alone
- [ ] #3 N/A BY DECISION (recorded, not skipped): this criterion was conditional on choosing an on-disk store, and arm (a) regenerate-on-demand was chosen, so nothing is on disk to evict or reclaim after a kill -9. Its RAM analogue WAS delivered and is gated under TASK-72 AC#1: a numeric ServeBudget (max NAR size / max concurrent bytes / max serve duration) with the decline proven by mutation (bounded: 0 supplier calls, VmRSS rise 720,896 B; unbounded: 1 call, 156,946,432 B). If a future wave adopts an on-disk store, restore this criterion verbatim rather than treating it as settled
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

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
DECIDED: regenerate on demand via nix-store --dump; NO local blob copy exists at rest. Written into PRD.md's new 'Supply model' section, which also decides the irreversibility-map entry it was blocking.

WHY: on the owner's measured store (108,401 paths / 155,621 MiB NAR / p100 3186 MiB) holding everything would be ~304 GiB of RAM at task-65's 2.0033 B/B, and ONE p100 serve ~6.2 GiB. A full FsStore copy is 152 GiB of disk, which does not fit on this project's own dev host; a bounded one caps supply at the budget and throws away the whole-store property the --dump decision bought.

THE THREE COSTS ARE WRITTEN DOWN, not implied: a re-hash (a full dump) per cold serve; a REAL bounded seeding gap across restart (a published claim can be undiallable until a hold-query re-derives its digest - task-82 closes it for ~40 B/path); and in-flight memory becoming the entire memory cost, hence task-72's bound.

BAO OUTBOARDS REJECTED WITH A REASON: ~0.4% of content removes the tree recomputation but not the dump, which is the part that costs, and iroh-blobs 0.103 has no store that serves a blob whose outboard is persisted while its content is regenerated. The artifact actually worth persisting is the 32-byte digest (0.003% of content), filed as task-82.

AC#1 met (the decision + its costs, in PRD.md and these notes).
AC#2 met, and it MOVED: holder peak RSS 2.004426 [2.000129 .. 2.008723] -> 1.020232 [1.009284 .. 1.031180], DISJOINT intervals, fitted over 5 NAR sizes x 3 replicates; holder STORE RESIDENCY (IROH-STORE-RESIDENT, never VmHWM) 1.000000 [1.0 .. 1.0] -> 0.000000. The fetcher slope is unchanged as a control.
AC#3 is N/A AS WRITTEN and says so rather than being silently ticked: it was conditional on choosing an on-disk store. Its RAM analogue was delivered by task-72 (numeric budget knobs, an eviction bite proven by mutation); the kill-9 reclamation bite is vacuous by construction when nothing is on disk, and is NOT faked.

LIMIT: both profile runs exit 1 because --swarm 1 makes the SWARM axis unfittable, so the report is marked unusable-for-quoting. That verdict is about the swarm axis; the size axis is usable, honesty-compliant and red-flag-free in both. Run a full profile before quoting anything else.
<!-- SECTION:FINAL_SUMMARY:END -->
