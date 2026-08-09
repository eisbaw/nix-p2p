---
id: TASK-61
title: >-
  WAVE-2B DECISION: how a node SUPPLIES bytes it serves (MemStore residency vs
  regenerate-on-demand)
status: To Do
assignee: []
created_date: '2026-08-09 13:24'
updated_date: '2026-08-09 13:32'
labels: []
dependencies: []
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
