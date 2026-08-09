---
id: TASK-72
title: >-
  A single large NAR OOMs the node, and the index promises more than the
  provider can serve
status: To Do
assignee: []
created_date: '2026-08-09 17:45'
updated_date: '2026-08-09 17:45'
labels: []
dependencies:
  - TASK-65
  - TASK-50
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Two coupled gaps found 2026-08-09 while answering the owner's question 'do we need to publish and hold in memory what we have cached locally?'. Answer: no - and here is why it matters.

GAP 1 - UNBOUNDED SINGLE-SERVE COST (self-DoS). daemon/src/main.rs:243 setup_iroh_provider seeds EAGERLY at startup: std::fs::read(path) reads the whole NAR into RAM, provider.seed() clones it again into MemStore (transport_iroh.rs:350), and nothing ever evicts it. Combined with the TASK-65 holder slope of 2.0033 B RAM per B NAR, serving one NAR costs ~2x its size in RAM, unbounded. On the owner's real store the tail is brutal: mean NAR 1.44 MiB (~2.9 MiB RAM, fine) but p100 is 3186 MiB -> ~6.2 GiB of RAM for a SINGLE serve (model output, extrapolated past the fitted grid). Since the daemon is outside the trust base, ANY peer can request the largest NAR we announce; there is no size cap on what we agree to serve. The safety envelope's NarSize abort bounds a LYING peer on the FETCH side - it does not bound a legitimately huge NAR on the SERVE side. Severity: robustness/availability, not integrity (Nix still re-verifies sig+NarHash, so no wrong bytes) - but a peer can OOM us on demand.

GAP 2 - INDEX COVERAGE != PROVIDER COVERAGE. The availability index (TASK-50) answers hold-queries for the whole store by deriving NarHash->StorePath->--dump->BLAKE3 on demand, so it can say 'yes' for all 108,401 local paths. The provider can only actually SERVE what was eagerly seeded via --iroh-seed-nar. So a positive claim does not imply a servable blob. Today that is masked because the harness seeds exactly what it claims; in a real deployment the index would promise what the provider cannot deliver, producing dial-then-fail for every unseeded path.

Both gaps have the same root: the provider has no on-demand supply path. The fix direction is the PRD's stated position - hold nothing persistent, regenerate via nix-store --dump on demand, hold only the in-flight serve - which is exactly the decision TASK-61 owns. This task makes that decision LOAD-BEARING for wave-2a rather than a wave-2b nicety, and adds the size cap that is needed regardless of which supply model wins.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Serving is bounded: a configurable maximum served-NAR size (and/or a maximum total in-flight serve bytes) above which the node declines to serve rather than allocating. Prove by mutation that removing the bound restores the unbounded allocation
- [ ] #2 A hold-answer is only positive for content the provider can actually SERVE - index coverage and provider coverage are the same set, or the difference is explicit and tested (a claim for an unseeded path must not produce a dial-then-fail)
- [ ] #3 The eager startup seed is replaced by, or supplemented with, an on-demand supply path so that announcing does not require holding; measured with TASK-65's residency oracle (store residency after an idle period, not peak RSS)
- [ ] #4 Pathological row for TASK-43: a peer requests the largest announced NAR - the node must degrade (decline / bounded memory) rather than OOM. Bites: without the bound, RSS tracks the NAR size
<!-- AC:END -->
