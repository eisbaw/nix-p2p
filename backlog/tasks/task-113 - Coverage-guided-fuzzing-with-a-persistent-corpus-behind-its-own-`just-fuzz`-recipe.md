---
id: TASK-113
title: >-
  Coverage-guided fuzzing with a persistent corpus, behind its own `just fuzz`
  recipe
status: To Do
assignee: []
created_date: '2026-08-10 21:39'
updated_date: '2026-08-10 21:39'
labels: []
dependencies:
  - TASK-109
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
WHAT EXISTS TODAY, so this is not filed as if from zero. task-13 added real fuzzing, but it is HAND-ROLLED and BLIND: seeded loops inside unit tests (20k iterations of path-traversal containment in both cache layers, 5k iterations of narinfo unknown-field identity). Those are valuable and must NOT be deleted. What they are not is COVERAGE-GUIDED: they sample a distribution someone wrote down, so they explore only as far as that distribution reaches, they keep no corpus between runs, and a crash found on one machine is not replayable on another.

WHY THIS REPO IN PARTICULAR. It parses untrusted bytes from the network in hand-rolled code, and TASK-36 already exists because the HTTP framing is hand-rolled and its edge cases were 'deferred behind the Nix hash gate'. Fuzzing is the cheap way to find the rest of that class before a rewrite, and to keep them found afterwards. Highest-value targets, roughly in order:
  * the HTTP/1.1 response reader (status line, headers, chunked framing, Content-Length vs Transfer-Encoding) - the exact surface task-36 owns
  * the NAR parser (nix-archive-1 framing: lengths, padding, nesting)
  * narinfo parsing + rewrite
  * the claim wire decoder - and note task-110 is a MISSING COUNT CAP found by reasoning; a fuzzer with a size budget is how the rest of that class surfaces
  * safe_key / cache path resolution (containment)

TOOLCHAIN DECISION, which this task must make explicitly rather than assume. rust-toolchain.toml pins an EXACT stable (1.97.1), deliberately: '-D warnings' plus a floating channel means an unrelated flake update can break a commit that changed no Rust. cargo-fuzz/libFuzzer needs NIGHTLY (-Z sanitizer). So one of:
  (a) a SECOND, separately pinned nightly toolchain used ONLY by `just fuzz`, never entering the default devshell or the crane build - keeps the gate's toolchain story intact but adds a pin to maintain;
  (b) honggfuzz-rs or afl.rs, which work on stable - no second toolchain, different tool maturity and ergonomics;
  (c) stay non-coverage-guided and just formalise the existing seeded loops - cheapest, and honestly the right answer if (a)/(b) prove heavy.
Pick ONE with the reason recorded. Do not quietly add a nightly to the default shell.

DETERMINISM CONSTRAINT (task-109). The gate has just been brought from a 45% failure rate to 0/20, and TESTING.md now forbids certifying 'test 0' from a non-deterministic gate. A fuzzer is unbounded by nature, so it MUST NOT run in `just test`. `just fuzz` is a deliberate, time-boxed invocation. What DOES belong in the gate is REGRESSION replay: every crash the fuzzer finds becomes a committed corpus entry replayed deterministically on every cycle. That is the durable value - the fuzz run finds it once, the gate keeps it found forever.

CORPUS. Seed it from real artefacts already in the repo (golden vectors, fixture narinfos, captured NAR headers) rather than from random bytes - a fuzzer that has to discover 'nix-archive-1' by chance wastes its whole budget. Corpus and crash artefacts are committed, small, and never contain fixture-tree paths (scripts/check-source-guard.py forbids .rs depending on the fixture tree; keep corpus entries self-contained).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A `just fuzz` recipe exists (time-boxed by default, target selectable), documented in the Justfile and named in TESTING.md as a SLOW/deliberate tier - explicitly not part of `just test`
- [ ] #2 The toolchain decision (nightly cargo-fuzz vs stable honggfuzz/afl vs formalising the existing seeded loops) is made and RECORDED with its reason; no nightly enters the default devshell or the crane build
- [ ] #3 At least 2 fuzz targets exist, with a corpus seeded from real repo artefacts rather than random bytes
- [ ] #4 Each target proven to BITE: introduce a known parsing defect, show the fuzzer finds it within the time box, then revert
- [ ] #5 Every crash found becomes a committed regression case replayed deterministically by `just test`, and the full-suite flake rate re-measured with flake_rate.py is still 0 failures at N>=20
- [ ] #6 The existing task-13 seeded loops are PRESERVED or explicitly subsumed with the reason stated - not silently deleted because a fuzzer now exists
- [ ] #7 STATED HONESTLY: what the fuzzer did NOT reach (untouched code paths, targets not written) so the coverage is not overread
<!-- AC:END -->
