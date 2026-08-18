---
id: TASK-113
title: >-
  Coverage-guided fuzzing with a persistent corpus, behind its own `just fuzz`
  recipe
status: To Do
assignee: []
created_date: '2026-08-10 21:39'
updated_date: '2026-08-18 20:35'
labels: []
dependencies:
  - TASK-112
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The existing deterministic seeded loops remain valuable regression tests but are blind to coverage and keep no persistent discovery corpus. Add real coverage-guided, time-boxed fuzzing for the untrusted HTTP, NAR, narinfo, claim/offer, Iroh framing/compression, and BitTorrent metainfo/discovery surfaces. Select either a separately pinned nightly cargo-fuzz toolchain used only by just fuzz, or a stable coverage-guided honggfuzz/afl setup; no nightly enters the default devshell or crane build. Formalising only the existing seeded loops is an evidenced no-go/blocker, not a completion path for this task. Seed corpora from real repository artifacts, commit minimized crash regressions, replay them deterministically in just test, and report uncovered surfaces honestly.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A `just fuzz` recipe exists (time-boxed by default, target selectable), documented in the Justfile and named in TESTING.md as a SLOW/deliberate tier - explicitly not part of `just test`
- [ ] #2 At least 2 fuzz targets exist, with a corpus seeded from real repo artefacts rather than random bytes
- [ ] #3 Each target proven to BITE: introduce a known parsing defect, show the fuzzer finds it within the time box, then revert
- [ ] #4 Every crash found becomes a committed regression case replayed deterministically by `just test`, and the full-suite flake rate re-measured with flake_rate.py is still 0 failures at N>=20
- [ ] #5 The existing task-13 seeded loops are PRESERVED or explicitly subsumed with the reason stated - not silently deleted because a fuzzer now exists
- [ ] #6 STATED HONESTLY: what the fuzzer did NOT reach (untouched code paths, targets not written) so the coverage is not overread
- [ ] #7 Coverage-guided targets include BitTorrent metainfo/infohash, peer/discovery record and piece/framing parsers plus shared claim/offer dispatch; a seeded BitTorrent crash corpus is replayed in `just fuzz`.
- [ ] #8 An Iroh target fuzzes compressed negotiation/framing and bounded decode across raw fallback/version skew; coverage reports prove the new targets executed rather than only legacy HTTP/NAR parsers.
- [ ] #9 A coverage-guided engine is selected and its toolchain decision is recorded: separately pinned nightly cargo-fuzz or stable honggfuzz/afl. A seeded-loop-only result cannot close the task; if neither engine is viable, leave the task blocked with evidence and re-plan it. No nightly enters the default devshell or crane build.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Dropped the TASK-119 dependency and downgraded to Medium 2026-08-18 (COMPASS F1, owner steer #2: iroh/BitTorrent deprioritized). TASK-119 is the zero-injection BitTorrent journey, Low + deferred-pending-202, so this edge made a High task unreachable AND transitively blocked TASK-14, TASK-21 and TASK-36. AC#7/#8 (BitTorrent metainfo + iroh framing fuzz targets) are dead by the same steer and should be deleted when this is picked up.
<!-- SECTION:NOTES:END -->
