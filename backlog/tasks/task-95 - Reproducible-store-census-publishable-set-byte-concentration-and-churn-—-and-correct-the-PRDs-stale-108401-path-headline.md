---
id: TASK-95
title: >-
  Reproducible store census: publishable set, byte concentration and churn — and
  correct the PRD's stale 108,401-path headline
status: To Do
assignee: []
created_date: '2026-08-10 08:43'
labels:
  - wave-2b
dependencies:
  - TASK-87
  - TASK-9
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Produces the denominator every cost model in the backlog is missing, and corrects the one it is currently using.

MEASURED TODAY (2026-08-10) from /nix/var/nix/db/db.sqlite opened with an immutable URI, reproducible in one query: 82,535 valid paths total; 70,663 are .drv (85.6% of paths, ~253 MiB, never served by cache.nixos.org and a privacy leak if published); 11,872 servable non-.drv paths holding 94,909 MiB; 6,311 of those carry a cache.nixos.org signature and hold 48,399 MiB — so the publishable set under the no-enumeration rule is 53.2% of paths and 51.0% of bytes. 2,244 paths carry the `ultimate` flag (locally built) and hold 31,110 MiB = 32.8% of ALL servable bytes; these are precisely the paths cache.nixos.org cannot serve, where p2p's advantage would be unbounded rather than a fraction, and they are excluded from publication by construction.

BYTE CONCENTRATION, which reshapes several designs: top 10 paths = 22.5% of servable bytes, top 100 = 67.1%, top 500 = 89.1%, top 1000 = 94.3%. 691 paths exceed 10 MiB and hold 91.7% of servable bytes, of which only 533 are signed. Fetch time is a function of bytes, not path count, so any design costed in paths is denominated in the wrong unit.

THE PRD IS STALE. PRD.md's measured-distribution table says 108,401 store paths / 155,621 MiB. Today's machine is 82,535 / 95,162 MiB. Either a GC ran or the figure counted something else; either way TASK-73, TASK-91, TASK-92 and TASK-93 all quote the stale number and their cost models inherit it.

THE NUMBER NOBODY HAS. Resident-store coverage (53%) is not the decision-relevant figure. What matters is REQUEST-weighted and BYTE-weighted coverage: of the bytes a real cold `nixos-rebuild` or `nix build` actually pulls, what fraction is (a) publishable under the signed-only rule and (b) resident on at least one peer. Expect requested-path coverage to look near-100% for the wrong reason — paths being substituted are on cache.nixos.org by construction — so the report must weight by BYTES and must separate 'requested' from 'resident'.

TRAPS. `nix path-info --all` includes .drv; never count or publish them. Nix records a signature only on paths it SUBSTITUTED, so a locally-rebuilt copy of a public path carries no local sig but IS public — 6,311 is a LOWER bound of unknown looseness, and the daemon already proxies and caches upstream narinfos (daemon/src/narinfo_cache.rs) so it can widen the set by consulting them; measure that widening, do not assume it. NarSize is uncompressed — do not mix with FileSize (see the peer-wins task).

CHURN. A one-day sample shows 763 signed paths registered in the last 24 hours = 12.1% of the entire publishable set in one day, and 79% of the trailing week's insertions landed in that single day. Publication and digest designs that assume 0.35% drift are modelling system-closure drift, not servable-set drift, and are wrong by ~35x.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 `just store-census` emits a table + JSON reproducing all six headline figures above on this machine within 1%. BITE: run it against a fixture store of known composition and require exact counts, and against a store containing only .drv paths — it must report 0 servable paths and 0 publishable bytes rather than counting them or dividing by zero.
- [ ] #2 The report separates locally-built (`ultimate`) bytes from signed bytes and prints publishable-bytes as an explicit fraction. BITE: mark one large path `ultimate` in a fixture DB and confirm the publishable-bytes figure drops by exactly that path's NarSize — a report that only counts paths will not move.
- [ ] #3 Request-weighted, BYTE-weighted coverage is measured from a real cold substitution on the S10 harness (TASK-87), reporting the fraction of REQUESTED bytes that are signed-publishable and the fraction resident on >=1 peer. BITE: run it on a node whose resident store already contains the whole closure and confirm the requested figure is derived from the daemon's request/byte counters (TASK-9, TASK-31), not from the store — if the two numbers are identical the measurement collapsed to the resident case.
- [ ] #4 Signed-set insert and delete rates are recorded over >=14 days from registrationTime and reported as both a daily rate and a burst maximum. BITE: the report must surface the burst — today's sample is 763 signed paths in 24h against 963 in 7 days; a tool that reports only a smooth weekly average hides the channel-bump burst and fails.
- [ ] #5 PRD.md's measured-distribution table is replaced with dated figures carrying a provenance line naming the exact command, and every backlog task quoting 108,401 or 155,621 gets a correction note. BITE: `grep -rn '108,\?401\|155,\?621' backlog/ PRD.md` returns only corrected/annotated references.
<!-- AC:END -->
