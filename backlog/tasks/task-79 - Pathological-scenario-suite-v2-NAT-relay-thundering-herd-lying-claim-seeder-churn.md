---
id: TASK-79
title: >-
  Pathological scenario suite v2: NAT/relay, thundering herd, lying claim,
  seeder churn
status: To Do
assignee: []
created_date: '2026-08-09 21:02'
updated_date: '2026-08-18 20:36'
labels:
  - wave-2b
dependencies:
  - TASK-23
  - TASK-43
  - TASK-66
  - TASK-89
  - TASK-118
  - TASK-125
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The four TESTING.md S8 rows that TASK-43 (v1: slow-HIT, dead-holder, cold-start) explicitly deferred and named in its own honest-limits AC. Filed as real tasks rather than living only inside TASK-47's re-plan description. Each row already has a defined good/bad in TESTING.md S8 - use those, do not invent new ones.

- NAT-BLOCKED PEER: good = relay path used, or peer skipped fast; bad = undialable peer stalls the fetch. Note iroh has relay + holepunching, and the current test endpoints are bound loopback with the RELAY DISABLED and no discovery (transport_iroh.rs bind_loopback_endpoint) - so this scenario needs a topology that can actually exercise the relay, which the current single-host container setup cannot fully provide (see TASK-80).
- THUNDERING HERD on a popular path: good = bounded fan-out, no self-DoS, single-flight per path; bad = N concurrent identical fetches. Note TASK-23 already tracks single-flight for the testproxy; the daemon-side p2p equivalent does not exist.
- LYING / SPAM CLAIM: good = the NarHash gate rejects, wasted dials bounded, peer scored down; bad = an attacker-chosen huge blob downloaded in full before the gate. The streaming NarSize abort (TASK-51) already bounds the huge-blob case on the FETCH side; peer SCORING does not exist at all.
- SEEDER CHURN: good = resolution tolerates holders joining/leaving, no wrong bytes; bad = churn causes a wrong-bytes serve or a crash. Needs multi-holder (TASK-66) to be meaningful.

Severity calibration: the daemon and peers are OUTSIDE the trust base and nix re-verifies sig+NarHash, so none of these can produce wrong bytes in the store - they are availability/robustness failures. Do not inflate them to integrity bugs.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Each of the four scenarios runs in the harness and asserts its S8 good-row behaviour with a bite that fails if the daemon hangs, self-DoSes, or degrades unboundedly - plus a per-cell fault-OFF baseline so the bite is non-vacuous
- [ ] #2 Peer scoring exists at least minimally: a peer that serves a failing claim is demoted, and the demotion is observable and bounded (no permanent ban from one failure)
- [ ] #3 Single-flight per path on the p2p fetch path: N concurrent requests for the same NarHash produce ONE peer fetch, proven by a provider-side counter
- [ ] #4 Each scenario emits its cost (added latency, wasted bytes, RAM) into the profiling report, and honest limits name what the single-host testbed could not exercise (esp. real NAT/relay - see TASK-80)
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
## Forward-carried from TASK-61/TASK-72: the serve path your lying-claim and herd rows now hit

The holder no longer holds what it announces; it regenerates on demand behind an
admission gate. Two of your rows land squarely on it.

THUNDERING HERD. Single flight is implemented and proven: 8 concurrent peers
asking for one absent digest cost ONE regeneration, not 8
(`concurrent_requests_for_one_absent_digest_regenerate_it_exactly_once`). Removing
it makes the count go 1 -> 8, which is 8x the memory the budget charged for once.
Your container-scale herd row should assert the SAME invariant at the holder:
`IROH-SERVE-COUNTERS regenerated` must be far below `admitted` under a herd. If
they track each other, single flight has regressed and the budget is no longer a
bound. NOTE the follower path is a `tokio::sync::watch`, so a follower arriving
after the leader published cannot miss the wakeup - but a herd row that never
actually overlaps would not test any of this. MEASURE the overlap at the holder
(the task-18 rule, and `IROH-SERVE-WINDOW` gives you the intervals).

LYING CLAIM. There is now a second place a lie can be told, and it is on OUR
side: a supplier that declares one size and produces another. `materialise`
re-checks the produced length against the per-NAR bound and re-checks
`tag.hash() == requested hash`, declining as `supply_failed` rather than serving
the wrong blob under the right name. Worth a row: a holder whose store path has
been REPLACED since it was announced must decline, not serve. (The fetcher-side
lie - a peer serving more bytes than the signed NarSize - is task-51's streaming
abort and is unchanged.)

SEEDER CHURN gets easier and more interesting: a restart now empties the digest
binding, so a peer that was serving a digest a second ago legitimately answers
`declined_unknown` after a restart until a hold-query re-derives it (task-61's
accepted seeding gap; task-82 would close it). Model that explicitly rather than
treating it as a failure.

ORACLES AVAILABLE TO YOU, all machine-readable on the holder's stdout:
`IROH-SERVE-BUDGET` (what it agreed to), `IROH-SERVE-COUNTERS` (admitted /
regenerated / declined_too_large / declined_busy / declined_unknown /
declined_supply_failed), `IROH-STORE-RESIDENT` (what it holds NOW - not VmHWM),
`IROH-SERVE-WINDOW` (per-serve intervals on the holder's clock).

For Stage B, apply each pathology to both backends where the mechanism exists and report backend-specific unsupported cells; do not assume an Iroh failure mode maps to BitTorrent.

Downgraded 2026-08-18 (COMPASS F1): deps TASK-89/118/125 are all Low/deferred, so this is unreachable as filed. The CONTENT (thundering herd, single-flight, peer scoring, seeder churn) is genuinely valuable -- re-file it against the shipped libp2p path rather than resurrecting the iroh/BitTorrent framing.
<!-- SECTION:NOTES:END -->
