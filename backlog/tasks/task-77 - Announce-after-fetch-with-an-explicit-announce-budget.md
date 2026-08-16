---
id: TASK-77
title: Announce-after-fetch with an explicit announce budget
status: In Progress
assignee:
  - '@claude'
created_date: '2026-08-09 21:01'
updated_date: '2026-08-16 20:15'
labels:
  - wave-2b
dependencies:
  - TASK-72
  - TASK-61
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
PRD MVP scope names 'announce-after-fetch with an explicit announce budget'. Neither exists. Today a node announces only what the harness told it to (--p2p-claim), and the availability index answers hold-queries derived on demand - nothing publishes new availability after a successful fetch.

Announce-after-fetch is what makes the swarm GROW: a node that just fetched a NAR becomes a holder for it, so popular paths acquire holders naturally instead of depending on a few seeders. The BUDGET is the guardrail - unbounded announcing is a self-DoS (every announce invites dials, and dials cost RAM at 2.0 B/B per serve, see TASK-72's unbounded-serve problem) and it is also a privacy surface: what you announce reveals what you fetched.

Interacts with TASK-72 (a node must not announce what it cannot serve) and TASK-61 (the supply model decides whether a fetched NAR is retained at all, or regenerated from /nix/store on demand - which changes what announce-after-fetch even means, since after nix realises the path the store IS the copy).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 After a successful peer or upstream fetch, the node becomes a discoverable holder for that content, and a second node can fetch it FROM the first - shown end to end
- [ ] #2 The announce budget is explicit, configurable and ENFORCED: past the budget, announcing stops rather than degrading. Bite by mutation - remove the budget and the count grows unbounded
- [ ] #3 A node never announces content it cannot serve (consistency with TASK-72's index-coverage == provider-coverage requirement)
- [ ] #4 The privacy cost is stated: announcing reveals what you fetched. Interacts with the leech-mode flag (TASK-78)
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
## Forward-carried from TASK-61/TASK-72: what the supply model retains, and what it costs to announce

TASK-61 decided: nothing is retained. A node holds a NAR only while a serve of it
is in flight. So an announce budget is NOT a storage budget - announcing costs no
bytes at rest at all.

WHAT ANNOUNCING DOES COST, measured: one streamed BLAKE3 pass over the NAR
(`Blake3Digest::stream_raw_nar`, 64 KiB peak allocation whatever the size) plus
the `nix-store --dump` that feeds it. On the owner's store that is a full read of
the path off disk - the dominant cost, not the hash (task-64: the peer path is
CPU-bound at ~204 MB/s with 72% of the work below our code). So your budget's
real unit is DUMPS PER INTERVAL / bytes read, not bytes stored. Sizing it as a
storage budget would be sizing the wrong quantity.

SECOND COST, and it is the one that will bite: every announce also creates a
promise this node must be able to keep. Task-72's rule is that a positive
hold-answer implies a servable blob. `setup_iroh_provider` already refuses at
STARTUP to announce a NAR larger than `--iroh-max-serve-nar-bytes`, because a
claim the node would then decline is the same defect in a different disguise.
Announce-after-fetch must apply the same check: never publish a claim for
something the serve budget would refuse.

THIRD: the announce is only durable while the process is. The digest -> path
binding is in memory (task-82 would persist it). An announce budget that assumes
announcements survive a restart is assuming something false today.

TASK-77 plan (announce-after-fetch + budget). Design: reuse the TASK-231 announcer + verified store-announce path (verify_store_provisions -> announce_store_provisions/announce_public_provisions) dynamically after a fetch. NO second announce path.
- daemon-core: capture StorePath from narinfo into Correlation+NarMeta (in-memory only; never persisted, privacy). New PostFetchAnnounce seam trait. App gains optional hook; handle() fires it on a successful SignedNarHash fetch with the store path. RunConfig gains the field.
- daemon-libp2p/lib.rs: Libp2pAnnounceAfterFetch impl. on_fetched spawns a bounded task: budget check (integer, enforced) -> bounded wait for the local nix to materialise the path -> index.register -> verify_store_provisions (TASK-56 dump+sha256==NarHash gate = index-coverage==provider-coverage) -> size guard -> announce via the existing verified door (LAN AdmitAll or public allowlist). Announcer re-checks TASK-231 eligibility fail-closed => AC#3 no bypass.
- becomes-a-holder = arm-(a): register the realised /nix/store path in the shared AvailabilityIndex; the CatalogNarSupplier serves it on demand via nix-store --dump. No blob at rest.
- CLI: --libp2p-announce-after-fetch (default OFF = consume-only/leech, AC#4 toggle; TASK-78 interaction) + --libp2p-announce-budget N (integer). Node A = provider(server+announcer) with EMPTY provide set + announce-after-fetch; allowlist learned dynamically from the narinfo it fetches.
- Realisation timing (honest): daemon relays bytes; local nix materialises the path just after serve completes, so the hook waits (bounded, fail-safe) for materialisation before dump+announce. Never announces what it cannot serve.
- Bites: AC#2 budget mutation (remove cap -> unbounded); AC#3 eligibility (unallowlisted fetched path refused; remove consult -> reaches DHT).
- e2e swarm-growth scenario (reuse _create_libp2p): BOOT + A(provider+announce-after-fetch, no seeds) + B(consumer). A self-realises target via its OWN daemon (upstream egress>=1) -> announces; B discovers A via kad and fetches (0 upstream egress); kill-A control.
- Frozen wire unchanged (no RawNarV1/ContentKey/ProviderRecord/claim/golden change).

TASK-77 landed in commit 1367cf8 (NOT marked Done; owner owns AC/Done state).
GATE (all green): cargo fmt --check clean; clippy --workspace --all-targets -D warnings clean; check-no-floats OK; check-golden-vectors byte-identical (2 vectors, no wire change); check-discovery-no-shortcut --self-test OK; daemon-core + daemon-libp2p + daemon cargo test green; announce-after-fetch bites 4/4; catalog 10/10. just e2e: 7/7 scenarios PASS incl new s9-libp2p-grow 14/14.
Bites proven by mutation: AC#2 remove the remaining==0 budget guard -> budget/zero-budget tests redden; AC#3 remove the allowlist approval in eligible_provisions -> the public-door refusal test reddens (unallowlisted fetched path would reach announce).
e2e s9 confound fixed: node A fetches origin-direct (bypasses the testproxy) so the proxy NAR cache stays cold -> B is cleanly attributable to A and the kill-A control is a true origin miss (the first e2e run correctly caught the warm-cache confound at the kill-A oracle).

CODEX DEEP GATE NO-GO on 1367cf8. AC#1/#3-eligibility/#5 PASS (231 hole NOT reopened - full fail-closed chain confirmed). FAILs: (AC#2) budget bite tests reserve_in not the production on_fetched, so removing the production reserve() leaves tests green + announces unbounded (oracle at wrong boundary); budget spent before eligibility + never refunded = invalid-fetch exhaustion vector. (AC#3/TASK-72) network-derived StorePath under-validated + UNPINNED GC lifetime -> can announce stale/GC-removed holdings it cannot serve. Fix cycle: production-load-bearing budget mutation + reserve-after-eligibility/refund + StorePath validation + GC-serveability (pin OR withdraw-on-unserveable OR honest-defer meeting never-announce-what-you-cant-serve).

CODEX RE-GATE NO-GO(2) on ab3137f. AC#2 budget NOW FIXED; AC#1/eligibility/#5 PASS. AC#3 FAIL: real defects — (1) GC reconcile bite not production-wired (mutant removing dispatch->reconcile left tests green); (2) failed withdrawals forgotten (unconditional delete even on withdraw failure, no retry); (3) StorePath still accepts non-/nix/store (shape-only); (4) ambiguous-announce refund+forget leaves an untracked possibly-published record. TCB arbitration (orchestrator): eventually-consistent reconcile is acceptable per the project guarantee (a stale record -> Declined -> retry, within the TCB) IF the real defects are fixed + residual documented; strict GC-pin/periodic-sweep is a deferrable follow-up, not a blocker. Fix cycle dispatched.
<!-- SECTION:NOTES:END -->
