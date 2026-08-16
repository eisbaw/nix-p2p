---
id: TASK-100
title: >-
  ProviderDirectory contract hardening: batch, no-enumeration, policy-selection,
  eligibility
status: In Progress
assignee:
  - '@claude'
created_date: '2026-08-10 09:26'
updated_date: '2026-08-16 05:20'
labels:
  - wave-2b
dependencies:
  - TASK-66
  - TASK-91
  - TASK-102
  - TASK-104
  - TASK-106
  - TASK-107
  - TASK-110
  - TASK-114
  - TASK-140
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Replace the insufficient single-key/single-holder seam with a mechanism-neutral discovery domain boundary. Adapters batch named keys, return multiple holders and typed MISS versus UNAVAILABLE outcomes, enforce caller deadlines and publication eligibility, and report measured latency/control cost/capabilities. A separate resolver execution plan—explicit configuration now, frozen policy artifact later—chooses ordering, parallelism, racing and stop conditions. The seam/registry must not hardcode cheapest-first, Iroh-first or any production preference before holdout. Mechanisms include in-process/direct probe, LAN/node discovery, tracker and TASK-103's selected global-DHT implementation.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The seam batch-resolves named keys to multiple holders, with single-key compatibility; in-process and direct-probe adapters preserve existing behavior.
- [ ] #2 MISS, UNAVAILABLE(reason), deadline expiry and partial results are typed and observable; a dead mechanism cannot silently read as nobody-has-it.
- [ ] #3 Every adapter enforces the caller's total deadline and reports capabilities plus observed latency/control bytes/resource outcome; these are measurements, not a timeless cheap/expensive class.
- [ ] #4 No-enumeration is structural: no listing method exists, batches contain only asker-named keys, and a negative mutation proves inventory cannot be requested.
- [ ] #5 Ordering, parallelism/racing and stop conditions come from an explicit versioned execution plan. A named fixed baseline is testable, but neither the seam nor registry selects a production default before TASK-123.
- [ ] #6 Every publish-capable adapter consumes the single TASK-102 eligibility decision, preserves transport offers, and emits mechanism-neutral publication outcomes; bypassing the filter makes a test fail.
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
IMPLEMENTATION PLAN (TASK-100 contract/policy hardening on the TASK-140 ProviderDirectory seam; ADDITIVE default-method approach so fabric-libp2p/fabric-iroh compile unchanged and the gate stays green).

New module peer-fabric/src/resolve.rs carrying the batch/plan contract types; wired through capabilities.rs (2 new trait methods with DEFAULT bodies), fake.rs (overrides for test drive), fabric-libp2p directory.rs + announcer.rs (real-adapter conformance).

AC#1 (batch->multiple holders, single-key compat): new BatchResolveRequest{keys} positional; ProviderDirectory gains resolve_batch(request,budget)->BatchResolution with a DEFAULT impl that loops the existing single-key find_providers under the caller total deadline. Each key yields Vec<ProviderRecord> (multiple holders). find_providers stays the primitive => single-key compat + regression preserved. Bite: 1-key batch == find_providers; multi-key returns per-key holders.

AC#2 (typed MISS/UNAVAILABLE/deadline/partial, dead != nobody): KeyResolution enum {Found(Vec),Miss,Unavailable(Unavailable incl DeadlineExceeded),NotAttempted}. BatchResolution positional over the request, is_partial()/is_complete(). Bite: dead mechanism -> every key Unavailable, NEVER Miss; genuine absence -> Miss; the two distinguishable (mutation dead->Miss reddens).

AC#3 (total deadline + measured latency/control-bytes/resource, no timeless class): DEFAULT resolve_batch measures wall latency (integer ns) via Instant + threads REMAINING of caller deadline per key (composes with TASK-106, no double-bound). MechanismMeasurement{observed_latency_ns:u64, control_bytes:ControlBytes(Measured(u64)|NotInstrumented), resource:ResourceOutcome}. capabilities()->DirectoryCapabilities (DEFAULT conservative; libp2p override is_global). NO floats (ns/bytes as u64; unmeasured is a typed variant, not a fake 0). Bite: batch cut by deadline -> resource=DeadlineCut + NotAttempted tail; latency is a measured value.

AC#4 (structural no-enumeration + negative mutation): BatchResolution carries NO keys of its own (positional, aligned_with fail-fast like PeerHoldReply); NO listing method on the trait. New peer-fabric/tests guard scans resolve.rs/capabilities.rs source: a method returning plural ProviderRecord/KeyResolution MUST take a key-bearing param (BatchResolveRequest/ContentKey/&[ContentKey]); a synthetic list-all with no key param BITES the guard (self-test).

AC#5 (explicit versioned execution plan, NO production default before TASK-123): ExecutionPlan{version, order:MechanismOrder(AsRegistered|Explicit), parallelism, stop, provenance:NamedBaseline|HoldoutSelected}. NO impl Default; ONLY constructor fixed_baseline_v1() = AsRegistered(no cheapest-first/Iroh-first)+Sequential+FirstHolder, provenance NamedBaseline. A MechanismRegistry executor REQUIRES an &ExecutionPlan (caller-supplied, compile-enforced) and consults in registration order (no reshuffle); fail-fast typed refusal for non-Sequential until TASK-123. Bites: baseline order==AsRegistered & provenance==NamedBaseline (mutation to Iroh-first reddens); source-scan that no Default/production/cheapest/iroh_first ctor exists (self-test bites an injected one).

AC#6 (every publish-capable adapter consumes single TASK-102 eligibility; bypass fails): finalize after mapping the existing ApprovedPublicProvision/PublicNarClaim structural gate; peer-fabric cannot depend on daemon-core, so a sealed eligibility witness lives in peer-fabric and is minted only by the daemon-core allowlist authority; announce requires it; bypass -> test fails.

FROZEN SURFACE UNTOUCHED: no change to RawNarV1/ContentKey/ProviderRecord wire, signing preimage, claim schema, golden vectors. Contract/type hardening only. Gate per-crate (peer-fabric first) then full: cargo test peer-fabric/fabric-libp2p/daemon-core/daemon, fmt, clippy -D warnings, check-no-floats, check-discovery-no-shortcut --self-test, golden vectors, just e2e.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Re-scoped 2026-08-11: the SEAM itself is now TASK-140 (ProviderDirectory trait). This task is no longer a duplicate seam - it is the contract/policy hardening ON that seam: positional batch, structural no-enumeration, typed MISS/UNAVAILABLE, explicit versioned execution plan (policy selects, no default before TASK-123), and single TASK-102 eligibility consumption. Depends on TASK-140.

PROGRESS 2026-08-16 (commits 5a9a9fc AC#1-5 [swept into a concurrent sessions commit - see HAZARD below - code intact], 6667345 AC#6 contract).

PER-AC STATUS:
- AC#1 CLOSED. ProviderDirectory::resolve_batch (default method) batch-resolves asker-named keys to MULTIPLE holders per key under the caller total deadline; single-key find_providers preserved as the primitive, 1-key batch == single-key path. Bite: batch_resolution.rs::batch_resolves_named_keys_to_multiple_holders_with_single_key_compat.
- AC#2 CLOSED. KeyResolution{Found(Vec),Miss,Unavailable(reason),NotAttempted} typed+positional; a dead mechanism is Unavailable, never Miss; NotAttempted is the typed PARTIAL marker; BatchResolution.is_partial/is_complete observable. Bites: a_dead_mechanism_is_distinguishable_from_a_genuine_miss; resolve.rs unit key_resolution_variants_are_distinct_and_typed / partial_is_observable.
- AC#3 CLOSED. Caller TOTAL deadline enforced (remaining-share per key, composes with TASK-106, no double-bound); MechanismMeasurement{observed_latency_ns:u64, control_bytes:ControlBytes(Measured|NotInstrumented), resource:ResourceOutcome} is a MEASUREMENT not a class; DirectoryCapabilities a-priori (libp2p directory declares global). No floats. Bites: a_spent_total_deadline_yields_typed_partial_not_a_miss; latency_is_a_measured_value_and_control_bytes_are_typed (>=5ms sleep -> >=3ms measured); capabilities_are_declared_and_overridable.
- AC#4 CLOSED. Structural: BatchResolution carries no keys of its own (positional; aligned_with is the checked reader); NO listing method. Guard tests/no_enumeration_seam.rs (proven parser reused verbatim from daemon guard) scans capabilities.rs+resolve.rs: plural holdings out require key-bearing params in; NEGATIVE MUTATION self-test the_seam_guard_bites_on_a_synthetic_inventory_api (list_all/everything with no key BITES); keyed form passes.
- AC#5 CLOSED. ExecutionPlan versioned (nix-p2p/resolver-plan v1); NO impl Default, NO production/cheapest/fastest/iroh_first ctor; only fixed_baseline_v1 = AsRegistered (no preference) + Sequential + FirstHolder, provenance NamedBaseline (HoldoutSelected reserved, no minting ctor). MechanismRegistry REQUIRES a caller plan, consults in REGISTRATION order, fail-fast on non-Sequential. Bites: baseline_plan_is_versioned_named_and_preference_free; the_registry_consults_in_registration_order; first_holder_stops; an_explicit_caller_order_is_honoured; a_non_sequential_plan_is_refused; the_no_production_default_guard_bites (source guard + self-test).
- AC#6 PARTIAL. CLOSED: the SEAM CONTRACT - a PUBLISH-capable adapter is CONSTRUCTED WITH a PublicationEligibility authority (AdmitAllPublication explicit / RefusePublication fail-closed) and consults it fail-closed before emitting; AnnounceError::Ineligible; FakeAvailabilityAnnouncer consumes it. Bite: publication_eligibility.rs - a refusing authority blocks the publish and emits NOTHING (mutation neutering the consult reddens). RESIDUAL (filed): the SHIPPED fabric-libp2p announcer does NOT yet consume the seam-level authority - its public eligibility stays enforced one layer up by the ApprovedPublicProvision gate (the single TASK-102 PublicNarAllowlist decision, already structural + bite-tested in daemon-libp2p). ROOT CAUSE the frozen ProviderRecord no longer carries the sha256 NarHash the allowlist is keyed by, so allowlist enforcement is inherently PRE-record; making the shipped announce STRUCTURALLY require a seam-level eligibility WITNESS (minted from ApprovedPublicProvision) is a signature change across ~46 announce call sites -> deferred (risk amplified by a concurrent session mutating the shared tree this session).

FROZEN SURFACE: untouched. provider_record_golden 8/8 + check-golden-vectors reproduced byte-identical; ContentKey/ProviderRecord wire + signing preimage unchanged. Additive default-method approach so fabric-libp2p/fabric-iroh compile unchanged.

GATE (green): peer-fabric 111 lib + 6 batch + 7 plan + 3 no-enum-seam + 3 eligibility + 8 golden; fabric-libp2p lib 81; daemon-core+daemon all pass (incl daemon no_enumeration + golden_vectors); cargo fmt --check + clippy -D warnings clean (peer-fabric+fabric-libp2p); check-no-floats + check-discovery-no-shortcut --self-test + check-golden-vectors green; just e2e 5/5 incl s6-p2p (74.6s).

HAZARD (flag): a CONCURRENT session committed to master during this task (filed TASK-107/229/230 etc; its git add -A swept my AC#1-5 staged files into commit 5a9a9fc "backlog: file TASK-230" - code intact + verified, but my commit message for AC#1-5 was lost and it is co-mingled with an unrelated TASK-230 backlog file). The AC#6 commit 6667345 was staged+committed with explicit pathspec to avoid a repeat. Not marking Done: AC#6 shipped-adapter enforcement is a genuine residual.

REVIEW 2026-08-16 (mped-architect, read-only): GO on the honesty framing - AC#1/#2/#4 genuinely closed with biting tests; AC#3 closed on the default+registry paths; AC#5 core closed; AC#6 PARTIAL is honest and correctly not-Done (verified fabric-libp2p/src/announcer.rs untouched - only the fake consumes the authority). No finding crosses the project TCB (no bad store path / no wrong bytes on the wire). Two MEDIUM registry defects found + FIXED (commit 922b816): (1) resource outcome was inferred from verdict flags -> mislabelled spent envelope Completed / healthy-mixed DeadlineCut, contradicting is_complete(); now derived from a real deadline_cut flag (DeadlineCut>Completed>MechanismDown), bite the_registry_resource_outcome_reflects_the_real_envelope. (2) an Explicit plan naming an unregistered mechanism dropped its UnknownMechanism warning silently; now surfaced on stderr, bite an_unknown_mechanism_in_an_explicit_plan_is_skipped_not_fatal. LOW: softened the eligibility.rs "inherently pre-record" wording (ContentKey=derive(NarHash) so a ContentKey-keyed authority COULD consult at admit time; deferred for the 46-site announce-signature cost, not impossibility). Residual for TASK-231: when the shipped announcer is threaded, the seam authority must be BACKED BY the same allowlist, not a second copy (single-source). FINAL GATE re-confirmed green incl just e2e 5/5.

COMMITS: 5a9a9fc (AC#1-5, co-mingled by a concurrent sessions git add -A - see HAZARD), 6667345 (AC#6 seam contract), 922b816 (review fixes).
<!-- SECTION:NOTES:END -->
