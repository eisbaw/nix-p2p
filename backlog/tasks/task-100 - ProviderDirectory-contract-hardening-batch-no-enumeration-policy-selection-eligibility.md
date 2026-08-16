---
id: TASK-100
title: >-
  ProviderDirectory contract hardening: batch, no-enumeration, policy-selection,
  eligibility
status: In Progress
assignee:
  - '@claude'
created_date: '2026-08-10 09:26'
updated_date: '2026-08-16 04:10'
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
<!-- SECTION:NOTES:END -->
