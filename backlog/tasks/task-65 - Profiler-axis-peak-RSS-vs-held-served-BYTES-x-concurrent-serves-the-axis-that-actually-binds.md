---
id: TASK-65
title: >-
  Profiler axis: peak RSS vs held/served BYTES x concurrent serves (the axis
  that actually binds)
status: Done
assignee:
  - '@me'
created_date: '2026-08-09 13:31'
updated_date: '2026-08-09 17:37'
labels: []
dependencies:
  - TASK-42
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-42 swept peer COUNT at roughly constant held-bytes and correctly found per-peer RSS flat at 19-21 MiB. That tells us nothing about the constraint that actually binds a real deployment: RSS as a function of the SIZE of the content a node serves, and of how many serves overlap. Without this axis, TASK-61's and TASK-62's RSS acceptance criteria are single-point and unfalsifiable - a claim about a SLOPE tested at one size. It is also the axis the owner goal asks for ('estimate RAM usage' for typical and pathological scenarios). Note also that the 18.75 GB @ n=1000 model output from TASK-42 is host-total for 1000 daemons packed on one host; it has no deployment meaning and must not be quoted as a scaling result. CAUTION on the oracle: peak RSS alone cannot reliably detect residency changes - glibc's allocator does not return freed arenas to the OS, so VmHWM may not drop even when the store correctly stops holding the NAR. The axis needs a residency oracle that is not VmHWM alone (store-side accounting, arena control, or malloc_trim at a defined point), or it will fail on a correct fix and pass on a wrong one.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 just profile grows a size axis: >=5 distinct NAR sizes, one holder + one fetcher, fitted slope (bytes of RSS per byte of NAR) with confidence interval via scalefit, for BOTH the holder and the fetcher
- [x] #2 A concurrency dimension: k overlapping serves of the same size, with the measured overlap asserted (a point whose overlap != k is INVALID, per the task-18 rule)
- [x] #3 The residency oracle is NOT peak RSS alone; state which mechanism is used and prove by mutation that it distinguishes 'the store released it' from 'the allocator kept the arena'
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
## Design

### The residency oracle (AC#3) - CHOSEN: store-side residency queried FROM the blob store
`IrohProvider::store_residency()` asks iroh-blobs itself what it currently holds
(`blobs().list().hashes()` + `blobs().status(h)` -> sum of Complete/Partial sizes).
Surfaced host-side as a daemon log line `IROH-STORE-RESIDENT blobs=N bytes_uncompressed_nar=M`,
next to the existing IROH-SERVED-TOTAL monitor.

REJECTED, with reasons:
 * VmHWM alone - monotone by kernel definition, so it CANNOT observe a release at all
   (this is the trap the task names; it fails on a correct fix).
 * VmRSS alone - glibc does not return freed arenas, so a released NAR can leave RSS flat.
 * malloc_trim / M_ARENA_MAX in-process - the workspace sets unsafe_code = "forbid",
   so libc::malloc_trim is not callable without changing a workspace-wide lint.
   MALLOC_MMAP_THRESHOLD_ via env would work but changes the allocator config of the
   system under measurement, making the slope non-representative of the default build.
 * smaps_rollup - still a process-level current-RSS reading; same arena problem.

STATED LIMIT: store residency answers 'does the STORE still hold this content'. With
MemStore that IS RAM residency by construction. Under a future FsStore it is not, and
the mapping would have to be re-derived (TASK-61).

MUTATION PROOF (AC#3): a Rust test constructs the two states with an IDENTICAL VmHWM
reading and OPPOSITE ground truth:
 (a) genuine release - a gc-enabled MemStore (`StoreRetention::GcEvery`), seed S bytes,
     release_all() (delete tags -> gc sweeps) -> residency 0.
 (b) store retains - seed S bytes, no release -> residency S.
Same process, same VmHWM (monotone), so an RSS-HWM oracle reports the SAME value for
both; the store-side oracle reports 0 vs S. VmRSS before/after is RECORDED (measured,
not assumed) to show what the allocator actually did.
Default stays `StoreRetention::RetainAll` - the supply-model decision is TASK-61's.

### The size axis (AC#1) - new module scripts/sizeaxis.py, driven by profile_p2p
 * >=5 distinct UNCOMPRESSED NAR sizes (default 8/16/32/64/128 MiB), one holder
   (node-b, seeds exactly that one NAR) + one fetcher (node-a), one pod per point.
 * SYNTHETIC graded fixtures built host-side: real single-file NAR framing, real
   sha256 NarHash, signed with the fixture key. Never realised by nix - the consumer
   is a host-side HTTP reader, because what is being measured is the DAEMON's
   buffering, and real nix would only add a client container per point.
 * fitted via scalefit with a NEW slope CI (scalefit gains slope_std_error +
   slope_ci95, proven by mutation in its self-test), for BOTH holder and fetcher.
 * size-appropriate extrapolation targets (256 MiB / 1 GiB / 8 GiB), NOT 10/100/1000
   which would extrapolate RSS at 10 BYTES.

### The concurrency dimension (AC#2)
 k overlapping serves of the same size, k distinct blobs so nothing dedupes. Overlap is
 measured AT THE HOLDER, not at the HTTP client: the provider records a per-transfer
 (started, completed) window from its own iroh-blobs event stream and logs
 IROH-SERVE-WINDOW; ss.max_overlap over those windows must equal k or the point is
 INVALID. Measuring overlap at the host-side GET would have been vacuous - the GET
 windows overlap even if the daemon serialised the peer fetches internally.

### Bonus, closing the open half of TASK-68
 The serve windows give the FIRST peer-side transport rate with a real denominator
 (bytes served / holder-side serving time). Plus a mechanical derived-quantity gate:
 two quoted ratios that are algebraically the same quantity have a ratio with ~zero
 variance across points; the gate computes it and refuses a restatement.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
## Forward-carried from TASK-64: instrumentation you can reuse, and one trap

TASK-64 added daemon/examples/iroh_throughput.rs (`just iroh-bench`), which
reads per-thread CPU nanoseconds from /proc/self/task/*/schedstat and context
switches from /proc/self/task/*/status, in-process and with no new dependency.
If your RSS-vs-bytes axis wants a CPU or wakeup axis beside it, that machinery
is there and already proven by mutation.

TRAP, measured the hard way, that bears directly on any /proc-derived counter
you add: UDP datagram counts read from /proc/net/snmp alone are WRONG for iroh.
iroh binds BOTH an IPv4 and an IPv6 socket and picks a path per connection, so
the same arm reported ~15 000 datagrams for 110 MiB in one run and ~10 in the
next - the IPv6 runs were invisible. /proc/net/snmp6 (`Udp6InDatagrams`) must be
summed in. Counting one family is worse than counting none, because the miss
looks like a measurement rather than a gap. Assume the same asymmetry for any
other network counter you reach for.

Also relevant to a bytes-axis: `provider_seed` (IrohProvider::seed, which
`to_vec()`s the caller's slice and computes the bao outboard) runs at 819 MB/s
for 110 MiB - i.e. ~141 ms and a full extra copy of the payload on the holder
side. That is the TASK-46 clone, now with a number attached.

## Forward-carried from TASK-63: what changed under you in profile_p2p.py

1. `run_speedup_arms` now takes `condition` + `shaping` and is driven by
   `run_speedup_conditions`, which runs it once per upstream condition. The
   report's speedup subtree is indexed `measured.speedup.by_upstream_condition`
   and each condition's block is keyed `speedup_<condition>`. If your size axis
   grows a speedup-like ratio, it must carry a condition suffix -
   `speedup_qualifier_violations` rejects a bare one, and
   `human_summary_violations` rejects an unqualified line in the PRINTED
   summary. Both are proven by mutation in `--self-test`.

2. `print_human_summary` is now `human_summary_lines(report) -> list[str]` plus
   a thin printer. Build your lines there; `main()` gates the returned text and
   a violation makes the run exit non-zero.

3. `throughput_bytes_uncompressed_nar_per_s` is GONE. It is
   `realise_rate_bytes_uncompressed_nar_per_s` and it says in its own key that
   it is 1/realise_s rescaled and NOT a transport rate (TASK-68). A real link
   rate now sits beside it: `upstream_nar_transport_bytes_compressed_wire_per_s`,
   derived from the testproxy's own per-record bytes_sent/duration_ms. Measured
   977.8 MB/s unshaped vs 19.9 MB/s shaped, so it tracks the link, not the CPU.
   THE PEER side still has no equivalent counter - if your axis can produce one
   (bytes served / time the provider was actually serving), that closes the open
   half of TASK-68 and is worth more than another RSS number.

4. Every speedup pod is now PREWARMED host-side (`prewarm_upstream_cache`) so no
   run carries an origin fetch the others do not. If you add an arm, prewarm it
   too or your first point differs from the rest for a reason that has nothing
   to do with your axis.

5. RSS numbers unchanged by all of this: per-peer VmHWM 19.8-21.8 MiB flat over
   n=1..16, RAM per held NarSize byte 2.16x on node-b. Both conditions agree,
   which is itself evidence that the shaping touched the link and not the memory.

## Progress: residency oracle landed (commit 43e3369)

MECHANISM CHOSEN: store-side residency (IrohProvider::store_residency), surfaced as
IROH-STORE-RESIDENT. Rejected alternatives and why are in the test file's module doc.
malloc_trim was NOT available: the workspace sets unsafe_code = "forbid", so
libc::malloc_trim cannot be called at all without changing a workspace-wide lint.

MUTATION EVIDENCE (both directions, both bite):
 * stub store_residency to report an empty store -> all 3 tests red on named checks
   ('the store must report exactly the seeded NAR', 'must report every seeded chunk',
   'RetainAll must still hold the blob after release_all')
 * make release_all not arm the sweep -> 2 tests red on 'after release_all + gc the
   store must hold nothing' (blobs: 1, bytes 33554544)

MEASURED: payload 33554544 B; VmHWM baseline 69414912 -> seeded 110739456 ->
released 110739456 -> retained 110739456. Peak-RSS verdict IDENTICAL in the released
and retained states and WRONG in the released one; store oracle correct in both.

GOTCHA FOUND (forward-carried to TASK-61): iroh-blobs' gc calls clear_protected()
before marking, so a free-running gc DELETES blobs mid-add. Measured: a 50 ms gc
alongside 512 seeds kept 501 of them. Hence StoreRetention::ReleaseOnRequest is armed
by release_all(), one sweep per request, not by the clock.

MEASURED NEGATIVE (do not re-attempt): current RSS could not be made to lie the way
VmHWM does. glibc returned ~97% of the payload whether the payload was one 32 MiB
blob or 512 fragmented 64 KiB ones. Interleaving live 64-byte pins to block
coalescing changes nothing, because the MemStore actor allocates on its OWN thread
and therefore in a different malloc arena from the caller's pins.

## Progress: size + concurrency axes landed (228b088, 6ef7b25, 5c6f8b3, 560edb9, 080374f)

MEASURED (five-size smoke grid 8/16/24/32/40 MiB, one replicate each, 5/5 valid):
  holder  2.0363 bytes RSS / byte of NAR  [95% CI 1.9852 .. 2.0873]  R^2 0.9998  O(n)
  fetcher 1.0322 bytes RSS / byte of NAR  [95% CI 0.9928 .. 1.0717]  R^2 0.9996  O(n)
  holder store residency 1.0000 NarSize bytes / byte  R^2 1.0000 (exact)
The gap between the holder's 2.04 RSS slope and its 1.00 residency slope is memory
the store is NOT holding - the seed-time file buffer plus the to_vec clone
(TASK-46). Consistent with task-42's single-point 2.15x, and now falsifiable.

CONCURRENCY oracle PROVEN ON REAL CONTAINERS (not just in the self-test):
  control    holder windows [352.0-387.9, 352.4-388.1, 352.2-389.2] ms, overlap 3, VALID
  serialised holder windows [364.2-383.7, 397.8-415.0, 427.6-444.3] ms, overlap 1,
             INVALID on 'MEASURED overlap at the holder is 1, not k=3'
RESIDENCY oracle PROVEN ON REAL CONTAINERS: stripping IROH-STORE-RESIDENT makes the
point INVALID on 'what its blob store holds is UNKNOWN, and unknown is not zero'.
scalefit slope CI proven by mutation: dropping the sqrt from se(b) takes measured
coverage 0.950 -> 0.083; a constant critical value takes it to 0.400.

DESIGN NOTES / gotchas for whoever follows:
 * overlap MUST be measured at the holder. k client request windows overlap even
   when the daemon serialises the peer fetches, so a client-side precondition
   cannot fail. That is the vacuous-oracle shape, and the serialised mutation
   above is what proves this one is not it.
 * the concurrency grid is 5 values because scalefit.MIN_POINTS is 5. A shorter
   grid is reported UNFITTED, not as a fit problem - a dev grid is not a broken
   instrument.
 * extrapolation targets for a SIZE axis must be sizes (256 MiB / 1 GiB / 8 GiB).
   The swarm axis's 10/100/1000 would predict the RSS cost of a ten-BYTE NAR.
 * DEFECT I SHIPPED AND CAUGHT IN SELF-REVIEW, worth naming as a class:
   ram_per_nar_byte(metrics, n) used the AXIS VARIABLE as its denominator. On the
   size axis n IS the byte count so it was correct and the bug invisible; on the
   concurrency axis n is k, so it divided RSS by 3 and reported the result as
   bytes-per-NAR-byte under a correctly unit-labelled key. THE UNIT GATE CHECKS
   WHAT A NUMBER IS CALLED, NOT WHAT IT WAS DIVIDED BY.
 * task-42's 18.75 GB @ n=1000 is now qualified AT THE FIT (not in prose
   elsewhere) as a host-total harness figure, and the printed summary says so.
   Proven by mutation.

## FINAL

All three ACs met and verified. Full gates: build/lint/test/e2e/profile all EXIT=0;
`just profile` at the default grid returns usable=True with 15/15 valid size points,
15/15 valid concurrency points (measured overlap == k for k=1..5) and 10/10 valid
speedup runs in both upstream conditions. Verification note on commit 080374f.

HONEST LIMITS a reader should carry forward:
 1. The size axis's consumer is a host-side HTTP reader, not real nix. It measures
    the DAEMONS' memory, which is the question; it proves nothing about nix's
    acceptance of what the daemon serves (S6 and check-rewrite-realnix own that,
    against the real fixtures).
 2. The payloads are SYNTHETIC single-file NARs: real framing, real sha256 NarHash,
    really signed - but never realised by nix, and the store path hash is derived
    from the content rather than from a derivation.
 3. The residency oracle answers 'does the STORE hold this'. With MemStore that IS
    RAM residency by construction; under an on-disk store it is not.
 4. The 'allocator merely retains' case is proven against VmHWM, which retains by
    kernel definition. It could NOT be constructed against CURRENT RSS on this host:
    glibc returned ~97-100% of the payload however the allocations were shaped.
 5. The fetcher slope measures the daemon's whole-NAR buffer under a client that
    drains as fast as it can. It is NOT a backpressure measurement; TASK-62 still
    has to build the slow-reading client for its AC#2.
<!-- SECTION:NOTES:END -->
