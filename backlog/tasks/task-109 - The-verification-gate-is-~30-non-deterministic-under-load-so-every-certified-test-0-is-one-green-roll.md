---
id: TASK-109
title: >-
  The verification gate is ~30% non-deterministic under load, so every certified
  "test 0" is one green roll
status: In Progress
assignee:
  - '@me'
created_date: '2026-08-10 16:00'
updated_date: '2026-08-10 21:32'
labels:
  - hardening
dependencies:
  - TASK-9
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
FOUND BY THE TASK-91 RE-GATE, 2026-08-10, and it undermines every 'gate green' claim this project has made.

daemon/tests/fault_loop.rs::fault_mode_loop failed 3 of 10 full `cargo test --locked --workspace` runs under machine load (502 instead of 200; 'no response headers from 127.0.0.1:37601') and passed 3/3 in isolation. It is a pre-existing test from task-4, untouched by task-91.

THIS IS THE FOURTH MEMBER OF A FAMILY, and the family is the point:
  TASK-105  store_residency_oracle      13/64 under 8 concurrent processes, 0/125 sequential
  TASK-108  testproxy truncated_nar_fault_short_reads   1 failure under the first full parallel run
  TASK-84   cargo test --workspace flaked once under load after task-72 added a heavier binary
  THIS      daemon fault_loop::fault_mode_loop          3/10 under load

Unlike TASK-108 this one is in the DAEMON crate, so the 'crate-independent, not mine' defence does not apply to it.

WHY THIS IS ITS OWN TASK RATHER THAN A FOURTH FLAKE TICKET: the individual flakes have individual causes (whole-process /proc reads under libtest parallelism; port/timing races under load). The SYSTEMIC fact is that `just test` fails roughly 30% of the time under load, which means every 'test 0' this project has certified - in task notes, in Final Summaries, in git notes, and in the README's implied gate-green status - is ONE GREEN ROLL of a non-deterministic gate. The honest-failure discipline this project runs on assumes the gate is a truth oracle. It is not, and nobody knew the rate until now.

DO NOT FIX BY RETRYING OR BY SERIALIZING EVERYTHING. --test-threads=1 diagnoses; it is not a fix, and buying determinism by deleting parallel coverage is the anti-pattern. The question to answer first is WHICH tests are load-sensitive and WHY - the two known mechanisms are (a) whole-process measurements read while siblings allocate, (b) fixed/ephemeral port and timing assumptions under CPU contention.

Reference: TASK-105's reproduction method (N concurrent processes x M rounds) is the harness that found the rate; reuse it rather than reinventing it.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The flake RATE is measured, not guessed: run the full suite N>=20 times under a defined load and report failures per test, so 'the gate is green' has a known confidence rather than an assumed one
- [ ] #2 Each load-sensitive test is classified by MECHANISM (whole-process measurement vs port/timing race vs something else) and fixed at that mechanism - no blanket --test-threads=1, no retry-until-green
- [ ] #3 After the fixes, the same N>=20 run reports ZERO failures; a single green run is explicitly NOT accepted as evidence (that is what created this problem)
- [ ] #4 The project's honesty convention is updated: a cycle may not certify 'test 0' from one run while a known flake rate is outstanding - state the rate or state that it is unmeasured
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
DEPENDENCY CORRECTED 2026-08-10: this task previously depended on TASK-105/108/84, i.e. on the very flake instances it exists to fix - the umbrella was blocked behind its own instances. They are now handled AS PART OF this task (same defect family, batched deliberately), not as prerequisites.

DISK NOTE for whoever runs this: a prior review filled the filesystem to 0 MB by building inside a /tmp worktree, which killed all shell access. 20+ full suite runs is disk-heavy. There is 53 GB free as of this correction; clean scratch dirs as you go and check headroom before starting.

## MECHANISM DIAGNOSIS (before the numbers land) 2026-08-10

Measurement in flight: scripts/flake_rate.py, N=20, cargo test --locked --workspace, 14 CPU burners
on a 14-core host (2x oversubscription). Baseline unloaded run is GREEN in 28s; build is clean.
Shared CARGO_TARGET_DIR=$HOME/.cache/nix-p2p-target so 20 runs share ONE build dir (task-54).

THREE DISTINCT MECHANISMS identified by reading, to be confirmed against the measured failures:

M1 - WHOLE-PROCESS MEASUREMENT WITH CONCURRENT SIBLINGS (daemon/tests/store_residency_oracle.rs).
vm_bytes() at :105 reads /proc/self/status, a WHOLE-PROCESS figure. Three #[tokio::test]s live in
that one binary and libtest runs them concurrently IN THE SAME PROCESS:
  :152 residency_oracle_discriminates_release_from_allocator_retention  - reads VmRSS/VmHWM x8
  :308 current_rss_after_release_is_an_allocator_policy_not_an_oracle   - reads VmRSS/VmHWM x5
  :434 residency_oracle_reads_the_store_not_the_release_request         - reads none, but ALLOCATES
So :434's ~32 MiB payload lands in :152's baseline, and :152's lands in :308's. The instrument
cannot be sound while siblings allocate in its process. FIX: process isolation - one RSS-measuring
test per test TARGET (cargo runs targets sequentially; libtest parallelises only WITHIN a binary),
NOT --test-threads=1, which would buy determinism by deleting parallel coverage everywhere.

M2 - PRODUCT TIMEOUT TOO TIGHT FOR A LOADED HOST (daemon/tests/fault_loop.rs, 3/10 under load).
NOT a port race: Testproxy::spawn already does bind-then-report (--listen 127.0.0.1:0, parses the
announced address, :85-:107). The real cause is daemon/src/upstream.rs:94-95 -
    connect_timeout: 1000 ms, header_timeout: 1000 ms
and daemon/tests/common/mod.rs:236 builds the harness daemon with UpstreamHttp::new(), i.e. those
1 s DEFAULTS, never calling the existing with_header_timeout(). Under 2x oversubscription a healthy
loopback round-trip exceeds 1 s, so the daemon 502s a perfectly good upstream and the clean-path
assert_eq!(status, Some(200)) fails. That is exactly the reported '502 instead of 200'. FIX: the
harness daemon gets an EXPLICIT, generous header timeout, so the test measures passthrough
semantics rather than the host's scheduling latency.

M3 - WALL-CLOCK DEADLINE ASSERTIONS (same file). Three sites assert
    start.elapsed() < Duration::from_secs(2)  // 'must not hang'
A 2 s wall-clock budget under CPU oversubscription fails on correct code. FIX: express the bound in
terms of the CONFIGURED timeout - the property is 'it failed fast instead of waiting out its full
upstream timeout', which stays a real discriminator while surviving scheduling noise. A magic 2 s
constant is not that property.

PRODUCT CONCERN RAISED, NOT FIXED HERE (out of scope, needs its own task): the 1000 ms upstream
header timeout is a PRODUCT default, not just a test setting. On a loaded or WAN-distant host, real
users get spurious 502s against a healthy upstream. This task will make the TESTS load-independent;
whether the product default is right is a separate question and must not be silently changed under
cover of a flake fix.

## M4 - FOUND BY THE MEASUREMENT, NOT BY READING (testproxy/tests/faults.rs)

Run 3 of 20 failed on two tests I had NOT predicted, which is the point of measuring rather than
reasoning: connection_reset_fault_yields_no_response (faults.rs:103) and
truncated_nar_fault_short_reads (faults.rs:133). Both died on the SAME assertion shape -
    assert_eq!(fault_count(&fx, "connection-reset"), 1);   // left: 0, right: 1
so the fault fired and was observed by the client, but the proxy had not yet COUNTED it.

MECHANISM - a happens-before gap between the client's observation and the server's bookkeeping.
fault_count() reads the in-process Mutex<Log>. The proxy pushes the record at proxy.rs:108,
AFTER serve() has already written the response (or performed the reset) at proxy.rs:126-144. So
the client's get() can return - having fully observed the fault's effect - while the server thread
has not yet reached the push. Under CPU oversubscription the server thread is descheduled in
exactly that window and the count reads 0. This is NOT a port race and NOT a timeout.

This makes FOUR mechanisms, and it invalidates the framing in the task title that the flakes are
one phenomenon. They are four, in three crates.

FIX CHOICE, stated with its tradeoff rather than hidden. Two candidates:
  (a) strengthen the proxy so the record is pushed BEFORE the client-visible effect, making the
      test's assumption true by construction; or
  (b) weaken the observation to the proxy's ACTUAL contract - the fault is recorded EVENTUALLY -
      by polling for the expected count under a deadline.
(a) is the stronger fix but does not compose with a connection RESET, where the client-visible
effect IS the abrupt close and cannot be ordered after a later bookkeeping step without
restructuring serve()'s outcome assembly. Taking (b), implemented as a deadline-bounded wait and
documented as such. To be explicit about what that is and is not: this is NOT retry-until-green -
it does not re-run the test hoping for a different roll. It waits for an event the design
GUARANTEES will happen, and FAILS if it does not happen within the deadline. It is the same idiom
already blessed in this repo at store_residency_oracle.rs:137 (poll_until_released, commented
'this bounds a HANG, it is not a timing assertion'). The residual weakness, stated: if the proxy
ever stopped recording faults entirely, this assertion would take the full deadline to fail
instead of failing instantly.

## M5 - ALSO FOUND BY MEASUREMENT (testproxy/tests/premature_eof.rs)

Run 4 of 20 failed on a THIRD unpredicted test:
    premature_eof.rs:79  'the second request must not be served a complete 200 from a poisoned cache'
with the proxy logging 'upstream fetch failed for /nar/x.nar: Broken pipe (os error 32)'.

TWO STACKED DEFECTS, both real:

(a) THE HAND-ROLLED ORIGIN CLOSES WHILE ITS PEER IS STILL WRITING. short_origin() (:18-:34) does a
    SINGLE stream.read(&mut buf) to 'drain the request head', writes a 2-of-10-byte response, and
    drops the stream - closing the socket. One read() is not the request head; it is whatever
    arrived so far. Under CPU oversubscription the origin thread can write and close while the
    proxy is still writing its request, and the proxy takes EPIPE. The origin, not the proxy, is
    the party violating the protocol here.

(b) THE ASSERTION CANNOT TELL THE TWO FAILURES APART. complete() means 'body length == advertised
    Content-Length'. When the upstream fetch dies with EPIPE the proxy answers a 502 error page
    whose body DOES match its own Content-Length - so second.complete() is true and the test
    reports 'served a complete 200 from a poisoned cache', which is NOT what happened. The cache
    was never poisoned. The assertion accuses the wrong component, which is how a 30% flake rate
    stays unexplained for as long as this one did.

FIX BOTH. (a) drain until the CRLFCRLF end-of-head before responding, so the origin never closes on
a half-written request. (b) assert the property actually meant - the second response is a 200 whose
body is SHORT of its Content-Length - so a 502 fails loudly as a 502 instead of masquerading as
cache poisoning.

RUNNING TALLY after 4 of 20 runs: 2 PASS, 2 TEST_FAILED, 0 build/harness errors. Three distinct
test files have now flaked, in two crates, and NONE of them is the store_residency_oracle that
task-105 and this task's own description were written around. The prior diagnosis was not wrong,
it was incomplete - and it was incomplete in the direction that matters, because the gate's
failure rate is the UNION of all of these, not the one flake anybody had reproduced.

## DEFECT-SPECIES INVENTORY - fix the CLASS, not the instances that happened to fire

Three test files flaked in 5 runs. Sweeping the tree for each mechanism's SIGNATURE shows the
observed failures are a minority of the sites carrying the same defect. Fixing only what fired
would leave the rest to surface later and re-open this task.

SPECIES A - WALL-CLOCK UPPER BOUNDS (load-sensitive by construction). 3 sites:
    daemon/tests/fault_loop.rs:186   elapsed() < 2s      'must not hang'   [FIRED]
    daemon/tests/fault_loop.rs:198   elapsed() < 2s      'must not hang'   [FIRED]
    testproxy/tests/faults.rs:53     elapsed() < 150ms   'narinfo wrongly delayed'  [LATENT]
  Note fault_loop.rs:252 asserts elapsed() >= 150ms - a LOWER bound, which CPU contention can only
  make more true. It is not a flake risk and must not be 'fixed'; touching it would weaken a real
  assertion. Upper bounds are the species, not elapsed() as such.

SPECIES B - THE HARNESS DAEMON INHERITS PRODUCTION'S 1 s TIMEOUTS. 1 site, wide blast radius:
    daemon/tests/common/mod.rs:236   UpstreamHttp::new(url)  - never calls with_header_timeout()
  Every daemon integration test built on spawn_daemon/spawn_daemon_with runs against connect and
  header timeouts of 1000 ms (daemon/src/upstream.rs:94-95).

SPECIES C - READING THE PROXY'S LOG WITHOUT A HAPPENS-BEFORE EDGE. 10 sites:
    testproxy/tests/faults.rs:56, 82, 103, 133, 159, 186, 214   (fault_count, 7 sites; 103+133 FIRED)
    testproxy/tests/passthrough_cache.rs:24, 40, 60             (stats() after get(), 3 sites)
  All read state the server thread writes at proxy.rs:108, AFTER the client-visible effect.
  2 of 10 fired at ~30% load. The other 8 are the same bug and have simply not been unlucky yet.

SPECIES D - HAND-ROLLED ORIGIN DRAINS THE REQUEST WITH ONE read() THEN CLOSES. 3 sites:
    testproxy/tests/premature_eof.rs:26   [FIRED - EPIPE at the proxy]
    daemon/tests/header_hygiene.rs:140    [LATENT]
    daemon/tests/header_hygiene.rs:194    [LATENT]
  One read() is not a request head. Closing on a half-written request gives the peer EPIPE.

SPECIES E - WHOLE-PROCESS RSS READ WHILE SIBLING TESTS ALLOCATE. 1 binary, 3 tests:
    daemon/tests/store_residency_oracle.rs  (:152 and :308 measure, :434 allocates 32 MiB)
  Reproduced 13/64 by qa-test-runner under 8 concurrent processes. Did NOT fire in the first 5 runs
  here, because this harness applies CPU load rather than running concurrent copies of the suite -
  a real limit of this measurement, recorded rather than hidden.

That is 18 sites across 5 species, of which 5 have actually fired. The gate's failure rate is the
UNION.

## VERIFIED ASSUMPTION: cargo serialises test TARGETS (this is what makes the species-E fix sound)

The species-E fix - give each RSS-measuring test its own test target - only works if cargo never
runs two test binaries at once. Checked rather than assumed, against run-001.log of this very
measurement: across all 27 targets the log strictly alternates
    Running tests/X -> test result: ... -> Running tests/Y -> test result: ...
with never a second 'Running' line before the preceding target's result. Targets are sequential.

WHY THIS SETTLES IT. /proc/self/status is PER-PROCESS. The 14 CPU burners this harness runs cannot
move it, and neither can a sibling test BINARY, because that is a different process. The ONLY thing
that can corrupt the reading is a test sharing the same process - which is exactly what libtest's
in-binary parallelism creates and what the split removes. So process isolation is not a mitigation
here, it is the elimination of the mechanism.

STATED DEPENDENCY, so a future reader is not ambushed: this rests on OBSERVED behaviour of the
cargo in this flake, not on a documented guarantee. If cargo ever runs test targets concurrently
(there has been unstable work in that direction), the two RSS tests would share a machine but still
NOT share a process, so /proc/self/status stays correct - what would change is memory PRESSURE, not
the accounting. The reading would remain sound; only the anti-vacuity threshold could get noisier.
That is a materially weaker exposure than today's, where a sibling's 32 MiB lands directly in the
baseline. A code comment records this so nobody merges the targets back together to 'tidy up'.

## LATENT, UNVERIFIED - recorded so it is not mistaken for cleared ground

Swept the rest of the suite for the same signatures. testproxy/tests/enospc.rs carries none.

serve_budget_and_supply.rs uses FIXED-DURATION sleeps as synchronisation before assertions
(:630 sleep 500ms, :675 sleep SWEEP*6, :815 sleep 300ms). Same family as species A - a wall-clock
assumption about how much progress the machine makes in a fixed window - but NONE has fired in this
measurement, so they are listed as LATENT and NOT counted among the 18 sites. They are not being
fixed in this task: changing assertions that have never failed, on the theory that they might, is
how a flake fix turns into an unreviewable sweep. If the AFTER measurement is clean they stay as
they are, and this note is the record that they were looked at and consciously left.

Distinguish these from the harmless ones, which must NOT be touched:
  - sleeps INSIDE poll loops (store_residency_oracle.rs:147 25ms, serve_budget_and_supply.rs:152)
    are the polling interval of a deadline-bounded wait, not a timing assumption.
  - store_residency_oracle.rs:450 sleeps 500ms to give a gc that MUST NOT release something the
    chance to release it. Load making that sleep effectively longer STRENGTHENS the assertion.
  - iroh_safety_envelope.rs:237 sleeps 3600s - a deliberate never-completes stub, not a wait.

## BEFORE MEASUREMENT - COMPLETE, N=20 (AC#1 SATISFIED)

  command       cargo test --locked --workspace
  load          14 CPU-burner processes, 14-core host (2x oversubscription)
  N             20 runs, IDENTICAL binaries, nothing edited between runs
  median run    64.3 s
  FAILURE RATE  9/20 = 45%
  exit codes    {0, 101} only - build_failed 0, harness_error 0, so every data
                point is a genuine libtest failure and none is a compile error
                or a missing binary miscounted as a flake

PER-TEST (10 failing instances across 9 failed runs; run 3 failed two at once):
    4  connection_reset_fault_yields_no_response          species C
    3  premature_eof_nar_is_not_committed_or_served_...   species D
    2  truncated_nar_fault_short_reads                    species C
    1  residency_oracle_discriminates_release_from_...    species E

THREE CORRECTIONS TO THIS TASK'S OWN PREMISE, all in the direction of worse:

1. THE RATE IS 45%, NOT ~30%. The title's '~30%' was an impression. Under a stated load and a
   stated N it is 45%, i.e. the gate fails almost every other run. Every 'test 0' certified by a
   single run of this gate had a ~55% chance of being that number honestly.

2. THE DOMINANT CAUSE IS NOT THE ONE THIS TASK WAS WRITTEN AROUND. task-109 and task-105 were both
   framed on store_residency_oracle. It caused 1 of 10 failing instances. Species C - reading the
   testproxy log with no happens-before edge - caused 6, in a crate task-108 had dismissed as
   'crate-independent, not mine'.

3. SPECIES A AND B NEVER FIRED. fault_loop did not fail once in 20 runs, so the 3/10 rate reported
   for fault_mode_loop earlier, and my own M2 (1 s upstream timeout) and M3 (2 s wall-clock)
   diagnoses, are NOT confirmed by this measurement. They were derived by READING. They are
   plausible and the sites are real, but this run is not evidence for them and must not be quoted
   as if it were. Whatever load reproduced fault_loop earlier, 14 CPU burners is not it.

Species E DID fire once, on the last run - after I had written in the notes above that it had not
fired in 5 runs. At 1/20 it is real but weakly evidenced here; the 13/64 figure from the 8-
concurrent-process reproduction remains the stronger evidence for it, and the two stressors are
not interchangeable.

## FIXES APPLIED (AC#2) - each at its mechanism, with the bite checked

SPECIES C (6/10 failing instances - the dominant cause). testproxy/tests/faults.rs gains
await_fault_count(); passthrough_cache.rs gains await_stats(). Both wait for the record the proxy
is GUARANTEED to push and then assert the ORIGINAL equality, so an over-count or a fault that never
fired still fails. 11 sites converted (7 fault_count + 4 in passthrough_cache). The 4th
passthrough_cache site was found while editing, not by the measurement: request_log_records_fields_
and_gap reads records() and does .find(..).unwrap(), which would have panicked with an unhelpful
'unwrap on None' rather than a diagnostic. The zero-assertion site ('repeat must not touch
upstream') is sound because a record carries its received AND upstream fields and is pushed as one
unit, so waiting for received_total==2 makes the paired zero non-vacuous - previously it could pass
by reading an EMPTY log.

SPECIES D (3/10). premature_eof.rs: the fake origin now drains to the CRLFCRLF terminator instead
of taking one read() and closing, so it stops handing the code under test an EPIPE. Separately, the
assertion was made to say what it means - status 200 AND short body, rather than bare !complete() -
because a 502 error page is 'complete' with respect to its own Content-Length, so the old form
reported cache poisoning when the real event was a broken upstream fetch.

SPECIES E (1/10). store_residency_oracle.rs split into THREE targets sharing
tests/residency_support/mod.rs: the discrimination proof, the allocator-policy measurement, and the
RetainAll direction. The third measures no RSS but seeds 32 MiB, so it is isolated too. Cargo runs
targets sequentially (verified above), and /proc/self/status is per-process, so each RSS test is now
the only allocator in the process it measures.
  THE FIX REPAIRED THE MEASUREMENT, NOT JUST THE PASS RATE - the strongest evidence it is the right
  fix. Before, corrupted runs printed 'allocator returned = 298.4%' and '-1.0%', and a VmRSS
  baseline HIGHER than the same test's seeded reading. After isolation:
      VmRSS baseline 37261312 -> seeded 71290880 (a 34.0 MB rise for a 33.5 MB payload)
      allocator returned 99.2% (test 1) and 96.8% (test 2), consistent with the documented ~97%
  A fix that only silenced the failure would not have made the numbers coherent.

SPECIES A (0/10 - NOT reproduced here). Two wall-clock upper bounds in fault_loop.rs now compare
against HARNESS_HEADER_TIMEOUT, stating 'it did not wait out its upstream deadline' instead of 'the
host can do a loopback round-trip in 2 s'. testproxy/tests/faults.rs's latency test was made
DIFFERENTIAL: the old 'narinfo < 150ms' asserted host speed; it now asserts narinfo is at least
200 ms faster than the deliberately-delayed nar, so machine slowness cancels between two samples
taken under the same conditions. TRADEOFF STATED: the fault_loop bound loosens from 2 s to 10 s. It
still catches the hang it exists to catch, because a regression that waits out the timeout takes
>= 10 s. The old 2 s was ~400x the observed ~5 ms, so this costs little real discrimination.
  fault_loop.rs:252 (elapsed() >= 150ms) was deliberately LEFT ALONE: a lower bound cannot be
  broken by contention, and 'fixing' it would have weakened a real assertion.

SPECIES B (0/10 - NOT reproduced here). daemon/tests/common/mod.rs now builds the harness upstream
with an explicit HARNESS_HEADER_TIMEOUT of 10 s instead of silently inheriting the PRODUCTION 1 s
default. Checked first that no daemon test depends on the 1 s value (none calls
with_header_timeout; iroh_safety_envelope configures its own separate dial/body timeouts).

MUTATION CHECK, because a passing test proves nothing about whether a REWRITTEN assertion still
bites. The riskiest rewrite was the differential latency assertion. Mutated the fault to
'latency_nar_ms=400&latency_narinfo_ms=400' so scoping is broken, and the assertion caught it with
a diagnostic that names the numbers:
    narinfo wrongly delayed: narinfo 402.493189ms is not clearly faster than the
    deliberately-delayed nar 400.664622ms (baseline 620.801us)
That run also incidentally confirms the old assertion's defect: the unloaded baseline is 620 US,
so 'baseline < 150ms' had a ~240x margin unloaded and none at all under contention. Mutant
reverted.

## AC#4 SATISFIED - honesty convention updated

TESTING.md gains a section 'Gate honesty - test 0 is a claim about a DISTRIBUTION (task-109)' in the
existing honesty area. Five binding rules: no 'test 0' from a single run while a flake rate is
outstanding (state the rate or state it is unmeasured); a rate quoted without its N and load is
rejected in review; re-measure with scripts/flake_rate.py after any change to harness
synchronisation, process/thread layout or timeouts; fix at the mechanism, with --test-threads=1 and
retry-until-green named as rejected; and a single green run is explicitly NOT evidence a flake is
fixed. It states the uncomfortable consequence plainly - every 'test 0' certified before 2026-08-10
was one sample from a distribution that was green about 55% of the time, and while the code was
very likely fine, the EVIDENCE was worth about half what it was quoted as being.
(Checked that daemon/tests/doc_citations.rs scans daemon/src/*.rs only, so prose in TESTING.md is
not subject to the citation gate.)

## PRODUCT CONCERN FILED AS TASK-111, NOT SILENTLY FIXED

The 1000 ms upstream connect/header timeout is a PRODUCT default. This task raised it only for the
HARNESS. Changing the product constant under cover of a flake fix would have buried a real decision,
so TASK-111 carries it with the evidence needed first (real-upstream header latency at realistic
RTT, which task-33/35 already own) and the connect-vs-header distinction the current single number
elides.

## MY FIRST FIX FOR SPECIES A WAS WRONG, AND THE RE-MEASUREMENT CAUGHT IT

The first AFTER run reached 13/20 clean and then FAILED on run 14 - on
latency_fault_delays_only_the_targeted_kind, THE TEST I HAD JUST REWRITTEN:
    narinfo wrongly delayed: narinfo 278.344264ms is not clearly faster than the
    deliberately-delayed nar 405.337084ms (baseline 19.990158ms)

WHAT I GOT WRONG. I replaced an absolute upper bound (narinfo < 150ms) with a DIFFERENTIAL one
(narinfo + 200ms < delayed) and called it load-independent. It is not. Both sides are still SINGLE
samples, so the common-mode cancellation I claimed only holds if the noise is stationary between
the two measurements. It is not: one scheduling hiccup on the narinfo sample (278 ms of pure noise
against a 400 ms injected delay) beats a fixed 200 ms margin. I had even written 'differential
cancels machine slowness' into the code comment as though that settled it.

THE SOUND FORMULATION, derived from what the fault actually DOES rather than from a margin that
felt generous. The fault imposes a FLOOR on every request of the targeted kind. So:
  * take the MINIMUM of NARINFO_SAMPLES=5 narinfo requests, not one sample;
  * compare it against LATENCY_FAULT (400 ms) itself, not a hand-picked constant.
If scoping broke, EVERY narinfo request is >= 400 ms, hence so is their minimum - the bite is by
construction, not by margin. A spurious failure now needs all 5 samples to be independently slow.
The threshold is not tuned: it IS the injected latency, and a single const feeds both the fault
query and the assertion so they cannot drift.

MUTATION-CHECKED AGAIN (latency_narinfo_ms=400 added, so scoping is broken):
    narinfo wrongly delayed: the fastest of 5 narinfo requests took 401.684284ms, at or above the
    400ms floor the fault injects into the nar kind ... (unfaulted baseline 1.116447ms)
Bites, with the numbers in the message. Mutant reverted.

PROCESS POINT, which is the whole subject of this task. A single green run would have shipped this
defect: the test passed on my machine, passed in isolation, and passed 13 consecutive full-suite
runs under load before failing. AC#3's insistence on re-measuring at the same N and load - rather
than accepting one green - is what caught it. The first AFTER measurement is therefore DISCARDED
(it measured code I have since changed) and a fresh N=20 run started against the final tree. Its
first 13 runs are not carried forward; that would be exactly the cherry-picking this task exists to
stop.

## AFTER MEASUREMENT - COMPLETE, N=20, SAME LOAD (AC#3)

  command       cargo test --locked --workspace          (identical to BEFORE)
  load          14 CPU burners, 14-core host             (identical to BEFORE)
  N             20                                        (identical to BEFORE)
  FAILURES      0/20
  exit codes    {0} only - no build_failed, no harness_error
  median run    74.5 s   (BEFORE 64.3 s)

  BEFORE  9/20 = 45%   ->   AFTER  0/20 = 0 observed failures

WHAT THIS DOES AND DOES NOT ESTABLISH - stated because the whole task is about not overclaiming
from a sample. 0/20 does NOT prove the rate is zero. The 95% upper bound on a failure rate
consistent with 0 failures in 20 trials is ~14%, so a residual few-percent flake would not have been
caught by this N. What it DOES establish is the CHANGE, decisively: under the measured 45% baseline
the probability of 20 consecutive clean runs is 0.55^20 ~= 6e-6. The improvement is real; the
absolute claim 'the gate is now deterministic' is not licensed by N=20 and is not made.

The AFTER runs also ran on a BUSIER host than the baseline (other work was competing for CPU
alongside the 14 burners), so the stressor was harsher, not gentler. The comparison is conservative
in the right direction.

COST, reported rather than buried: median run time rose 64.3 s -> 74.5 s (+16%). Contributions are
+2 test targets from the species-E split, NARINFO_SAMPLES=5 extra loopback requests in the latency
test, and the busier host. Not separated per cause - the honest attribution would need a controlled
re-run, and the number is small enough that I did not spend another 25 minutes to apportion it.

RESIDUAL, explicitly not closed by this run:
  * SPECIES A and B never fired in EITHER measurement. Their fixes are justified by reading and by
    an earlier QA report (fault_mode_loop 3/10), not by evidence gathered here. They are real
    load-sensitive sites, but this 45%->0 result is NOT evidence for them and must not be cited as
    such.
  * SPECIES E fired once in 20 here. The stronger evidence for it remains qa's 13/64 under 8
    CONCURRENT PROCESSES - a different stressor that this CPU-burner harness does not reproduce. A
    clean 20 under CPU load is therefore weaker evidence for E than for C and D. The independent
    corroboration for E is not the pass rate but the MEASUREMENTS becoming coherent (see above).
  * The latent sites listed earlier (serve_budget_and_supply fixed sleeps, header_hygiene single
    read()) remain unfixed and unfired.

## e2e-full CAUGHT A REAL DEFECT IN THIS CHANGE - untracked module invisible to the Nix build

First e2e-full run FAILED (exit 2), during the container image build:
    error[E0583]: file not found for module `residency_support`
      --> daemon/tests/store_residency_oracle.rs:65:1
    error: could not compile `daemon` (test "store_residency_oracle")

CAUSE. The species-E split created daemon/tests/residency_support/mod.rs and two new test targets,
and I had not `git add`ed them. The Nix flake sources from the GIT TREE, so untracked files simply
do not exist inside the sandbox. cargo test passed locally throughout - twenty times under load,
plus lint and the full `just test` - because every one of those reads the WORKING TREE.

WHY THIS IS WORTH RECORDING RATHER THAN QUIETLY FIXING. It is a second instance of this task's own
subject: a gate that appeared green while not testing what it claimed. The 20-run AFTER measurement
is NOT invalidated - it exercised the split correctly via the working tree, which is what it was
measuring - but it could NEVER have caught this class, because a nix-sandbox build is the only gate
here that sees the git tree rather than the working tree. Two gates, two different views of 'the
code', and only one of them matches what a fresh clone or CI would build.

Fixed by staging the three new paths (plus scripts/flake_rate.py and the task-111 file). e2e-full
re-run against the staged tree.

CONSEQUENCE FOR THE CONVENTION: 'just test is green' does not imply 'a clean checkout builds'. Any
cycle that ADDS a file must run a git-tree-sourced gate (e2e, e2e-vm, or nix build) before claiming
the change is complete - or must at minimum confirm the new paths are tracked.

## e2e-full GREEN, and the per-scenario timings CORRECTED my split rationale

  e2e-full: 26/26 PASS, 439.2s of scenarios, ALL SCENARIOS PASSED
  just e2e (new fast subset): 5/5 PASS, 83.3s of scenarios, 1m41s wall -> ~5x cut

Added per-scenario timing to run_scenarios() so this choice is data, not taste. The data refuted
two things I had asserted while designing the subset:
  * fault-depth-matrix is NOT expensive. 29 checks in 11.8s - it reuses ONE pod rather than
    spawning 21. I had told the owner it was where the minutes go. Wrong.
  * The real cost is scenarios that WAIT ON PROCESS DEATH: chain-kill-middle-daemon 37.3s,
    crash-kill-mid-nar 32.6s, crash-sigstop-stall 28.9s, chain-timeout-boundary 26.0s.
  * There is a ~11s per-scenario floor (pod setup), so scenario COUNT dominates which ones are
    picked. A sixth 'cheap' scenario costs ~11s, not ~1s.
All three now recorded in the Justfile next to the selection, so the next person tuning the list
starts from measurements.

The five kept: s1-byte-and-counts (core S1), s2-fallback (additive invariant), tamper-narhash (the
safety bite - a fast gate that cannot catch a verification regression is the wrong gate at any
speed), chain-s1-and-counts (depth composition), s6-p2p (wave-2 acceptance). One per distinct path;
e2e-full remains the gate that must be green before shipping a serving-path change.
<!-- SECTION:NOTES:END -->
