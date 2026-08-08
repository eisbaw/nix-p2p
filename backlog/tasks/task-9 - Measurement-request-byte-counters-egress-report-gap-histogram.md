---
id: TASK-9
title: 'Measurement: request/byte counters + egress report + gap histogram'
status: To Do
assignee: []
created_date: '2026-08-07 21:56'
updated_date: '2026-08-08 12:46'
labels:
  - irreversible
dependencies:
  - TASK-5
  - TASK-8
  - TASK-20
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The instrument the kill criterion depends on (PRD: <20% net egress cut kills p2p thesis; TESTING.md S3/S4). Test proxy byte counters are ground truth; daemon exports its own counters (JSON or prometheus text) but is measured, not trusted. Harness scenario runs an identical scripted workload daemon-on vs daemon-off and emits a report: net upstream egress, p95 build wall-clock, and the narinfo-to-nar gap histogram (empirical input for the DHT wave, PRD risk 3).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Counting rule committed as a doc next to the code: exactly what net upstream egress includes (bodies vs headers, narinfo vs nar bytes, retries, hedge losers); testproxy counters are ground truth; irreversible label rationale: the J2 baseline freezes against this definition
- [ ] #2 Report: egress + p95 for both arms, N>=10 runs per arm with variance; A/A calibration (daemon-off vs daemon-off) proves noise floor <10%, else S4 is flagged unusable in the report itself
- [ ] #3 Magnitude bite: fixed scenario asserts absolute egress equals the known sum of fixture file sizes within framing tolerance; daemon self-counters agree with testproxy ground truth within stated tolerance
- [ ] #4 Gap-oracle bite: testproxy injects a known narinfo->nar delay X; histogram reports X within tolerance and tracks a changed X
- [ ] #5 Latency bite: injected 200ms/request trips the >10% p95 flag; product-side bite: toggling the daemon narinfo cache (task-8) measurably moves narinfo egress (instrument validated against a PRODUCT change, not only the fixture)
- [ ] #6 just measure replaces the task-1 stub as a real recipe
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
forward-carried from task-1 (e9b3378): 'just measure' is currently a stub that exits 0 printing '0 scenarios registered - NOT a pass'. Replace it, and add a DoD check that greps for that marker and requires zero hits for measure.

forward-carried from task-3 (119cbb7): the measured workload is nix-p2p-fixture-workload-v1, pinned by fixtures/workload.lock.json. Any egress/latency number you record MUST quote that version string - it is what makes cross-wave comparison against the kill criterion meaningful, and the gate fails if TESTING.md stops naming it.

Run 'just fixtures-large' for measurement runs: the fast tier omits fixture-big. fixture-big is 110 MiB (NarSize 115343872) stored with Compression: none, deliberately, so wire bytes equal disk bytes and the counting rule needs no correction factor for it. The other three are none/xz/zstd - for those, compressed FileSize is what crosses the wire and is NOT the NarSize; fixtures/out/manifest.json carries both (nar_size and file_size) per path, so the counting rule can be written against real numbers instead of estimates.

Payloads are incompressible by construction (seeded SHAKE256), so xz/zstd bodies are close to their raw size - do not treat compression ratio here as representative of real nixpkgs closures. Say so where the baseline is written.

CAUTION for the frozen baseline: a 'nix flake update' changes stdenv, which changes every payload's store path and NarHash, which changes the workload even though WORKLOAD_VERSION would sit still. The lock file turns that into a hard gate failure. If it ever fires, the previously recorded baseline is retired, not adjusted.

deep-gate finding on task-3 (architect): every measurement artifact must record workload_version + the fixture lock's public key and hashes; and one cross-host regeneration diff of the fixture tree must be performed and recorded before any J2 baseline number is quoted (repeatability is proven, cross-host reproducibility is not - the lock makes drift loud, the cross-host diff makes it checked).

forward-carried from task-3 round 2 (9dba842): REQUIRED PRE-J2 STEP. Run 'nix develop -c just fixtures-verify-rebuild' and record its result before writing any measurement baseline.

Why it is not optional: 'just test' regenerates the fixture and diffs it, but regeneration re-EXPORTS store paths that are already realised - nix build finds them and never rebuilds. So that check proves NAR serialisation, compression and signing are repeatable, and proves nothing about whether the payload derivations build deterministically. A payload that produced different bytes on every build would be realised once and pass 'just test' forever, and the frozen workload would rest on whichever bytes happened to land first - a baseline nobody, including its author, could reproduce. 'just fixtures-verify-rebuild' (nix build --rebuild per payload) is what closes that gap. It takes ~3s warm.

Scope of what it earns: determinism on THAT machine against THAT store's copy. Cross-machine reproducibility is verified by nothing in this repository - do not let the baseline text imply otherwise.

Also from this round: the lock now pins a tier per payload, and 'just fixtures-large' runs the gate with --require-tier full, so a measurement run cannot silently proceed against a fast-tier tree missing the 110 MiB payload. If you script measurement setup, call 'just fixtures-large' rather than 'just fixtures'.

round-2 deep-gate (architect): run check-fixtures.py (not just generation) before any measurement run; a measurement against an unverified tree is not a baseline.

task-20 added as dependency: fixtures-verify-rebuild is a required pre-J2 step and must not misdiagnose cold stores before measurement relies on it (round-2 qa finding).

forward-carried from task-3 round 3 (0a70c5e): scripts/check-rebuild.py now also asserts that each payload's built output path EQUALS the store_path pinned in fixtures/workload.lock.json. If you reuse it, note the consequence: it fails when the checkout and the lock disagree, which is the desired behaviour for a pre-J2 gate but means it must be run on the same revision the baseline is recorded against.

Its scope limit is now documented and matters for you: it rebuilds each payload's OWN derivation, not its closure. Correct for the current leaf-shaped workload; if a payload ever gains a first-party dependency, that dependency is NOT covered and the attr list needs extending.

Also: the generated tree's file modes and mtimes are now normalised (0644/0755, mtime 1, signing key 0600), so a tree copied with rsync/tar is identical to one served over HTTP. If measurement tooling copies the tree, it must preserve or re-normalise metadata, or the determinism gate will flag the copy.

forward-carried from task-3 round 5: the fixture tree is now published as an immutable generation behind a symlink, so every path above that starts fixtures/out/ gains one level: fixtures/out/current/cache, fixtures/out/current/manifest.json, fixtures/out/current/test-key.pub. Resolve through fixtures/out/current (never name a generation directly); it is a relative symlink to generations/gen-<manifest-sha>, and the generation it points at is immutable, so a consumer that resolves it once cannot have the tree change underneath it. Retention is two generations, not a lease: re-resolve on ENOENT if you hold it across repeated regenerations.

--- from task-5 (80319ec): how to read the testproxy counters for egress/gap oracles ---
`Pod.proxy_stats()` returns the derived Stats JSON: received/upstream/cache_hits per kind (cache-info/narinfo/nar), received_total, upstream_total, bytes_sent, faults. `Pod.proxy_log()` returns the per-request records; each NAR record carries gap_ms (narinfo->nar wall gap) - the gap-histogram input. Egress oracle = bytes_sent (proxy is ground truth; daemon self-report is NOT trusted). The counting discipline is already enforced: proxy_reset() zeroes counters but NOT the disk cache (so cache-on/off deltas are real), client_run wipes the client narinfo cache and pins max-substitution-jobs=1 per run. s1-byte-and-counts already demonstrates the cold(upstream==N)/warm(upstream==0, received>0) paired delta - the S3 bite is the same shape with bytes_sent. For A/A and N>=10 sampling, wrap client_run in a loop; the Pod persists across runs within a scenario.

From TASK-6 (J1 journey): the daemon now emits one operator-facing line per served NAR in daemon/src/server.rs::log_substitution -> 'daemon: substituted path=nar/<token> source=<upstream> bytes=<n> duration_ms=<d>'. Measurement can parse this for a coarse per-substitution count/byte view, BUT read TASK-31 first: bytes=Content-Length (not a counted drain) and duration_ms=time-to-upstream-headers (not full body drain). For authoritative counters keep using the testproxy stats/log endpoint (Pod.proxy_stats/proxy_log) - the daemon log is narration, the proxy log is ground truth. New reusable accessor Pod.logs(role) in scripts/e2e_harness.py reads a container's stdout host-side.

--- forward-carry from task-7 (crashes the measurement must handle) ---
A mid-transfer daemon crash produces proxy records that egress/counting must NOT
naively sum: (1) a TRUNCATED NAR record (status 200, bytes_sent < file_size) from
the killed daemon hop, AND (2) the fallback's FULL NAR - plus the killed daemon's
proxy thread keeps draining origin->cache, so the SAME payload can be fetched from
origin twice (killed-drain + fallback miss). Counting both as delivered payloads
would double-count egress and corrupt the with/without-daemon delta. The egress
rule must exclude/attribute truncated + retried transfers. The truncated-record
shape (bytes_sent < Content-Length/file_size, fault=None) is the discriminator;
see scenario crash-kill-mid-nar. Also: the new `throttle_nar_bps` fault paces a
transfer without changing total bytes - handy for measurement bite tests that need
a wide observation window.

SCOPE CHANGE (owner, 2026-08-08): kill criterion descoped to a non-blocking metric. Still build the instrument and keep it HONEST (bites must bite, testproxy counters are ground truth), but the counting rule is a comparison basis, not an irreversible project-gate freeze - so the close gate is LIGHT+one mutation-verify pass, not a task-3-style multi-round freeze panel. Do NOT over-invest in freeze ceremony.
<!-- SECTION:NOTES:END -->
