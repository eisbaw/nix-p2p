---
id: TASK-25
title: >-
  Daemon NAR body-read/idle timeout + wave-2 streaming NarSize abort (PRD risk
  6)
status: In Progress
assignee:
  - '@claude'
created_date: '2026-08-08 08:16'
updated_date: '2026-08-15 21:57'
labels:
  - wave1-followup
  - daemon
  - hardening
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Two related gaps carried from TASK-4 (daemon/src/upstream.rs fetch_streaming):

1. No body-stall timeout: connect_timeout/header_timeout bound connect + header arrival, but an upstream that sends headers then stalls the NAR body indefinitely hangs the daemon->Nix response. Wave-1 fault suite only exercises terminating faults. Add a per-read/idle timeout so S2 no-hang holds for body stalls too.

2. SourceError::TooLarge + the expected_size Content-Length pre-check are DEAD in wave-1 (expected_size is always None; the daemon serves NAR statelessly). Wave-2 must populate expected_size from the signed NarSize/FileSize (needs narinfo correlation) AND add a per-chunk streaming abort - the claim-spam amplification defense (PRD risk 6). This task claims that dead code.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 an upstream that stalls mid-NAR yields a clean error within a bounded time, not a hang
- [x] #2 expected_size is populated from the signed narinfo and a transfer exceeding it is aborted mid-stream (per-chunk, not just Content-Length pre-check)
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
--- forward-carry from task-7 (SIGSTOP evidence) ---
Direct repro of the missing body-idle timeout: e2e scenario `crash-sigstop-stall`
freezes the daemon mid-NAR (podman pause = cgroup freeze, no RST/FIN). The client
connection then goes silent and NOTHING in the daemon bounds it - recovery relies
entirely on nix's client-side `stalled-download-timeout` (default 300s = ~5 min
hang). The e2e pins it to 8s + `download-attempts 1` to measure a bounded ~13.9s
failover. A daemon NAR body-read/idle timeout would cap the hang regardless of the
client's setting. Repro tools already exist: testproxy fault `throttle_nar_bps`
(paces the NAR so the freeze lands mid-body) + Pod.pause()/unpause() +
Pod.nar_tmp_bytes() in scripts/e2e_harness.py. When this task lands, add a bound
assertion at the DAEMON boundary, not just the pinned client timeout.

FROM task-39 (commit 120463e): the iroh fetch path (daemon::IrohTransport, transport_iroh.rs) currently assembles the whole blob via iroh_blobs get_blob(...).bytes() with NO NarSize bound - a lying holder could stream a huge blob. TransportNarSource::resolve receives _expected_size but forward-carries it (frozen seam). Enforcing the signed NarSize bound DURING streaming is this task: iroh-blobs exposes get_verified_size (a pre-check) and a streaming GetBlobResult (BaoContentItem leaves) so the bound can be enforced incrementally as bytes arrive, not post-hoc. The Transport::fetch trait carries no size today - wiring the bound likely needs a trait/seam extension coordinated with task-51.

PLAN (mped-emulated design; unit-labelled for the NarSize-vs-FileSize trap):

Scope reality found on read:
- expected_size is ALREADY populated from the signed narinfo NarSize at the seam (server.rs meta.nar_size on the SignedNarHash path) and is proven by an existing biting test (daemon/tests/nar_source_seam.rs asserts size: Some(NARSIZE) crosses the seam). SourceError::TooLarge is ALSO already live via the p2p path (peer_source.rs / transport_fetch.rs / fabric-libp2p nar.rs). So the task premise (both dead in wave-1) is partly stale. New work is entirely the two fetch_streaming gaps.

UNIT decision (the crux): fetch_streaming streams the ON-WIRE TRANSPORT body. Its byte-unit is FileSize (compressed for .nar.xz). expected_size is the SIGNED NarSize (uncompressed). They are NOT interchangeable.
- AC#2 abort bound = min(Content-Length, signed_raw_cap) in TRANSPORT bytes, enforced per-chunk.
  * Content-Length = FileSize (the on-wire byte count) - always the right unit for the on-wire body.
  * signed_raw_cap = expected_size (NarSize) ADMITTED ONLY when the on-wire body is proven RAW (/nar/<h>.nar AND no Content-Encoding), where FileSize==NarSize so it is like-for-like. NEVER applied to a compressed .nar.xz body (that is the 5x-recurred bug). The signed uncompressed NarSize guarantee on a compressed transfer is enforced downstream by Nix NarHash/NarSize (and, for untrusted p2p peers streaming the RAW nar, by fabric-libp2p mid-stream NarSize abort - already done).
- AC#1 = per-read body-idle timeout in a BoundedBody wrapper: a silent mid-body stall yields a bounded TimedOut error at the DAEMON boundary, not a hang.

Daemon-boundary proof for AC#1: a Rust integration test with an in-process STALLING upstream (daemon alive, upstream silent mid-body) is the precise oracle. The e2e crash-sigstop-stall FREEZES the daemon itself (cgroup freeze = frozen timer), so it stays nix-client-bounded by construction; and every e2e upstream-stall point (proxy/origin) is SHARED with the fallback route, so e2e cannot isolate the daemon timer. Will update that scenario comment honestly rather than overclaim.

PRE-COMMIT REVIEW (qa-test-runner + mped-architect, parallel):
- qa-test-runner: all 5 gates GREEN - cargo fmt --check (0), clippy -p daemon-core -p daemon --all-targets -D warnings (0), cargo test -p daemon-core (195 pass / 0 fail / 1 ignored-network), cargo test -p daemon (all pass), check-no-floats.py (0). New upstream tests execute and pass.
- mped-architect: NO HIGH/critical defects; unit reasoning judged airtight (traced every path to fetch_streaming - expected_size is always signed NarSize or None; the rewrite <narhash>.nar path is the sharpest case and is correct/like-for-like); BoundedBody state machine correct (no hang/double-count/oversize-forward; strict > verified). Honesty check PASS on the e2e comment + TASK-225.

FIXES APPLIED from the review (re-gated green):
- MEDIUM (fail-verbose): the mid-stream abort was invisible in daemon logs (log_substitution emits the 200 success line on headers, before the body streams; hyper does not log a body-stream error). Added eprintln! at BOTH BoundedBody abort points (idle-timeout + oversize) so the PRD-risk-6 signal is observable.
- LOW: Content-Encoding: identity (RFC no-op coding) no longer drops the signed-NarSize bound - replaced contains_key(CONTENT_ENCODING) with is_content_encoded() that treats absent/empty/identity as NOT encoded; comma-list with a real coding = encoded. Unit-tested.
- LOW: added a happy-path streaming test (raw NAR of EXACTLY NarSize streams uncut) guarding the strict > against a future >= regression.
- LOW: documented the TRUST DEPENDENCY of the raw-determinant (rests on upstream honesty about suffix-vs-encoding; a dishonest trusted upstream is already broken end-to-end and untrusted peers never traverse this HTTP path).
Deferred (reviewer agreed no change needed): size_hint passthrough.

FINAL (commit 0f19166, not pushed):
- AC#1 idle timeout: BoundedBody per-read idle bound aborts a silent mid-body stall at the daemon boundary. Biting tests: body_idle_timeout_bounds_a_midstream_stall (+ bite control without_the_idle_timeout_the_same_stall_would_hang).
- AC#2 streaming size abort: per-chunk transport-unit cap = min(Content-Length, signed_raw_cap). expected_size(NarSize) admitted ONLY for a proven-raw on-wire body. Biting tests: raw_nar_body_over_signed_narsize_is_aborted_midstream (+ no-cap bite control), compressed_nar_body_is_not_bounded_by_uncompressed_narsize (ANTI-TRAP), raw_nar_body_of_exactly_narsize_streams_uncut (strict-> boundary). expected_size population pre-existing at seam (server.rs), covered by nar_source_seam.rs.
- UNIT each abort uses: compressed on-wire body -> bounded by Content-Length (FileSize) ONLY, never NarSize; raw on-wire body -> bounded by NarSize (== FileSize, like-for-like). Signed uncompressed NarSize on a compressed transfer is enforced downstream by Nix + by fabric-libp2p for untrusted peers.
- Gate (actual): cargo fmt --check 0; clippy -p daemon-core -p daemon --all-targets -D warnings 0; check-no-floats 0; cargo test -p daemon-core 195 pass/0 fail/1 ignored(network); cargo test -p daemon all pass; just e2e 5/5 scenarios PASS (74.2s); crash-sigstop-stall 7/7 PASS.
- Follow-up filed: TASK-225 (narinfo fetch_buffered stall gap, referenced in code).
- Honest limits: the raw-determinant rests on upstream honesty (trust dependency, documented); Content-Length-only cap for a compressed CHUNKED runaway is bounded by Nix downstream, not at this layer (correct unit-wise). e2e cannot isolate the daemon idle timer (frozen-daemon scenario + shared fallback route), hence the Rust in-process oracle.

DEEP gate (codex) NO-GO, reopened. The NarSize-vs-FileSize unit trap RECURRED (6th time) in a subtle form.
FINDING 1 (HIGH/GATE - must fix): raw-body detection at upstream.rs:749/794 (path_is_raw_nar) classifies a body as RAW from the .nar URL SUFFIX + no non-identity HTTP Content-Encoding. But Nix's narinfo Compression field is INDEPENDENT of the URL suffix: a spec-valid narinfo can be URL:nar/object.nar + Compression:xz (an xz archive has NO HTTP Content-Encoding - xz is the Nix archive representation, not an HTTP content-coding). So path_is_raw_nar returns true, admits NarSize as the cap, and a LEGITIMATE compressed transfer is ABORTED (cap = min(Content-Length=FileSize, NarSize) or just NarSize when Content-Length is absent). ROOT: catalog.rs:118 parses only (url-token, NarHash, NarSize) and DISCARDS the authoritative Compression/FileSize, so the daemon cannot tell the body is compressed and falls back to the suffix heuristic. ROOT FIX (codex): thread the narinfo Compression (and preferably FileSize) through catalog.rs -> server.rs -> upstream.rs; admit NarSize as the raw cap ONLY when Compression==none (the authoritative narinfo field) AND no non-identity HTTP content-coding - NOT the URL suffix. A compressed body is bounded by FileSize/Content-Length, never NarSize. ADD the anti-trap test: URL:nar/x.nar + Compression:xz must NOT be capped by NarSize.
FINDING 2 (MEDIUM): the size test (upstream.rs:2139/2214) asserts is_err() only - a mutant that errors before forwarding any frame, or forwards the over-cap frame then errors, still passes. Add a test that ASSERTS prior valid frames were forwarded to Nix and the crossing frame was DROPPED (the impl already drops it at 889 - prove it).
FINDING 3 (MEDIUM): the idle-timeout test (upstream.rs:2153) does not mutation-prove the PER-READ RESET - removing the re-arm would still pass. Add a PACED-body oracle: every inter-frame gap below the idle bound but total transfer time above it must SUCCEED (not time out), and assert the received prefix.
codex confirmed clean: SIGSTOP e2e wording honest, untrusted peers never reach UpstreamHttp (chain case: upstream daemon builds HTTP metadata after transport verification), compressed-without-Content-Length correctly uncapped, no floats, frozen surface untouched.
<!-- SECTION:NOTES:END -->
