---
id: TASK-31
title: 'Daemon substitution log: full-drain byte + duration accounting'
status: Done
assignee:
  - '@claude'
created_date: '2026-08-08 11:35'
updated_date: '2026-08-16 09:36'
labels:
  - journey-finding
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-6 (J1 journey) added a per-substitution log line in daemon/src/server.rs (log_substitution): 'daemon: substituted path=... source=... bytes=... duration_ms=...'. WAVE-1 LIMITATION: duration_ms is time-to-upstream-response-headers, not the full NAR body drain (the body streams verbatim after the line is emitted), and bytes is the upstream Content-Length, not a counted drain. Both are exact for the fixed-size Content-Length fixtures used today but mis-report on chunked or truncated transfers. Wave-2 should wrap the streamed NAR body to count actual bytes and fire the log line on stream completion for a true duration. TASK-9 (measurement) will consume these numbers, so accuracy matters there.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Daemon logs actual drained NAR byte count (not Content-Length) per substitution
- [ ] #2 duration_ms covers the full body transfer, emitted on stream completion
- [ ] #3 Chunked/truncated transfer reports honest bytes (a truncated stream is not logged as a full substitution)
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Scope clarification (mped-architect review of TASK-6): the wave-1 log reports bytes=Content-Length (the COMPRESSED on-wire size) and duration=time-to-upstream-headers. When the upstream sends no Content-Length (chunked) the daemon now logs bytes=unknown - it deliberately does NOT fall back to the signed NarSize, which is the UNCOMPRESSED size and thus a unit mismatch for any compressed NAR. Wave-2 full-drain accounting (wrap the streamed NarBody, count actual bytes, emit on completion) resolves both the drain-accuracy and the unknown-length cases with a single honest compressed-byte count.

task-13 triage: KEEP for wave-2 - full-drain byte/duration accounting in the substitution log is a measurement-accuracy refinement (chunked/truncated transfers); exact for the Content-Length fixtures used today. Distinct concern, feeds task-9.

PLAN (TASK-31): move the per-substitution log from header-arrival to STREAM COMPLETION via a LoggingBody wrapper in daemon-core/src/server.rs.

Design:
- New LoggingBody<B> wraps the streamed NarBody on the Route::Nar 200 GET path. It counts ACTUAL drained frame-data bytes (compressed on-wire / FileSize-scaled transport unit - the SAME unit wave-1 Content-Length reported, now COUNTED not declared; NEVER the uncompressed NarSize). It composes ABOVE TASK-25 BoundedBody: BoundedBody enforces idle-timeout + over-cap and surfaces aborts as Err frames; LoggingBody sits outside it, so a BoundedBody abort reaches LoggingBody as an Err and is narrated as aborted, not substituted.
- On poll_frame Ready(None) = clean end -> emit Complete{bytes,duration} -> prints the pinned success line daemon: substituted path=/nar/TOKEN source=SRC bytes=N duration_ms=M. On Err (upstream truncation, hyper IncompleteMessage on truncated chunked/CL, or a BoundedBody abort) -> emit Aborted{bytes,duration,reason} -> prints daemon: substitution-aborted ... (a DIFFERENT, non-substituted line with the PARTIAL counted bytes). On Drop before completion (client hang-up) -> Aborted too. Fuse: emit once.
- duration = started.elapsed() at completion (request-dispatch -> body drained) = full transfer duration, emitted on completion (AC#2).
- HEAD and non-200 are NOT narrated as substitutions (no body drained / not a substitution); matches the old early-returns.
- Remove old header-time log_substitution + its content_length helper.

Bites (unit tests, sink-injected so the oracle observes the recorded outcome at the right boundary):
- AC#1: a chunked-style body (no Content-Length) that drains K bytes then ends -> Complete{bytes=K}, i.e. the COUNTED drain, not unknown/Content-Length.
- AC#2: a paced body sleeping between frames -> duration >= sum of paces (whole transfer, not header latency).
- AC#3: a body that yields data then an Err mid-stream -> Aborted (partial bytes), NEVER a Complete/substituted line.

No floats (u64 bytes, Duration::as_millis u128). Gate: cargo test -p daemon-core -p daemon, fmt, clippy -D warnings, check-no-floats, just e2e.

DONE (TASK-31). Implemented in daemon-core/src/server.rs: a LoggingBody<B> wraps the streamed NAR body on the Route::Nar 200 GET path and fires the per-substitution log on STREAM COMPLETION (not header arrival).

UNIT: bytes = COUNTED drained on-wire body bytes = the COMPRESSED transport representation (FileSize-scaled for xz/zstd; == NarSize only for Compression: none). Same unit the wave-1 Content-Length reported, now counted not declared; NEVER the uncompressed NarSize. duration_ms = started.elapsed() at completion = full transfer duration.

COMPOSITION with TASK-25: LoggingBody sits ABOVE the existing BoundedBody (idle-timeout + over-cap). A BoundedBody abort surfaces as an Err frame that LoggingBody narrates as substitution-aborted (partial bytes), never substituted. Clean end (poll_frame None) -> Complete -> the pinned daemon: substituted ... success line on stdout. Err (upstream truncation / hyper IncompleteMessage / BoundedBody abort) or Drop-before-completion (client hang-up) -> daemon: substitution-aborted ... on stderr with the honest partial count. Removed the old header-time log_substitution + its content_length helper.

Per-AC status (all bite, proven by mutation):
- AC#1 (actual drained bytes, not Content-Length): ac1_logs_actual_drained_bytes_not_content_length. Bite: a chunked-style body with NO Content-Length drains 7+5+3 -> Complete{bytes=15} (the counted drain). Mutation removing the counter -> bytes=0, test fails.
- AC#2 (duration covers full transfer, on completion): ac2_duration_covers_full_body_transfer. Bite: a body paced 30ms/frame -> duration >= 2*gap. Mutation zeroing the completion duration -> test fails.
- AC#3 (truncated = honest, not a full substitution): ac3_truncated_stream_is_aborted_not_substituted + client_hangup_midstream_is_aborted_not_substituted. Bite: data then a mid-stream Err -> Aborted{bytes=8}, and asserts NO Complete/substituted outcome exists. Mutation making the Err path report Complete -> test fails.

Gate (nix dev shell, ACTUAL): cargo test -p daemon-core -p daemon exit 0 (daemon-core lib 213 passed / 1 pre-existing ignored, incl. the 4 new tests; all daemon test binaries green, 0 failures). cargo fmt --check clean. cargo clippy -p daemon-core -p daemon --all-targets -- -D warnings exit 0 (no warnings). scripts/check-no-floats.py green. just e2e exit 0: 5/5 scenarios PASS (s1-byte-and-counts 11/11, s2-fallback 9/9, tamper-narhash 4/4, chain-s1-and-counts 13/13, s6-p2p 11/11). The count oracles (exactly one NAR served per payload per hop) confirm the completion-fired substitution line emits exactly once per served GET - no double-count, no missing count.

HONEST LIMITS: (1) HEAD and non-200 no longer emit a substitution line - a HEAD drains no body so it is not a substitution (the wave-1 header-time logger did emit for HEAD with bytes=Content-Length; no test/e2e relied on it). (2) The success line now appears AFTER the body is fully served rather than before it; harnesses read the daemon log after the client build completes, so timing is unaffected (e2e green). (3) The substitution-aborted line is new operator-facing output on stderr; nothing parses it yet. No FROZEN surface touched.
<!-- SECTION:NOTES:END -->
