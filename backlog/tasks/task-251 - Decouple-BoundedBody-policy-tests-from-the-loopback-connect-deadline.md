---
id: TASK-251
title: Decouple BoundedBody policy tests from the loopback connect deadline
status: Done
assignee: []
created_date: '2026-08-18 08:55'
updated_date: '2026-08-18 09:54'
labels:
  - testing
  - flaky
  - streaming
  - daemon-core
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The TASK-57 pre-commit workspace gate exposed two existing daemon-core body-policy tests failing before HTTP headers with Unreachable(connect timed out to mock-upstream). Both tests intend to prove BoundedBody byte-cap and per-read idle-reset semantics, but route through a separate hard-coded 1000 ms loopback connect/header gate. Isolated, repeated, and concurrent reruns are green, so the exact host trigger is not deterministic; the proven design defect is that policy tests can fail at an unrelated network gate. Fix the root test seam. Do not increase the timeout, serialize the suite, or treat a lucky retry as evidence.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Exact-size strict-greater-than and paced idle-reset semantics are exercised through a deterministic in-memory Body/stream with no TCP connect or response-header deadline.
- [x] #2 The exact-size oracle mutation-bites if seen > cap becomes seen >= cap; the paced oracle mutation-bites if the per-read idle deadline is not reset.
- [x] #3 At least one separately named real fetch_streaming HTTP integration test continues to prove BoundedBody is wired into the upstream response path.
- [x] #4 Any retained mock-server task used by touched tests is awaited or otherwise surfaces server-side failure instead of being silently detached.
- [x] #5 The full daemon-core/workspace test gate passes repeatedly under bounded concurrent load without retries masking a first failure.
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Factor the two body-policy assertions onto a small scripted in-memory Body in daemon-core/src/upstream.rs tests; keep transport wiring coverage separate; prove both mutations; run bounded repeated full-suite checks and the repository e2e gate.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Implementation complete pending independent review/commit. daemon-core/src/upstream.rs now drives the exact-cap strict-`>` boundary and paced per-read-reset policy directly through a deterministic test-only ScriptedBody; the paced test uses paused Tokio time, so neither test crosses TCP connect or response-header gates. A separately named fetch_streaming_http_integration_wires_bounded_body_transport_cap test retains real loopback HTTP wiring coverage and awaits/checks both mock-server JoinHandles. Production timeout values and BoundedBody logic were not changed.

Mutation evidence: temporary `seen > cap` -> `seen >= cap` made bounded_body_exact_cap_in_memory_streams_uncut fail (exit 101 at exactly 2048/2048 bytes); removing the progress deadline reset made bounded_body_paced_in_memory_resets_idle_deadline_per_frame fail (exit 101 with TimedOut at 300 ms). Both mutations were restored immediately and the restored source was verified.

Gate evidence: all three focused tests passed (1/1 each); `cargo clippy -p daemon-core --all-targets -- -D warnings` passed; three fail-fast full daemon-core runs with `--test-threads=4` each passed 291 unit tests + 20 integration tests, with 1 intentional unit ignore; two fail-fast `cargo test --locked --workspace --quiet -- --test-threads=4` passes exited 0, including daemon-core 291 passed/1 ignored on both runs. No retry masked a failure. Gotcha: focused `--exact` filters require the full `upstream::streaming_bounds_tests::...` path; an earlier short-path invocation selected zero tests and was discarded as evidence.

Architect NO-GO hardening applied: the checked HTTP server now returns an owned CheckedServerTask whose finish API has a 2-second bound; on expiry it calls abort and awaits the JoinHandle before returning TimedOut, while early Drop requests cancellation. This prevents a failed pre-connect fetch from leaving finish blocked on accept. A paused-time no-client control directly proved timeout, abort, and join completion (1/1 passed in 0.00s). read_request_checked now returns UnexpectedEof with request-header context when EOF arrives before CRLFCRLF; its duplex-stream control passed 1/1. The stale spawn_chunked_frames comment now states that paced-reset proof belongs to ScriptedBody and the helper only supports the crossing-frame test. Post-hardening, all streaming_bounds_tests passed 10/10 with four test threads; cargo fmt completed; cargo clippy -p daemon-core --all-targets -- -D warnings passed; diff-check is clean. Full workspace/e2e and independent re-review remain orchestrator-owned before commit.

Second architect lifecycle hardening applied. CheckedServerTask::finish now keeps its JoinHandle inside self across both the normal bounded await and the abort/join await; the handle is taken only after join completion, so cancelling finish at either suspension point leaves Drop able to abort the owned task. The new cancellation-safety control uses a readiness oneshot after installing a task-future drop guard, polls finish, cancels it before the deadline, and requires the guard drop signal. Baseline passed 1/1 in 0.00s. Mutation proof: temporarily taking the JoinHandle out of self across the first await made this control fail exit 101 after 1.00s (`dropping finish must abort the owned task, not detach it`); mutation restored and baseline rerun green.

The real HTTP integration now sends both fetched and server-cleanup results through finish_checked_fetch in both arms. If both fail, the causal fetch error is emitted first and cleanup remains secondary context; cleanup-only failure also remains visible. A sentinel control proved both errors are retained in causal order (1/1 passed). Post-fix streaming_bounds_tests passed 12/12 with four test threads (0.81s); the real HTTP wiring test passed 1/1; cargo fmt --check, diff-check, and cargo clippy -p daemon-core --all-targets -- -D warnings all passed. Per orchestration request, broad QA/e2e was not rerun here.

Final deterministic-test hardening: cancelling_checked_server_finish_aborts_the_owned_task now uses #[tokio::test(start_paused = true)]. This supersedes the earlier wall-clock mutation timing: restored baseline passed 1/1 in 0.00s, and the exact old take-first mutation failed exit 101 in 0.00s while virtually advancing the one-second detached-task deadline; the mutation was restored and baseline rerun green in 0.00s. Final focused gate: streaming_bounds_tests 12/12 in 0.81s, cargo fmt and fmt --check passed, git diff --check passed, and cargo clippy -p daemon-core --all-targets -- -D warnings passed. Broad QA/e2e intentionally remained orchestrator-owned.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Moved exact-cap and per-read idle-reset policy checks onto deterministic in-memory bodies while retaining separately named real-HTTP fetch_streaming wiring coverage. Added owned, bounded, cancellation-safe checked-server lifecycle handling with fail-verbose premature EOF and causal fetch/cleanup error reporting. Mutation proofs bite for strict >, idle reset, and take-first task detachment; all policy/cancellation proofs use paused time where deadlines matter. Mandatory final QA passed fmt, strict clippy, 12/12 streaming tests, daemon-core 295/0/1 plus 20/20 integrations, and repository just test first-run; MPED architecture verdict GO. Exact just e2e and commit remain orchestrator-owned.
<!-- SECTION:FINAL_SUMMARY:END -->
