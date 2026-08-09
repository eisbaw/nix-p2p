---
id: TASK-51
title: >-
  Conservative safety envelope: dial + body-idle + NarSize abort (default before
  policy)
status: Done
assignee: []
created_date: '2026-08-08 20:28'
updated_date: '2026-08-09 01:34'
labels: []
dependencies:
  - TASK-39
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Mid-transfer fallback + bounded slow-HIT behavior are required BEFORE any policy is chosen (codex#5, arch#3, qa#4) - otherwise task-43 has nothing safe to assert and a slow peer just stalls. A conservative default: bounded dial timeout, body-idle timeout (subsumes/uses task-25), and a size abort keyed on the SIGNED raw NarSize (NEVER the compressed unsigned FileSize - unit trap). This is the provisional safety net that task-43 asserts (weak invariant: never unbounded-hang, never wrong bytes); task-44 later MODELS the real policy on top; a still-later task implements the chosen optimization. Explicitly labeled provisional.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 A slow/stalled peer on a HIT triggers the default bounded abort within a PINNED time bound, then falls back to upstream; build succeeds (bite: remove the envelope -> stall)
- [x] #2 Size abort uses signed NarSize (bite: a peer serving > NarSize is aborted early, not downloaded in full); dial timeout bounds a dead holder
- [x] #3 Labeled PROVISIONAL: task-44 may replace the policy; this is the safety floor, not the tuned answer
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
FROM task-39 (commit 120463e): daemon::IrohTransport currently has only a COARSE guard - a single FETCH_TIMEOUT (20s) wrapping dial+get_blob (transport_iroh.rs). The full safety envelope is yours: per-request dial timeout, idle timeout, and a hard abort. Also note get_blob(...).bytes() buffers the WHOLE blob into memory (no streaming bound) - the NarSize abort is task-25, but the envelope should bound total transfer time/bytes too. The Transport::fetch trait signature carries no size/deadline, so wiring a per-request bound may need a seam/trait extension (task-39 deliberately did NOT change the frozen trait).

IMPLEMENTED (commit pending gate): safety envelope = THREE bounds in IrohTransport + a streaming NarSize cap, all PROVISIONAL (task-44 replaces the slow-HIT policy).
- SEAM EXTENSION: Transport::fetch gained expected_size: Option<u64> (the SIGNED NarSize; task-39 deliberately left the trait size-less and carried it here). Threaded through fetch_via_offers -> Transport::fetch. FakeTransport IGNORES it (in-memory stand-in has no streaming boundary; enforcing post-hoc would be the buffer-then-check anti-pattern).
- NarSize abort (risk 6, the important one): iroh-blobs get_blob() returns a Stream<GetBlobItem>; we drive it leaf-by-leaf (NOT .bytes(), which buffered the whole blob - the task-39 bug) and abort the instant cumulative bytes exceed the signed NarSize. Memory bounded to <= NarSize + one bao chunk-group. Unit: RawNarV1 == the raw NAR verbatim, so wire bytes == uncompressed NarSize == the signed bound; NEVER FileSize. New TransportError::TooLarge{limit,streamed} short-circuits fetch_via_offers -> FetchError::TooLarge -> SourceError::TooLarge (PROPAGATES; FallbackNarSource does NOT paper it over).
- DIAL bound: tokio::timeout around endpoint.connect() (DIAL_TIMEOUT=10s prod). Dead holder -> Unavailable -> next/fallback.
- BODY-IDLE bound: tokio::timeout around each stream.next() (BODY_IDLE_TIMEOUT=10s). Connect-then-stall -> Unavailable. Distinct from total; a slow-but-progressing peer resets the idle clock.
- TOTAL backstop: FETCH_TIMEOUT widened to 60s wrapping dial+stream.
- SafetyEnvelope{dial,body_idle,total} injectable via IrohTransport::with_envelope (tests pin ~400ms). IrohPeerAddr::new(node,sockets) added (discovery resolution + black-hole test).
BITES (all fail-before/pass-after, verified by mutation): (1) NarSize - neutralize cap -> 4MiB blob returned in full (bite fires); (2) dial - enlarge dial bound -> falls to 5s total backstop, wrong attribution + >2s; (3) body-idle - same via stalling ProtocolHandler. tests/iroh_safety_envelope.rs (5 tests) + 2 unit tests in transport_fetch.rs.
GOTCHAS/LIMITS: streamed in TooLarge is a LOWER bound on true size (aborted early, not drained) - honest, sufficient to prove the abort. get_verified_size (authenticated last-chunk size) noted as a future O(1) fast-reject optimization but NOT used (streaming cap is the task-described mechanism and single source). Timeouts are PROVISIONAL defaults, NOT tuned - task-44 owns the real policy. Daemon outside TCB: these are availability/DoS bounds, integrity stays Nix's sha256 gate. Added dev-dep iroh (for the stalling handler the friendly API can't express) + deps bao-tree/n0-future (already transitive; independence denylist unaffected).
<!-- SECTION:NOTES:END -->
