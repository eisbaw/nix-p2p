---
id: TASK-301
title: >-
  TASK-62 inc3 oracle-completeness hardening: strengthen streaming oracles (code
  correct, tests weak)
status: To Do
assignee: []
created_date: '2026-08-21 16:47'
labels: []
dependencies: []
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
codex DEEP re-gate (round 2) on TASK-62 inc3 confirmed the streaming-flip CODE is correct (HIGH-1 absolute transfer deadline fixed + propagated; gate-1 verified-before-emission intact; nix-midbody-abort-retry proves the committed-head Nix-retry invariant 8/8 with a real Nix client). These are ORACLE-STRENGTHENING follow-ups where the code is right but the test proves less than claimed. NOT safety holes (Nix gate-2 backstops correctness; the deadline code is correct).

1. HIGH-1 deadline oracle is weak: fabric-libp2p/src/nar.rs:5137 (a_dribbling/stalled_peer_is_cut...) uses a HARD stall, not a peer dribbling 1 byte just under the renewable idle timeout, and asserts elapsed <30s rather than the configured ~400ms + slack. Make it a true slow-loris (under idle timeout, over total_timeout) and assert the abort lands within total_timeout+slack (RED if the absolute deadline is reverted). The companion nar.rs:4096 predates 2ce008a and tests provider-side serving, not fetch_stream.
2. Terminal-error enqueue residual: fabric-libp2p/src/nar.rs:942-947 enqueues the terminal error OUTSIDE the absolute deadline; it can wait indefinitely behind a full downstream queue (Bao permit is already released, so not a worker-pin, but the send can hang). Bound it or make it non-blocking.
3. NarStreamBody shipped-seam oracle: the new daemon-core/src/peer_source.rs:655 direct test catches Err->clean-EOF laundering but bypasses streaming_response / committed HTTP 200 / LoggingBody / Hyper. Add a test that drives a mid-body Err (and a client hangup) through the FULL shipped HTTP stack and asserts Nix sees a terminal body error / retries. The server.rs:1144/1188 tests exercise StepBody->LoggingBody, not NarStreamBody.
4. AC#4 truncation observation: daemon-core/src/peer_source.rs:683 checks only the internal header map; add a test that observes actual HTTP truncation + refetch (a signed-size Content-Length with a short body -> Hyper rejects -> Nix refetch).

Blocks nothing user-facing; hardening-wave rigor on a functionally-safe shipped path.
<!-- SECTION:DESCRIPTION:END -->
