---
id: TASK-25
title: >-
  Daemon NAR body-read/idle timeout + wave-2 streaming NarSize abort (PRD risk
  6)
status: To Do
assignee: []
created_date: '2026-08-08 08:16'
labels:
  - wave1-followup
  - daemon
  - hardening
dependencies: []
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Two related gaps carried from TASK-4 (daemon/src/upstream.rs fetch_streaming):

1. No body-stall timeout: connect_timeout/header_timeout bound connect + header arrival, but an upstream that sends headers then stalls the NAR body indefinitely hangs the daemon->Nix response. Wave-1 fault suite only exercises terminating faults. Add a per-read/idle timeout so S2 no-hang holds for body stalls too.

2. SourceError::TooLarge + the expected_size Content-Length pre-check are DEAD in wave-1 (expected_size is always None; the daemon serves NAR statelessly). Wave-2 must populate expected_size from the signed NarSize/FileSize (needs narinfo correlation) AND add a per-chunk streaming abort - the claim-spam amplification defense (PRD risk 6). This task claims that dead code.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 an upstream that stalls mid-NAR yields a clean error within a bounded time, not a hang
- [ ] #2 expected_size is populated from the signed narinfo and a transfer exceeding it is aborted mid-stream (per-chunk, not just Content-Length pre-check)
<!-- AC:END -->
