---
id: TASK-225
title: Daemon narinfo-body idle timeout (fetch_buffered stall gap)
status: To Do
assignee: []
created_date: '2026-08-15 21:23'
labels:
  - daemon
  - hardening
  - wave1-followup
dependencies: []
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-25 added a per-read body-idle timeout to UpstreamHttp::fetch_streaming (the NAR/passthrough path). The narinfo path (UpstreamHttp::fetch_buffered -> Limited::new(..).collect()) has the SAME gap: an upstream that sends narinfo headers then stalls the (small) body indefinitely would hang collect() with nothing bounding it (connect_timeout/header_timeout only bound connect+header arrival). Wrap the buffered read in the same body-idle bound (or a total read deadline) so a stalled narinfo body fails fast at the daemon boundary too. Lower severity than the NAR path (narinfo is ~1KB, capped at MAX_NARINFO_BYTES) but still an S2 no-hang gap.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A mock upstream that sends narinfo headers then stalls the body yields a bounded error (not a hang), proven by a biting test
<!-- AC:END -->
