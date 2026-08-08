---
id: TASK-7
title: 'Additive-invariant crash suite: daemon down, killed mid-NAR, wrong ordering'
status: To Do
assignee: []
created_date: '2026-08-07 21:55'
updated_date: '2026-08-08 09:46'
labels: []
dependencies:
  - TASK-5
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
S2 made into standing e2e scenarios: (a) daemon absent at nix-daemon store-open; (b) daemon SIGKILLed at ~50% of a >=100MB NAR transfer; (c) regression guard on nix-cache-info priority (daemon must actually be preferred, and its loss must actually fall back). Architect round-2 finding: mid-stream crash yields truncated NAR - Nix must hash-fail and refetch from fallback, store never corrupted.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Crash scenarios green in just e2e: (a) daemon absent at store-open; (b) SIGKILL at 50% of the >=100MB NAR, triggered by BYTES OBSERVED at the testproxy, not a sleep; (c) kill DURING the narinfo response; (d) kill BETWEEN narinfo 200 and the NAR GET (the actual S2 claim); each asserts fallback served the bytes
- [ ] #2 SIGSTOP stall scenario: no RST/FIN - measured behavior vs Nix stalled-download-timeout documented, build eventually succeeds via fallback; if the stall exceeds an acceptable bound, that is a finding to file, not a pass
- [ ] #3 Post-crash state: fixture path IS present via fallback with NarHash equal to fixture's; no orphaned locks/tmp files; bite: an injected corrupt store path makes this check fail
- [ ] #4 Keep-alive desync: upstream truncation while daemon survives -> next request on the reused connection returns correct bytes or the connection is closed (never NAR-tail-as-narinfo)
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
--- from task-5 (80319ec): crash-injection hooks ---
`Pod.kill(role)` (podman kill) is the entry point. To kill the daemon MID-NAR-TRANSFER: launch a client_run in the BACKGROUND (subprocess.Popen without wait - refactor client_run to expose the argv, or add a client_run_async), poll `pod.proxy_stats()`/`pod.proxy_log()` until the NAR request for the 110 MiB `big` payload appears (it is uncompressed so the transfer window is wide), then `pod.kill("daemon")`. The truncated-transfer event is then visible in proxy_log() (status/bytes_sent short of file_size). For daemon-RETURNS-ERRORS (S2 c): the daemon has no fault injection (by design); simplest is to point the daemon's --upstream at a dead port so it 502s, or front it with a faulted testproxy. S2 in task-5 only covers daemon-ABSENT; the kill-mid-transfer and error cases are yours. The oracle-pairing discipline (reset proxy, max-substitution-jobs=1, fresh client per run) is already baked into Pod.client_run.
<!-- SECTION:NOTES:END -->
