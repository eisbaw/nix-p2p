---
id: TASK-7
title: 'Additive-invariant crash suite: daemon down, killed mid-NAR, wrong ordering'
status: Done
assignee: []
created_date: '2026-08-07 21:55'
updated_date: '2026-08-08 12:38'
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
- [x] #1 Crash scenarios green in just e2e: (a) daemon absent at store-open; (b) SIGKILL at 50% of the >=100MB NAR, triggered by BYTES OBSERVED at the testproxy, not a sleep; (c) kill DURING the narinfo response; (d) kill BETWEEN narinfo 200 and the NAR GET (the actual S2 claim); each asserts fallback served the bytes
- [x] #2 SIGSTOP stall scenario: no RST/FIN - measured behavior vs Nix stalled-download-timeout documented, build eventually succeeds via fallback; if the stall exceeds an acceptable bound, that is a finding to file, not a pass
- [x] #3 Post-crash state: fixture path IS present via fallback with NarHash equal to fixture's; no orphaned locks/tmp files; bite: an injected corrupt store path makes this check fail
- [x] #4 Keep-alive desync: upstream truncation while daemon survives -> next request on the reused connection returns correct bytes or the connection is closed (never NAR-tail-as-narinfo)
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
--- from task-5 (80319ec): crash-injection hooks ---
`Pod.kill(role)` (podman kill) is the entry point. To kill the daemon MID-NAR-TRANSFER: launch a client_run in the BACKGROUND (subprocess.Popen without wait - refactor client_run to expose the argv, or add a client_run_async), poll `pod.proxy_stats()`/`pod.proxy_log()` until the NAR request for the 110 MiB `big` payload appears (it is uncompressed so the transfer window is wide), then `pod.kill("daemon")`. The truncated-transfer event is then visible in proxy_log() (status/bytes_sent short of file_size). For daemon-RETURNS-ERRORS (S2 c): the daemon has no fault injection (by design); simplest is to point the daemon's --upstream at a dead port so it 502s, or front it with a faulted testproxy. S2 in task-5 only covers daemon-ABSENT; the kill-mid-transfer and error cases are yours. The oracle-pairing discipline (reset proxy, max-substitution-jobs=1, fresh client per run) is already baked into Pod.client_run.

From TASK-6 (J1 journey): scripts/journey.py demonstrates the daemon-down path - Pod.kill('daemon') then a build via ctx.substituter_daemon_and_fallback(), asserting exit 0 AND testproxy received-NAR count == payloads (fallback truly served). New Pod.logs(role) accessor lets a crash suite read operator-visible daemon output; note the daemon emits NO substitution line once dead (silence is the observable), and a killed container's published port yields connection-refused (OSError) not a hang - the journey uses that as its 'daemon is really gone' oracle.

--- task-7 done (crash suite, 6 scenarios in `just e2e`, 15/15 green) ---
Scenarios added to scripts/e2e_harness.py SCENARIOS: crash-daemon-absent (a),
crash-kill-mid-nar (b + AC#3 integrity), crash-kill-during-narinfo (c),
crash-kill-between-narinfo-nar (d), crash-sigstop-stall, crash-keepalive-desync.
Each asserts fallback SERVED the bytes via proxy request counts + byte oracle,
never exit 0 alone.

KEY GOTCHA (cost the first (b) run): a 110 MiB UNCOMPRESSED NAR completes over
pod loopback faster than an out-of-process `podman kill` can land, so both proxy
records came back FULL and the truncated-event oracle went RED. Root cause: the
proxy logs a request only on COMPLETION, so the log cannot report in-flight
bytes. Fix (correct, not a workaround): added testproxy FAULT MODE 8
`throttle_nar_bps` (paces NAR egress; cache still gets every byte; NOT in the
product daemon) -> a wide deterministic mid-transfer window. The BYTES-OBSERVED
trigger reads the proxy's in-progress cache tmp-file size (/tmp/proxy-cache/.tmp/*
via `stat`; `find` is absent from the image), NOT the log. This is also the
truncated-event oracle's fails-before/passes-after proof.

BITES SHOWN: (b) truncated-event RED pre-throttle / GREEN after; (b)/AC#3
integrity: nix-store --verify-path goes RED on an injected corrupt store byte
(self-contained in the container run, verify-clean rc=0 vs verify-corrupt rc!=0);
keepalive: the desync discriminator (_looks_like_http_response) is exercised on
NAR-magic (rejects) and an HTTP line (accepts).

FINDINGS:
- SIGSTOP (task-25 evidence): the daemon has NO body-read/idle timeout, so a
  FROZEN peer (cgroup freeze = no RST/FIN) hangs the client until nix's
  client-side `stalled-download-timeout` (DEFAULT 300s = ~5 min hang). Pinned to
  8s + `download-attempts 1` for a bounded deterministic test -> measured ~13.9s
  recovery via fallback. A daemon body-idle timeout would cap this.
- crash(d) answers the S2 question: after losing the daemon post-narinfo, nix
  RE-QUERIES the next substituter's narinfo (proxy saw ~8 big.narinfo requests)
  and recovers - it does NOT reuse the daemon's narinfo. Reported, not asserted.
- crash(c) observability limit (honest): the daemon serves /nix-cache-info
  LOCALLY, so the proxy sees no 'mid-narinfo' event; 'during the narinfo
  response' is not microsecond-observable. Enforced instead via
  latency_narinfo + throttle_nar (any NAR can't finish) + the daemon-served-NO-
  NAR oracle, kill fired on first OBSERVED proxy activity (no blind sleep).

New Pod seams (reused by task-9/11): client_run_async + BackgroundClient,
pause()/unpause() (SIGSTOP stall), nar_tmp_bytes() (fail-closed byte gauge),
_daemon_action_at_bytes(kill|pause). New Pod methods are python over the seam;
no .rs names fixtures/ or NIX_P2P_ (source guard green).

Reviewed: mped-architect (findings #1 crash(c) blind-sleep/race, #2 sigstop
download-attempts flake, #3 nar_tmp_bytes silent probe failure all FIXED before
commit; #4/#6 docstrings; #5 poller dedup; #7 nested heredocs + #8 throttle-in-
FaultConfig noted as by-design/deferred). qa-test-runner: build/lint/test green.
Deferred (LOW): _CRASH_CLIENT_SCRIPT duplicates _CLIENT_SCRIPT's realise+pathinfo
(single-source drift risk if the base changes); nested py-in-bash heredocs.
<!-- SECTION:NOTES:END -->
