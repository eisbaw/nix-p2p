---
id: TASK-254
title: >-
  Real-upstream test tier against cache.nixos.org (additive; existing suites
  preserved unchanged)
status: To Do
assignee: []
created_date: '2026-08-18 20:26'
labels:
  - testing
  - real-upstream
  - e2e
  - user-value
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
OWNER ASK 2026-08-18: "we need to preserve all our tests, but add more real-world tests using real cache.nixos.org."

PRESERVE-FIRST IS A HARD CONSTRAINT OF THIS TASK. The existing mock-upstream, testproxy, long-chain and container suites stay exactly as they are and remain the common loop. This task ADDS a real-upstream tier; it deletes and weakens nothing. Any change that trades an existing deterministic oracle for a network-dependent one is out of scope.

WHY IT MATTERS FOR USERS: the README correctly admits the daemon "has not been run against the real cache in a deployment". Every green gate today runs against a fixture we control. The failure modes users will actually meet -- real narinfo shapes across the full nixpkgs corpus, xz and zstd Compression fields, real 404 and 403 behaviour, redirects, CDN TLS and HTTP/2 quirks, real RTT and tail latency, rate limiting -- are precisely what a mock cannot produce.

RESPECT THE PRD CONSTRAINT. PRD round 4/5 made the local test cache-proxy a permanent fixture specifically so "the real cache is never loaded needlessly". So the real-upstream tier MUST be:
  * its own opt-in just recipe, NOT part of just test or the fast gate;
  * front the real cache THROUGH the caching testproxy so a repeat run is served from local disk and the real cache sees each path at most once;
  * bounded by an explicit small path budget, with the budget asserted in the harness rather than trusted;
  * polite -- serial or low concurrency, honour rate limits, identify itself, and never sweep the corpus.
Contact with a third-party public service is an outward-facing action: get owner sign-off on the budget and the identifying user-agent before the first unattended run.

STARTING MATERIAL: TASK-22 and TASK-24 (TLS upstream, both Done) already give the testproxy and the daemon a verified-TLS path to cache.nixos.org, and TASK-35 already measured the real narinfo-to-nar gap against it -- so this is an extension of an established capability, not a new one.

CANDIDATE COVERAGE, roughly in user-value order:
  1. Real narinfo corpus conformance: fetch a bounded, deterministic sample of real narinfos and assert the parser, the truncation validation and the raw-rewrite allowlist handle every field shape seen -- including Compression xz, zstd and none, and the TASK-220 missing-FileHash case.
  2. End-to-end real substitution: an unmodified nix build against the real cache through the daemon, asserting byte identity and the additive invariant (kill the daemon mid-transfer, build still completes).
  3. The mock-vs-real differential: run the same assertions against the mock and the real cache and report where they diverge. Divergence is the actual finding -- it tells us where our fixture has been lying to us.
  4. Real-RTT latency characterisation feeding the paired p95 guard, so the latency bound is calibrated against a real CDN rather than loopback.

Report divergences honestly as defects in OUR fixture or OUR parser, and fix at the owning boundary -- do not paper over a real-cache behaviour by special-casing it.
<!-- SECTION:DESCRIPTION:END -->
