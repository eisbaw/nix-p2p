---
id: TASK-115
title: >-
  Iroh node runtime: persistent identity, one shared endpoint/router, explicit
  endpoint scopes
status: Done
assignee:
  - '@me'
created_date: '2026-08-10 22:23'
updated_date: '2026-08-11 11:00'
labels:
  - iroh
  - production
  - wave-2c
dependencies:
  - TASK-39
  - TASK-69
  - TASK-114
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Replace the current test-shaped endpoint lifecycle with one deployment-capable Iroh node runtime. The daemon currently creates separate ephemeral endpoints for serving and fetching. A real node needs one persisted identity and one long-lived Endpoint/Router that serves iroh-blobs and can register additional ALPN handlers. This task owns identity persistence, endpoint/router lifetime, lower-level bind scopes and explicit relay/address-lookup capability inputs, plus a hermetic offline-test configuration. It does not activate LAN-local discovery (TASK-130), DNS/pkarr or relay discovery (TASK-89), conditional Mainline address lookup (TASK-131), choose content lookup policy (TASK-100/101/103/116), or define operator participation modes (TASK-120). No Iroh public-network default may be inherited implicitly.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 A daemon state directory stores a versioned, integrity-checked Iroh secret-key record under restrictive directory and file permissions. Restart preserves the NodeId. Missing state initializes durably and atomically without clobbering an identity created concurrently. Existing unreadable, malformed, permission-unsafe, version-unknown, checksum-mismatched, symlink or non-regular state fails without rewrite or key regeneration.
- [x] #2 One runtime builds one Endpoint and one Router after rejecting duplicate ALPN registrations. Provider, fetch transport and registered application handlers share that endpoint, NodeId and socket set. Provider and fetch handles cannot independently create or close endpoints.
- [x] #3 Shutdown has a named numeric deadline. It stops new accepts, drains or cancels inbound and outbound streams and owned tasks, shuts down handlers and the Router, and closes the Endpoint. On deadline expiry it force-closes and aborts remaining owned tasks. A test immediately restarts on the same state directory and fixed port, observes the same NodeId, and detects no surviving task or socket.
- [x] #4 Daemon and benchmark call the same endpoint constructor. The benchmark test selector is guarded equal to the daemon test selector, and a one-sided selector or constructor mutation fails. Persistent versus ephemeral identity is an explicit constructor input, not a duplicated builder.
- [x] #5 One closed lower-level endpoint configuration represents offline-test, LAN-bind and global-bind scopes plus explicit relay and address-lookup capability inputs. Offline-test is the test default: it clears default IP transports, adds only explicit loopback binds, disables port mapping, relay, network-report probes and every AddressLookup service, and rejects injected network capabilities. Selecting LAN-bind or global-bind alone enables no discovery or public service; TASK-130, TASK-89 and TASK-131 activate and test their separate mechanisms. No path uses presets::N0.
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Map the pinned iroh EndpointBuilder/Router shutdown and identity APIs, then freeze a closed endpoint configuration and explicit identity input in one daemon-owned module.
2. Implement fail-closed, versioned and checksummed secret-key persistence with restrictive permissions, concurrent no-clobber initialization, and file/directory durability.
3. Introduce one long-lived IrohNodeRuntime owning the Endpoint and Router; refactor provider and fetch handles to borrow clones of the runtime endpoint and never bind or close it; reject duplicate ALPN registrations.
4. Add focused behavioral and mutation tests for offline isolation, identity corruption/permission/race cases, shared NodeId/socket ownership, duplicate ALPN, bounded shutdown, and immediate fixed-port restart.
5. Preserve the TASK-69 benchmark seam with explicit ephemeral identity and compile-time daemon/benchmark selector parity; run focused tests plus build, lint, test, e2e, e2e-full and iroh-bench, then record exact evidence for independent review.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Foundation for operational Iroh discovery. TASK-115 owns identity, endpoint/router lifetime, lower-level network scopes and capability inputs only. TASK-130 owns LAN address discovery; TASK-89 owns DNS/pkarr and relay discovery; TASK-131 owns conditional Mainline address lookup; TASK-100/101/103/116 own content lookup; TASK-120 owns operator participation modes. Pinned iroh Minimal is not offline: true offline-test must clear default IPv4/IPv6 transports, re-add loopback explicitly, disable portmapper, relay, net-report probes and all AddressLookup services.

Implementation started 2026-08-11. Scope is TASK-115 only: runtime/identity/lower-level endpoint scopes and focused integration. Discovery activation, content lookup policy and operator participation modes remain explicitly deferred to TASK-130/89/131/100/101/103/116/120. Acceptance boxes and Done status remain open until independent review.

Implementation evidence for independent review (2026-08-11): added one daemon-owned Iroh runtime with explicit OfflineTest/Lan/Global bind scopes, explicit persistent-versus-ephemeral identity, explicit relay/address-lookup capabilities, duplicate-checked ALPN registration, weak provider/fetch handles, one shared Endpoint/Router, and a named 10 s bounded shutdown. Production daemon now requires --iroh-state-dir and --iroh-endpoint-scope whenever Iroh is configured; provider and fetch attach to the same node; SIGINT/SIGTERM and all post-spawn exits invoke bounded shutdown. Identity record is versioned, domain-checksummed, derived-NodeId checked, exact 0700/0600 and same-EUID validated, opened no-follow and descriptor-relative, size/hard-link checked, and initialized via fsynced temp plus renameat2 NOREPLACE plus directory/parent fsync; concurrent losers converge without rewrite. Offline-test clears both default IP transports, re-adds only IPv4/IPv6 loopback, disables relay/address lookup/portmapper and uses minimal net-report probes. No presets::N0 path exists. Focused evidence: iroh_runtime 10/10 and real daemon SIGTERM 1/1; active stalled outbound fetch plus hanging handler forces the 75 ms deadline, cancels fetch, makes surviving handles inert, and immediately rebinds the fixed port with the same NodeId. Deliberate selector mutation failed compilation with E0080; deliberate benchmark-local Endpoint::builder mutation failed benchmark_endpoint_construction_cannot_bypass_the_shared_runtime_constructor; both were restored and green. Final gates on the exact tree: just build PASS; just lint PASS; just test PASS; just e2e PASS 5/5 scenarios, 48/48 checks, 74.8 s; just e2e-full PASS 26/26 scenarios, 206/206 checks, 439.2 s; just iroh-bench PASS over 8/32/110 MiB and N=1/2/4, with final 110 MiB medians iroh_drain 286.7 MB/s, iroh_collect 236.1 MB/s, daemon_fetch 199.0 MB/s. Acceptance boxes and Done intentionally remain open pending independent review.

Evidence correction: the final just e2e-full summary totals 200/200 checks across 26/26 scenarios, not 206/206 as stated in the preceding note. The 439.2 s scenario time and all-pass result are unchanged.

Independent review returned NO-GO on 2026-08-11. Remediation resumed with acceptance boxes and Done still open. Review scope: one absolute shutdown deadline including tracked work; no owning Endpoint clone escape; fallible retained provider handles; nonblocking special-file rejection; deterministic concurrent-publication durability; shared constructor in pathological tests; stronger offline and benchmark guards; provider ALPN collision; Result-returning wrappers; bounded inbound/materialization ownership; and stable-identity logging minimization.

Final independent review after remediation (2026-08-11): qa-test-runner GO and mped-architect GO on the frozen tree. The prior panic-after-spawn NO-GO is fixed by retaining the live Child and exact PGID outside the unwind boundary, killing the group, waiting the direct child and reaping adopted same-PGID descendants to ECHILD before completion, PGID clearing or registry removal. A deterministic live child+grandchild panic oracle and an HTTP 1024/1024 saturation/drop/recovery same-listener oracle pass 20/20 in debug and 20/20 in release. Final exact gates: just lint PASS; just test PASS; just e2e PASS 5/5 scenarios and 48/48 checks in 74.2 s; just e2e-full PASS 26/26 scenarios in 433.0 s; just iroh-bench PASS with 110 MiB daemon_fetch median 221.9 MB/s; nix flake check -L PASS all 9 clean-sandbox checks; git diff checks clean. No source changed after these gates. Nonblocking limits retained honestly: the 1024-task global ceiling and fairness are owned by TASK-120; kernel D-state and deliberate process-group escape cannot be forcibly solved but ownership fails closed; command-backed availability still buffers the full NAR; supply selection is lazy after cold restart and a vanished oldest same-digest source does not yet fall through to a sibling; identity initialization requires O_TMPFILE support; public discovery, relay activation and operator policy remain later tasks.

Correction to the superseded interim identity note above: the final implementation publishes an fsynced unnamed O_TMPFILE with no-replace linkat(EMPTY_PATH), followed by directory and parent durability checks; it does not use a named temporary file or renameat2.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Implemented the production Iroh node foundation: durable restrictive identity with stable NodeId, one shared endpoint/router for serving and fetching, explicit offline/LAN/global bind scopes with default-off relay and address lookup, weak non-owning handles, bounded supervised async/process ownership, fail-closed shutdown and immediate fixed-port restart, inert per-digest provider supply capability, and overload recovery. Real daemon, fault, E2E and benchmark evidence is green; global peer/content discovery remains the next implementation wave.
<!-- SECTION:FINAL_SUMMARY:END -->
