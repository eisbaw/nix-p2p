---
id: TASK-272
title: >-
  Composite /bin/daemon should honour RUST_LOG (install a tracing subscriber
  like daemon-libp2p)
status: Done
assignee: []
created_date: '2026-08-19 20:57'
updated_date: '2026-08-20 14:53'
labels: []
dependencies: []
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Diagnosed during TASK-272 discovery-latency measurement: the composite /bin/daemon binary has NO tracing subscriber (unlike the thin daemon-libp2p, which has init_tracing at daemon-libp2p/src/main.rs:1266). So fabric-libp2p diagnostics (autonat/relay/dcutr NAT verdicts + any instrumentation) emitted via tracing::info! are SWALLOWED when running the composite daemon — even with RUST_LOG set + passed into the container (the e2e -e RUST_LOG plumbing works; there is just no subscriber to consume it). Fix: mirror daemon-libp2p's init_tracing() in daemon/src/main.rs (install a stderr tracing_subscriber gated on RUST_LOG; unset RUST_LOG installs nothing so default behaviour is unchanged). Low-risk debuggability fix; the TASK-272 measurement worked around it with eprintln.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 The composite /bin/daemon installs a stderr tracing subscriber when RUST_LOG is set (mirroring daemon-libp2p init_tracing); fabric-libp2p tracing::info! surfaces; unset RUST_LOG keeps the daemon quiet (no behaviour change to any gate/deploy)
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
TASK-272 delivered (commit d52ca24), LIGHT gate. AC#1 DONE: composite /bin/daemon now honours RUST_LOG.

Approach (single source of truth, not duplication): moved init_tracing into the daemon-libp2p LIB as pub fn; both the thin daemon-libp2p binary and the composite daemon call daemon_libp2p::init_tracing(). Composite call sits after the __dump-raw-nar/rewrite-narinfo filter subcommands and before config parse; unset RUST_LOG installs nothing (unchanged behaviour).

AC#1 bite: daemon-libp2p/tests/init_tracing_bite.rs -- forks the test binary twice (global subscriber is process-once). RUST_LOG=info surfaces a fabric-libp2p info line on stderr; unset stays silent. Mutation-verified: deleting the subscriber install reddens the set case with message "expected fabric-libp2p diagnostic on stderr" (rc=101), restored to green.

Gate: cargo test -p daemon -p daemon-libp2p -p fabric-libp2p all green (daemon-libp2p 6 passed incl the bite); cargo fmt --all --check clean; ruff check scripts clean; nix-instantiate --parse nixos/nix-p2p.nix OK. Disk 20G at end.

HONESTY / premise correction: the orchestrator context referenced an existing measure-discovery-latency e2e scenario + mdns_discovery_elapsed_ms/kad_get_providers_elapsed_ms instrumentation + container -e RUST_LOG plumbing. NONE exist at HEAD (grep-verified: no such scenario in e2e_harness.py, no such instrumentation anywhere, no RUST_LOG in scripts/). TASK-272 has exactly one AC (the subscriber), which is fully delivered. Producing REAL discovery-latency numbers is NOT this tasks AC and needs new scope (latency instrumentation + harness RUST_LOG passthrough + a new scenario) -- that is TASK-268/282 (real-network discovery latency). No numbers fabricated.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
AC#1 done (LIGHT gate). Single-sourced init_tracing into daemon-libp2p/src/lib.rs (pub fn) called by BOTH the thin binary and the composite /bin/daemon (placed after the internal filter subcommands, before config parse) so RUST_LOG-set diagnostics surface on the shipped composite and drift is impossible; unset stays quiet. Bite test daemon-libp2p/tests/init_tracing_bite.rs forks 2 processes (RUST_LOG=info -> fabric-libp2p line on stderr; unset -> silent), mutation-verified RED-on-revert. cargo test -p daemon -p daemon-libp2p -p fabric-libp2p green; fmt/ruff/nix-parse clean. HONEST: this is the PRECURSOR only — the discovery-latency MEASUREMENT (the measure-discovery-latency scenario + mDNS/kad integer-ms instrumentation) does NOT exist at HEAD (the just discovery-latency recipe dangles on a missing scenario); split to the new measurement task. Commit d52ca24.
<!-- SECTION:FINAL_SUMMARY:END -->
