---
id: TASK-272
title: >-
  Composite /bin/daemon should honour RUST_LOG (install a tracing subscriber
  like daemon-libp2p)
status: To Do
assignee: []
created_date: '2026-08-19 20:57'
labels: []
dependencies: []
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Diagnosed during TASK-272 discovery-latency measurement: the composite /bin/daemon binary has NO tracing subscriber (unlike the thin daemon-libp2p, which has init_tracing at daemon-libp2p/src/main.rs:1266). So fabric-libp2p diagnostics (autonat/relay/dcutr NAT verdicts + any instrumentation) emitted via tracing::info! are SWALLOWED when running the composite daemon — even with RUST_LOG set + passed into the container (the e2e -e RUST_LOG plumbing works; there is just no subscriber to consume it). Fix: mirror daemon-libp2p's init_tracing() in daemon/src/main.rs (install a stderr tracing_subscriber gated on RUST_LOG; unset RUST_LOG installs nothing so default behaviour is unchanged). Low-risk debuggability fix; the TASK-272 measurement worked around it with eprintln.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The composite /bin/daemon installs a stderr tracing subscriber when RUST_LOG is set (mirroring daemon-libp2p init_tracing); fabric-libp2p tracing::info! surfaces; unset RUST_LOG keeps the daemon quiet (no behaviour change to any gate/deploy)
<!-- AC:END -->
