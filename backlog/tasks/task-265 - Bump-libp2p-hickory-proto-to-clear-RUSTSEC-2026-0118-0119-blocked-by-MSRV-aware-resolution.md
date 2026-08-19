---
id: TASK-265
title: >-
  Bump libp2p/hickory-proto to clear RUSTSEC-2026-0118/0119 (blocked by
  MSRV-aware resolution)
status: To Do
assignee: []
created_date: '2026-08-19 14:03'
labels: []
dependencies: []
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
just audit ignores RUSTSEC-2026-0118 + -0119 (hickory-proto 0.25.2, DoS-class, dnssec feature not enabled + encode over our own bounded mDNS records) pending an upstream bump. The fix rides hickory-proto 0.26.1, which requires libp2p past 0.56 (libp2p 0.56 pins hickory ^0.25 via libp2p-mdns 0.48 + libp2p-dns 0.44). BLOCKER discovered on TASK-260: the workspace resolves MSRV-aware to rustc 1.83.0-compatible (nix toolchain is 1.97.1), so rewriting Cargo.lock to bump hickory drags ~14 collateral downgrades (syn MAJOR downgrade, windows-sys, socket2). Resolve the MSRV mechanism (rust-version pin / resolver.incompatible-rust-versions) FIRST, then bump. Re-run just audit; remove the two ignores from deny.toml when green.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 libp2p/hickory bumped so hickory-proto >= 0.26.1 with NO collateral major downgrades (syn/windows-sys/socket2 stable)
- [ ] #2 RUSTSEC-2026-0118 and -0119 ignores removed from deny.toml; just audit rc=0 without them
- [ ] #3 MSRV-resolution mechanism documented so the downgrade trap does not recur
<!-- AC:END -->
