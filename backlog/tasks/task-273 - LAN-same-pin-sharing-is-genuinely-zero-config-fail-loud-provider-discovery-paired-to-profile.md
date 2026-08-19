---
id: TASK-273
title: >-
  LAN same-pin sharing is genuinely zero-config (fail-loud provider; discovery
  paired to profile)
status: In Progress
assignee: []
created_date: '2026-08-19 21:41'
updated_date: '2026-08-19 21:52'
labels:
  - usability
  - cornerstone
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
COMPASS #1 / north-star: the honest first product (org/LAN same-pin) is not zero-config and its provider half silently no-ops.

daemon-libp2p/src/main.rs:758 lets a lan-share/public-share provider start with --libp2p-listen but NO entry/store path -> it joins no DHT, is discovered by no one, announces into the void, with no error. consume-only correctly fails loud (main.rs:763-776). mDNS (TASK-257) shipped default-off; nixos/nix-p2p.nix keeps profile and mdns as independent options. Close the gap so a real same-pin user gets value with zero/low config.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A lan-share/public-share provider with no shareable entry path fails loud at startup (symmetry with consume-only), never a silent no-op
- [ ] #2 A node given ONLY --profile lan-share (no bootstrap, no injected peer address) discovers a same-pin peer on the LAN and serves a real nix build; proven by a two-node e2e that BITES (mutation: disable the auto-mDNS/zero-config wiring -> fetch falls back to upstream)
- [x] #3 The mDNS-default-on-with-opt-out vs fail-loud-only fork is decided by mped-architect (Mark-emulator) with the privacy tradeoff (mDNS discloses LAN presence) made explicit, and the chosen contract documented
- [ ] #4 First-run: a startup line states the discovery entry path and the LAN-presence disclosure, so the user can tell it is working without RUST_LOG surgery
- [ ] #5 Supply/reachability zero-config: under lan-share, announce-after-fetch and a listen multiaddr are DEFAULTED so a bare --profile lan-share passes the nothing-shareable (main.rs:740-748) and listen (758-762) guards with no extra flags (folded in so AC#2 is genuinely achievable end-to-end)
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Decision (mped-architect as Mark-emulator, via scope+decide workflow wf_ec77f3d5): CHOICE C.

Under profile=lan-share: (a) default mDNS ON via a tri-state flag (--libp2p-mdns / new --libp2p-no-mdns opt-out) resolved AFTER profile derivation; (b) a first-run presence-disclosure line; (c) a fail-loud guard when a provider has no discoverability path.

Refined premise (scouts corrected COMPASS): the provider branch ALREADY fails loud on nothing-to-serve (main.rs:740-748) and no-listen (758-762). The REAL gap is an UNDISCOVERABLE provider (has provide-store+listen but no mdns/bootstrap/external-address) runs silently dark; only consume-only enforced an entry path (763-776). New guard mirrors it inside the serves() block.

Wiring: profile helper default_lan_mdns() in operator.rs (single source of truth). Flag Option<bool>, resolve mdns_active = flag.unwrap_or(profile.default_lan_mdns()); feed resolved value to lan_mdns_enabled (main.rs:303), selected_mechanisms (289-293), NodeConfig.with_mdns (851 -> lib.rs:2259), and the new guard. ORDERING TRAP: the has_bootstrap inference that DERIVES profile (main.rs:724-726) must consume the RAW opt-in (Some(true)) only, never the profile-dependent resolved value (circular); lan-share is always explicitly declared so derive() never fires for it. nixos: mdns option nullOr bool default null; mdnsEnabled = if mdns!=null then mdns else (profile==lan-share); emit --libp2p-mdns / --libp2p-no-mdns accordingly; upstream-only assertion keys off resolved value. Disclosure line at main.rs:1376-1386.

Supply sibling folded in: default announce-after-fetch + a default listen multiaddr under lan-share so a bare --profile lan-share is a complete participant.

Biting e2e: scenario libp2p-lan-share-zeroconfig in scripts/e2e_harness.py, parametrize Libp2pMdnsTopology so node B argv = ONLY --profile lan-share; assert argv has NO --libp2p-mdns/bootstrap/provider-addr (mDNS implicit = the teeth); fetch exit0 + proxy upstream.nar==0 (peer-served) + provider liveness control. MUTATION reddening: make default_lan_mdns return false -> node B discovers nothing -> upstream fallback -> upstream.nar>=1.

DEEP gate = YES (codex + qa + mped): flips a privacy default off->on (presence disclosure) AND alters the shipped serve/discovery path; verify the e2e reddens at mDNS boundary, not a coincidental upstream hit; full just e2e for the Done claim (cross-crate profile change).
<!-- SECTION:PLAN:END -->
