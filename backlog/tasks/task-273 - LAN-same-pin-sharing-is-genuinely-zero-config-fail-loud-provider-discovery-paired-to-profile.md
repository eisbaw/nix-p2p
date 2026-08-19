---
id: TASK-273
title: >-
  LAN same-pin sharing is genuinely zero-config (fail-loud provider; discovery
  paired to profile)
status: In Progress
assignee: []
created_date: '2026-08-19 21:41'
updated_date: '2026-08-19 23:14'
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
- [x] #1 A lan-share/public-share provider with no shareable entry path fails loud at startup (symmetry with consume-only), never a silent no-op
- [x] #2 A node given ONLY --profile lan-share (no bootstrap, no injected peer address) discovers a same-pin peer on the LAN and serves a real nix build; proven by a two-node e2e that BITES (mutation: disable the auto-mDNS/zero-config wiring -> fetch falls back to upstream)
- [x] #3 The mDNS-default-on-with-opt-out vs fail-loud-only fork is decided by mped-architect (Mark-emulator) with the privacy tradeoff (mDNS discloses LAN presence) made explicit, and the chosen contract documented
- [x] #4 First-run: a startup line states the discovery entry path and the LAN-presence disclosure, so the user can tell it is working without RUST_LOG surgery
- [x] #5 Supply/reachability zero-config: under lan-share, announce-after-fetch and a listen multiaddr are DEFAULTED so a bare --profile lan-share passes the nothing-shareable (main.rs:740-748) and listen (758-762) guards with no extra flags (folded in so AC#2 is genuinely achievable end-to-end)
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

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Implementation (commit b1be7da): tri-state mDNS (Option<bool> + --libp2p-no-mdns), operator.rs default_lan_mdns()/default_announce_after_fetch() helpers, explicit --profile lan-share back-fills provider axis, AC#5 lan-share defaults (announce-after-fetch ON + LOOPBACK listen), AC#1 undiscoverable-provider fail-loud guard, AC#4 startup disclosure line. nixos: mdns nullOr bool + resolved mdnsEnabled + lan-share mirrors defaults. 4 new unit tests. Per-crate: 432 passed 0 failed; fmt+ruff clean. IMPORTANT correction to the plan: DEFAULT_LAN_SHARE_LISTEN is LOOPBACK not 0.0.0.0 - the TASK-102 lan-isolation guard refuses a routable listen for a no-allowlist lan-share, so a wildcard default would fail startup. Zero-config gets mDNS discovery + peer FETCH; cross-host SERVING needs the allowlist door or explicit routable listen -> filed TASK-276. e2e scenario libp2p-lan-share-zeroconfig added (node B argv ONLY --profile lan-share on /bin/daemon-libp2p, scope defaults to v1 so provider runs on v1). Image build + biting run + mutation proof pending.

E2E verified (commit 3328c28, image .#e2e-image). BASELINE PASS: libp2p-lan-share-zeroconfig 13/13 checks, 76.8s - node B (bare --profile lan-share, /bin/daemon-libp2p) argv teeth all green (NO --libp2p-mdns/bootstrap/listen/scope/provider-addr), fetch exit0 + byte-identical NarHash + upstream.nar==0 (peer-served) + provider-liveness control. MUTATION PROOF (bites): (1) default_lan_mdns->false rebuilt+reran: RED - node B fails LOUD via the AC#1 undiscoverable-provider guard (no way to be discovered), never HTTP-ready, harness FATAL exit2 (also reddened 2 unit tests). (2) source_config mdns_enabled->false rebuilt+reran: RED exit2 - node B runs but its mDNS-off means the lone-genesis provider node A cannot find its put-quorum peer (node B) -> node A exits without announcing -> FATAL. NEITHER reaches the upstream.nar oracle because node B mDNS is load-bearing for the whole 2-node topology (node B is also node A quorum peer) - the bite is broader than upstream fallback. upstream.nar oracle discrimination is independently established by sibling libp2p-mdns-scope-isolation (>=1 on discovery failure). All temp mutations reverted; tree == committed; per-crate 432+4 green. HONEST DEVIATION from plan: brief expected upstream.nar>=1 RED but my AC#1 guard converts the silent-dark path into a loud refusal (stronger).
<!-- SECTION:NOTES:END -->
