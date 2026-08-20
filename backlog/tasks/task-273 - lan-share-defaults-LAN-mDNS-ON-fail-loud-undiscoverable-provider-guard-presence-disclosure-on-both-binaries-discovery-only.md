---
id: TASK-273
title: >-
  lan-share defaults LAN mDNS ON + fail-loud undiscoverable-provider guard +
  presence disclosure on both binaries (discovery-only)
status: In Progress
assignee: []
created_date: '2026-08-19 21:41'
updated_date: '2026-08-20 00:25'
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
- [x] #2 The mDNS-default-on-with-opt-out vs fail-loud-only fork is decided by mped-architect (Mark-emulator) with the privacy tradeoff (mDNS discloses LAN presence) made explicit, and the chosen contract documented
- [ ] #3 First-run: a startup line states the discovery entry path and the LAN-presence disclosure, so the user can tell it is working without RUST_LOG surgery
- [ ] #4 A node given ONLY --profile lan-share (no bootstrap, no injected peer address) DISCOVERS a same-pin peer on the LAN and is SERVED a real nix build BY that peer (zero-config = discovery + consume/fetch), proven by a biting e2e (mutation: disable auto-mDNS -> RED). NOTE: cross-host SERVING from a bare lan-share node is NOT zero-config (loopback default listen; routable serve needs the allowlist) -> deferred TASK-276
- [ ] #5 Contradictory --libp2p-mdns / --libp2p-no-mdns FAILS CLOSED on both daemon-libp2p and the composite /bin/daemon (not last-wins)
- [ ] #6 A bare --profile lan-share DERIVES lan-share then FAILS LOUD on missing listen/supply (honest 'saw your intent, here is what is missing', never a silent no-op); supply/listen defaults moved to the new supply task
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
RE-SCOPED to Option B (Mark-emulator arbitration after codex NO-GO on 94fb494): DISCOVERY-ONLY. Revert the AC#5 supply/listen forcing (it caused the silent seed-nar bypass + false report + the complete-participant overclaim); split additive-supply + default-listen into a new task.

FIX (in 273): (a) guard rewrite main.rs~859 - entry path = mdns_active OR bootstrap OR provider_addr; external_address is NOT one (only identify metadata after connect); profile-aware remedy (no-allowlist lan-share: mDNS is its ONLY entry; public-share: mdns/bootstrap/provider-addr); prove it BITES by mutation. (b) disclosure parity: add the presence-disclosure line to the composite daemon/src/main.rs startup too; correct the daemon-libp2p announce_clause (drop the false static-supply-avoids-announce advice; accurate avoidance is --profile consume-only). (c) #8 fail-closed contradictory mdns flags on both binaries. (d) e2e #6: add a 3rd independent same-scope quorum/consumer node so mut(default_lan_mdns->false) isolates B and B falls back to upstream (upstream.nar>=1 attributable), keeping the argv teeth; else honestly downgrade the oracle claim. (e) retitle + strip complete-participant/serves claims about the bare node.
REVERT: DEFAULT_LAN_SHARE_LISTEN const+block, default_announce_after_fetch(), nixos wantsAnnounceAfterFetch lan-share clause + defaultLanShareListen. KEEP default_lan_mdns() + provider back-fill.
Gate: per-crate + FULL just e2e + qa+mped+codex re-review; guard mutation-proven; e2e mutation attributable.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Implementation (commit b1be7da): tri-state mDNS (Option<bool> + --libp2p-no-mdns), operator.rs default_lan_mdns()/default_announce_after_fetch() helpers, explicit --profile lan-share back-fills provider axis, AC#5 lan-share defaults (announce-after-fetch ON + LOOPBACK listen), AC#1 undiscoverable-provider fail-loud guard, AC#4 startup disclosure line. nixos: mdns nullOr bool + resolved mdnsEnabled + lan-share mirrors defaults. 4 new unit tests. Per-crate: 432 passed 0 failed; fmt+ruff clean. IMPORTANT correction to the plan: DEFAULT_LAN_SHARE_LISTEN is LOOPBACK not 0.0.0.0 - the TASK-102 lan-isolation guard refuses a routable listen for a no-allowlist lan-share, so a wildcard default would fail startup. Zero-config gets mDNS discovery + peer FETCH; cross-host SERVING needs the allowlist door or explicit routable listen -> filed TASK-276. e2e scenario libp2p-lan-share-zeroconfig added (node B argv ONLY --profile lan-share on /bin/daemon-libp2p, scope defaults to v1 so provider runs on v1). Image build + biting run + mutation proof pending.

E2E verified (commit 3328c28, image .#e2e-image). BASELINE PASS: libp2p-lan-share-zeroconfig 13/13 checks, 76.8s - node B (bare --profile lan-share, /bin/daemon-libp2p) argv teeth all green (NO --libp2p-mdns/bootstrap/listen/scope/provider-addr), fetch exit0 + byte-identical NarHash + upstream.nar==0 (peer-served) + provider-liveness control. MUTATION PROOF (bites): (1) default_lan_mdns->false rebuilt+reran: RED - node B fails LOUD via the AC#1 undiscoverable-provider guard (no way to be discovered), never HTTP-ready, harness FATAL exit2 (also reddened 2 unit tests). (2) source_config mdns_enabled->false rebuilt+reran: RED exit2 - node B runs but its mDNS-off means the lone-genesis provider node A cannot find its put-quorum peer (node B) -> node A exits without announcing -> FATAL. NEITHER reaches the upstream.nar oracle because node B mDNS is load-bearing for the whole 2-node topology (node B is also node A quorum peer) - the bite is broader than upstream fallback. upstream.nar oracle discrimination is independently established by sibling libp2p-mdns-scope-isolation (>=1 on discovery failure). All temp mutations reverted; tree == committed; per-crate 432+4 green. HONEST DEVIATION from plan: brief expected upstream.nar>=1 RED but my AC#1 guard converts the silent-dark path into a loud refusal (stronger).

DEEP-gate (mped) correction to record honestly: the zero-config guarantee is DISCOVERY + CONSUME (fetch), NOT cross-host serving. A bare --profile lan-share defaults a LOOPBACK listen (TASK-102 lan_isolation_or_refuse refuses a routable listen without the allowlist), so it discovers+fetches over the LAN but only serves to loopback/same-host; cross-host serving is TASK-276. AC#2 reworded accordingly.

Also: the composite /bin/daemon (NixOS-shipped) is NOT silently dark for the undiscoverable case -- a pre-existing entry-path guard (daemon/src/main.rs:1232) already fails it loud; TASK-277 residual is external-address parity + message unification, NOT a missing guard.

DEEP gate re-run: codex (cross-model) VERDICT_NO_GO on commit 94fb494 -- caught real defects mped (same-model) GO'd past. e2e: 11 default scenarios PASS but libp2p-lan-share-zeroconfig is NOT in the default just-e2e set (unexercised). codex findings:
1 CRIT: forced announce-after-fetch selects store-supply mode that reads only provide_store, silently bypassing --libp2p-seed-nar; startup falsely reports 1 seeded NAR.
2 CRIT: AC#1 guard accepts --libp2p-external-address as discovery, but it is NOT an entry path (no dial/no kad seed) -> provider still silent-dark.
3 CRIT(honesty): loopback default => "complete LAN participant" false; narrow task to discovery+consume.
4 CRIT(privacy): composite/NixOS path enables mDNS with NO disclosure (disclosure only in daemon-libp2p); and the "static supply avoids announce" advice is false given #1.
5 HIGH: guard omits provider-addr (a real kad entry hint) -> over-rejects a valid PublicShare; and its bootstrap remedy cannot produce a runnable no-allowlist LanShare.
6 HIGH(test-honesty): neither mutation proves B falls back to UPSTREAM (mut1 fails AC#1 pre-body; mut2 kills A quorum); needs a 3rd same-scope quorum peer to isolate the boundary.
7 MAJOR: composite parser rejects --libp2p-external-address as unknown-flag while the NixOS module emits it -> unusable third path on the shipped surface.
8 MED(privacy): contradictory --mdns/--no-mdns is last-wins (order-dependent) -> should fail closed.
Confirmed OK: raw/derived/resolved ordering (no circular feedback); no mDNS content-enumeration shortcut. Routing re-scope + fix spec through Mark-emulator.
<!-- SECTION:NOTES:END -->
