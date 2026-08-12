---
id: TASK-161
title: >-
  Podman multi-daemon libp2p e2e: decentralized discover->fetch->serve across
  real containers
status: Done
assignee:
  - mped
created_date: '2026-08-12 10:22'
updated_date: '2026-08-12 23:12'
labels:
  - libp2p
  - daemon
  - e2e
  - wave-2c
dependencies:
  - TASK-160
  - TASK-164
  - TASK-178
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Follow-up to TASK-160 (which proved the in-process daemon<->libp2p integration test). Stand up >=3 real daemon containers on a podman pod (a bootstrap, a serving provider that announces a known NAR, and a consumer daemon): the consumer discovers the provider via libp2p-kad (NOT injected) and fetches+serves the NAR byte-identical through its serving stack, with a MISS arm falling back to upstream. Extends the existing s6-p2p iroh e2e with a libp2p arm. Depends on the production main.rs libp2p config wiring.
<!-- SECTION:DESCRIPTION:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Harness plumbing: add a 3-daemon libp2p topology to Pod (_create_libp2p): BOOT (genesis provider seeding a DECOY nar, dummy bootstrap, prints addr), PROVIDER P (seeds the real target NAR, bootstraps to BOOT, prints addr), CONSUMER C (bootstraps to BOOT ONLY, no --libp2p-provider-addr). Parse LIBP2P-PROVIDER-ADDR/LIBP2P-SEED. All on shared pod loopback (documented scope limit vs separate-netns).
2. scenario_s7_libp2p (positive + load-bearing control): C builds the target NAR held ONLY by P (BOOT holds a decoy) -> discovers P via kad through BOOT (never injected), fetches byte-identical, 0 upstream NAR egress. Control: kill P -> no peer serves -> upstream fallback (proves the DHT-mediated peer path is load-bearing; BOOT cannot serve the target).
3. scenario_s7_libp2p_miss: build a NAR no peer announces -> clean upstream fallback.
4. Rebuild .#e2e-image (carries TASK-178 daemon). Run targeted: s7-libp2p, s7-libp2p-miss, plus s6-p2p regression. Bounded runs. Clean pods.
5. Honest scope: no LIBP2P-SERVED-TOTAL counter (attribution via proxy upstream.nar==0 + byte-identity); shared-loopback not a separate-netns routed net; F1 control conflates discovery+resolution legs (documented, matches transport.rs stated limit). NO Rust changes.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
LANDED GREEN (commits 1919d78 plumbing, 9d97329 fix+green). scripts/e2e_harness.py: Pod._create_libp2p + _await_libp2p_identity + _await_http_ready + libp2p_consumer_argv; scenarios scenario_s7_libp2p (+ SCENARIOS 's7-libp2p') and scenario_s7_libp2p_miss ('s7-libp2p-miss'). NO Rust changes: TASK-169 already moved resolve-then-dial INSIDE fabric-libp2p transport (transport.rs), so the daemon layer needs no add_address of a resolved DialInfo - the F1 code item (1) is satisfied by the existing architecture.

TOPOLOGY (3 real daemon containers, one pod): lp-boot (a PURE kad router, FIXED identity seed so its PeerId is derived offline, holds NO content, never announces) + lp-provider P (seeds the target, bootstraps to BOOT, announces) + lp-consumer C (bootstraps to BOOT ALONE, NO --libp2p-provider-addr). C discovers P via kad get_providers and resolves P's dial address via kad peer-routing, both inside the fabric.

RESULTS (nix develop -c, targeted --only, TWO bounded runs each; s6-p2p regression run alongside): s7-libp2p 11/11 PASS, s7-libp2p-miss 5/5 PASS, s6-p2p 11/11 PASS (regression green). Pods+containers clean after (podman pod ps / ps -a empty), disk 67G free, load calm. just lint fully green (clippy/fmt/ruff/source-guard/independence).

WHAT THE ARMS PROVE: positive = C serves the NAR byte-identical (NarHash==signed upstream) with 0 upstream NAR egress and narinfo egress>0, discovered via kad (no-injection asserted from C's actual container argv - provider PeerId absent, no --libp2p-provider-addr). MISS = a NAR no peer announces -> clean upstream fallback (upstream.nar>=1). Load-bearing control = kill P -> the target (held ONLY by P; BOOT holds nothing) is unreachable via any peer -> upstream fallback (upstream.nar>=1). ORACLE BITE: the MISS + control arms both flip upstream.nar to >=1, so the positive 0-egress oracle genuinely discriminates (a silently-broken libp2p would fall to upstream and fail it).

GOTCHAS (for the next implementer): (1) A LONE genesis PROVIDER cannot announce - put-provider needs >=1 reachable peer for quorum ('the quorum failed; needed 1 peers'). Fix: a separate PURE kad node (non-provider) must be up and reachable BEFORE the provider starts; gate it on HTTP readiness (_await_http_ready). (2) Only a --libp2p-provider prints LIBP2P-PROVIDER-ADDR, so a non-provider bootstrap node cannot advertise its address - use a FIXED --libp2p-identity-seed and derive its PeerId offline (ed25519 pubkey -> protobuf 08 01 12 20 <32B> -> identity-multihash 00 24 <..> -> base58btc; a drift is caught at the first run when P cannot reach BOOT). (3) Every libp2p daemon REQUIRES --libp2p-bootstrap; the genesis points at a valid-format UNREACHABLE dummy PeerId (self-lookup fails best-effort, node still binds). (4) --libp2p-scope must MATCH across all three or kad protocol names differ and they never meet. (5) Bounded LIBP2P_CONVERGE_S sleep (12s) before the measured build lets the 3-node DHT settle; a per-NAR find_providers racing an unconverged DHT would false-negative the 0-egress oracle.

HONEST SCOPE / DEFERRED: the pod shares ONE loopback netns, so this is NOT the 'REAL routed container network' the F1 arm specified. On shared loopback a kad query MAY pre-open a connection to P, so the load-bearing control proves the DHT-mediated peer PATH to P is load-bearing (BOOT holds no content, no injection) but does NOT fully ISOLATE the address-RESOLUTION leg from a pre-populated shared routing table / pre-open (transport.rs's own stated HONEST LIMIT). Fully discharging the TASK-159/169 caveat needs a separate-netns podman BRIDGE topology + a resolution-only-broken control -> filed as TASK-179. Also: libp2p target is 'lib' (already-raw), so the compressed->raw narinfo rewrite is NOT exercised on the libp2p path (S6's app covers it on iroh) - a libp2p xz target is a follow-up. And there is no LIBP2P-SERVED-TOTAL provider counter yet (the IROH-SERVED-TOTAL analogue); peer-served bytes are attributed via the proxy egress ledger, not provider-side.

UPDATE - F1 FULLY DISCHARGED by TASK-179 (commit 3b08f29): the separate-netns S7 (scenario s7-libp2p-netns) adds a resolution-only-broken control that BITES with the provider ALIVE + reachable - proving kad address-RESOLUTION is load-bearing independently of the shared-loopback pre-open/shortcut THIS task's shared-pod S7 could not isolate. The shared-pod s7-libp2p arm here REMAINS as a green regression guard. The two remaining deferred items are now filed as their own tasks: TASK-180 (LIBP2P-SERVED-TOTAL provider counter) and TASK-181 (libp2p xz target).
<!-- SECTION:NOTES:END -->
