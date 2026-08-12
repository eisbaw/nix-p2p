---
id: TASK-179
title: >-
  S7 libp2p e2e on a separate-netns routed podman network (fully discharge the
  F1 resolution-load-bearing caveat)
status: Done
assignee:
  - mped
created_date: '2026-08-12 22:28'
updated_date: '2026-08-12 23:04'
labels:
  - libp2p
  - e2e
  - daemon
  - wave-2c
dependencies: []
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Follow-up to TASK-161. TASK-161 landed the S7 libp2p arm GREEN on a shared-loopback podman POD (positive 0-egress + byte-identity + no-injection, a MISS arm, and a load-bearing control that kills the provider). But the pod shares one loopback netns, so it is NOT the 'REAL routed container network' the F1 arm specified: on shared loopback a kad get_providers query MAY pre-open a connection to the provider P, so the topology narrows but does not fully ISOLATE that the address-RESOLUTION (kad peer-routing) leg is load-bearing independently of a pre-populated shared routing table / pre-open connection (transport.rs's own stated HONEST LIMIT, carried from TASK-159/169). Build S7 on a podman BRIDGE network (each daemon in its own netns with its own container IP, provider --libp2p-listen on the routable IP), so a dial genuinely requires the DHT-resolved routable address and no loopback shortcut exists. Then add a control that breaks ONLY resolution (record discoverable but peer-routing yields no address) and assert the dial is REFUSED -> upstream fallback. This requires reworking the harness Pod (currently pod-shared-netns + published ports) to a bridge topology, or a parallel driver. Also add the missing LIBP2P-SERVED-TOTAL provider counter (the analogue of IROH-SERVED-TOTAL) so peer-served bytes are attributed provider-side, not only via the proxy egress ledger.
<!-- SECTION:DESCRIPTION:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Add a separate-netns libp2p topology to the harness: two non-internal podman bridge networks (netC consumer, netP provider/boot/proxy/origin), each daemon its OWN container (own netns => own loopback), joined by podman host routing. C reaches BOOT/P/proxy cross-subnet. The image lacks iproute2, so rely on podman inter-network routing (probe-confirmed) rather than an ip-route L3 router.
2. scenario s7-libp2p-netns: POSITIVE arm - P announces its routable netP IP; C bootstraps to BOOT ALONE, discovers+resolves+fetches; assert 0 upstream NAR egress, byte-identical, no-injection.
3. RESOLUTION-ONLY-BROKEN control (fresh topology, single delta = P --libp2p-listen 127.0.0.1): P alive + announces content, but publishes a NON-routable loopback addr; C resolves 127.0.0.1, dials its OWN loopback, fails => upstream fallback (upstream.nar>=1). Prove P reachable+alive via podman exec C -> HTTP GET P netP IP (path exists, P up). Oracle BITES: positive 0-egress vs control >=1, with P alive+reachable.
4. Extend cleanup to remove labelled networks. Keep s6-p2p / s7-libp2p / s7-libp2p-miss byte-identical (regression). Bounded runs, clean pods+networks.
5. Secondary (if reachable): LIBP2P-SERVED-TOTAL provider counter + libp2p xz target; else file follow-ups.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
LANDED GREEN (commit 3b08f29). CORE delivered: the separate-netns S7 + resolution-only-broken control that FULLY DISCHARGES the F1 caveat TASK-161 could not.

WHAT LANDED (scripts/e2e_harness.py only, NO Rust change): class Libp2pNetnsTopology + scenario_s7_libp2p_netns (SCENARIOS key "s7-libp2p-netns"); cleanup_pods now also removes label-scoped networks.

TOPOLOGY: each daemon is its OWN --network container (own netns => own 127.0.0.1), NOT a pod (pods share one loopback - the exact thing that blocked F1). Consumer C on podman bridge net-c (10.211.31.0/24); provider P + bootstrap BOOT + proxy + origin on net-p (10.211.32.0/24). The two /24s are joined by ROOTLESS PODMAN HOST ROUTING (probe-confirmed: a container on net-c reaches net-p, SNAT'd via the net-p gateway). GOTCHA: the e2e image ships NO iproute2 (ip not found), so the iroh-relay-style in-container "ip route" L3 router is NOT usable here - I rely on podman inter-network routing instead, and the routed hop is real (C reaches P by P routable net-p IP, never a shared loopback). Oracles run via podman exec into the proxy/consumer (python3 urllib; image has no curl); the client (nix build) runs as a --network net-c container substituting from C routable net-c IP. Bounded DHT settle LIBP2P_NETNS_CONVERGE_S=16s (routed hop is slower than the shared pod 12s).

HOW RESOLUTION IS ISOLATED (the F1 discharge): two arms, a MINIMAL PAIR whose ONLY delta is P --libp2p-listen. Separate loopbacks are what make it bite:
  * POSITIVE: P announces its ROUTABLE net-p IP => kad peer-routing resolves a DIALABLE address; C (told ONLY BOOT, no --libp2p-provider-addr, PeerId absent from argv) discovers+resolves+fetches byte-identical; upstream.nar==0, narinfo>0.
  * RESOLUTION-ONLY-BROKEN CONTROL: P announces ONLY /ip4/127.0.0.1. P is ALIVE, announces the SAME content (LIBP2P-SEED printed => announce reached quorum), and is REACHABLE at its routable net-p IP - PROVEN by an HTTP 200 GET of P /nix-cache-info FROM INSIDE C netns. But the address C RESOLVES for P is 127.0.0.1, which in C separate netns is C empty loopback => the dial fails => upstream fallback (upstream.nar>=1), still byte-identical. On a shared-loopback pod that same 127.0.0.1 would have REACHED P; here it cannot - so the peer-serve failure is attributable to RESOLUTION specifically.

WHY IT IS NOT A DISCOVERY MISS (closes the alternative): P announce is independent of its listen addr, so discovery (get_providers) is held constant across arms. Corroborated directly: the consumer daemon log in the control arm shows "discovered N provider record(s) ... but none yielded verified bytes" (daemon/src/source_libp2p.rs per-offer-failure path) and NOT "libp2p-kad miss" (Lookup::Miss). So C DID discover P via kad; only the address-resolution/dial leg broke.

ORACLE BITE: positive upstream.nar==0 vs control upstream.nar>=1, sole knob = the address P published for C to resolve.

RESULTS (nix develop -c, targeted --only, ONE combined bounded run): s7-libp2p-netns 15/15 PASS (82-83s); regression s6-p2p 11/11, s7-libp2p 11/11, s7-libp2p-miss 5/5 all PASS. just lint FULLY GREEN (check-independence, clippy workspace+daemon, cargo fmt, ruff check+format, source-guard, lock-sources). Pods/containers/label-networks CLEAN after (verified empty); disk 67G free unchanged; load calm.

SECONDARIES FILED (not Done-blockers per task guidance "if it balloons, file it and keep the topology proof"): TASK-180 = LIBP2P-SERVED-TOTAL provider counter (it is a fabric-libp2p SUBSTRATE change across nar.rs/server.rs/fabric.rs/main.rs + a nix e2e-image rebuild, more than a small daemon change - turnkey design captured in TASK-180). TASK-181 = a libp2p xz target (compressed->raw rewrite over libp2p; S6 covers it on iroh).

HONEST SCOPE: peer-attribution in the positive arm still rests on (0 upstream egress + BOOT-holds-nothing + byte-identity + no-injection) over the routed netns, NOT yet a provider-side served-bytes counter (TASK-180). "Reachable" in the control = P process up + net-c->net-p path present (both proven by the in-netns HTTP 200 to P routable IP); the control does NOT require P to be libp2p-listening on a routable addr (that IS the withheld input). This is the genuine resolution-only break the F1 caveat asked for.
<!-- SECTION:NOTES:END -->
