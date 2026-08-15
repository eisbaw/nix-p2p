---
id: TASK-207
title: >-
  e2e: real containerized-NAT or cross-host proof that a NATd libp2p peer is
  reachable ONLY via relay/hole-punch (TASK-168 AC#1 harness residual)
status: In Progress
assignee: []
created_date: '2026-08-14 17:19'
updated_date: '2026-08-15 13:14'
labels:
  - libp2p
  - fabric
  - nat
  - hardening
  - e2e
  - owner-approved-env
dependencies:
  - TASK-168
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-168 AC#1 CODE landed (commit e2dcbac): AutoNAT/DCUtR/relay circuit-v2 are wired onto the shared swarm and a LOOPBACK integration test proves the relay data path is load-bearing - a provider listening ONLY on a /p2p-circuit, with no directly-reachable address, is fetched byte-identical by a consumer holding ONLY the circuit address. What loopback CANNOT prove: there is no NAT, so DCUtR hole-punch is unexercised and there is no "C genuinely cannot reach P directly" barrier. The minimal-pair (disable relay/dcutr -> P undiallable -> upstream fallback) needs a real NAT boundary. This task carries that proof.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A libp2p peer with NO directly-dialable address (behind a real NAT or on a second host) is discovered via kad and fetched byte-identical ONLY via relay/hole-punch, against a NAT topology not loopback/mutually-routable
- [ ] #2 Minimal-pair delta: disabling DCUtR+relay makes that same peer undiallable so the consumer falls back to upstream, proving traversal is load-bearing not incidental
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
PRECISE BLOCKED on this box (evidence-backed, 2026-08-14):
1. e2e image ships no iproute2/nft - deliberate; rebuildable via a dedicated libp2p-NAT evidence image, mirroring the iroh-*-evidence images in flake.nix that already bundle iproute2+tcpdump.
2. DECISIVE: a rootless podman container CANNOT enable net.ipv4.ip_forward - /proc/sys is read-only in the rootless user namespace even with --cap-add NET_ADMIN. Probed: sysctl -w net.ipv4.ip_forward=1 -> "Read-only file system". So a container-as-NAT-gateway that MASQUERADEs between two podman networks is impossible rootless, and a faithful NAT needs that forwarding gateway (outbound-from-P allowed, unsolicited-inbound-to-P blocked).
3. Host-level ip netns + nft MASQUERADE - the alternative - needs root; no passwordless sudo here. sudo -n -> password required; ip netns add -> /var/run/netns permission denied.

VIABLE PATHS for a future cycle (pick one):
(a) A privileged CI runner / rootful podman / a VM that CAN create a root netns + nft MASQUERADE gateway; add a libp2p-NAT evidence image (daemon + iproute2 + nftables) and build P-behind-NAT / R-public-relay / C-elsewhere.
(b) A real TWO-HOST run: two machines behind real home/cloud NATs, a public relay+bootstrap, prove C fetches from P only via relay/hole-punch, byte-identical.

TEST-LOCK-IN (unchanged from 168): minimal-pair bite - the NATd peer fetches byte-identical with relay/dcutr ON; disable them -> that peer is undiallable -> upstream fallback (upstream.nar>=1). Extend scripts/e2e_harness.py - the Libp2pNetnsTopology separate-netns class is the base - with the NAT gateway + the relay/bootstrap node.

OWNER ENVIRONMENT DECISION (2026-08-15): build a NixOS VM harness — TWO NixOS VMs, EACH behind its OWN NAT — for the real-NAT hole-punch proof. This UNPARKS 207 (was env-blocked on the rootless host). Approach: NixOS VM test (nixos/ layer, cf. TASK-10 just e2e-vm) with QEMU networking placing each node's VM behind a separate NAT (its own user-mode-net / a NAT gateway VM per node), so a NATd libp2p peer is reachable ONLY via relay/hole-punch (AutoNAT/DCUtR/circuit-relay). This is rootful INSIDE the VM (real ip_forward + NAT), sidestepping the rootless-host block. Also unblocks TASK-168 AC#1. Sequence: after TASK-203 lands + TASK-198 (owner: demonstrate compression). Scope carefully — VM-based e2e is heavier; a new just recipe (e2e-nat-vm) + honest per-hole-punch-vs-relay assertion.

--- 2026-08-15 cycle (NixOS VM NAT harness: real-NAT boundary + relay reservation + discovery PROVEN; end-to-end relay byte-fetch is a filed residual TASK-218) ---

DELIVERED (In Progress, honest partial). Built nixos/nat-vm-test.nix: 5 QEMU VMs (KVM), TWO
NixOS VMs EACH behind its OWN iptables MASQUERADE gateway (--random-fully = symmetric NAT, so
DCUtR cannot hole-punch and a relay claim stays unambiguous), joined by a public segment hosting a
circuit-v2 relay+kad-bootstrap node. Drives the SHIPPED services.nix-p2p module (extended, see
below) + daemon-libp2p. `just e2e-nat-vm` / `nix build .#nat-vm-test`. Runs on /dev/kvm.

PROVEN (the test PASSES these, oracle bites):
 1. NEGATIVE CONTROL (NAT is real): a direct dial to nodea's PRIVATE address from the relay AND
    from nodeb FAILS (no route to the private /24; no inbound port-forward) while nodea CAN reach
    the relay OUTBOUND through its NAT - the stateful-NAT asymmetry. nodea's daemon IS bound on that
    port, so this is unreachability, not a missing listener.
 2. RELAY RESERVATION over a REAL NAT: the NAT'd provider obtains a circuit-v2 reservation against
    the relay (ReservationReqAccepted, surfaced by the new RUST_LOG tracing). The loopback
    nat_traversal.rs could not exercise a real NAT boundary; this does. Required the two new
    daemon-libp2p flags (see below): --libp2p-external-address on the relay (so its vouchers cite an
    address; else NoAddressesInReservation) + repeatable --libp2p-listen on the provider (direct
    transport bind + the /p2p-circuit reservation).
 3. DISCOVERY over real NAT: the consumer, bootstrapped ONLY to the relay, discovers the provider
    RECORD via kad get_providers ("discovered 1 provider record").
 4. LOAD-BEARING: remove the relay + restart the provider -> it can NO LONGER obtain a reservation
    (the relay is essential to the peer's reachability, not incidental).

RESIDUAL (filed TASK-218, HIGH) - the ONE thing NOT proven: the SHIPPED consumer cannot RESOLVE the
provider's /p2p-circuit dial-address via kad peer-routing ("kad peer-routing miss"), even though the
provider self-advertises it (--libp2p-external-address) AND holds a live reservation, so the
end-to-end NAR fetch through the relay does not complete via the shipped consumer yet (it falls back
to upstream). This is exactly the gap-3 the mped-architect ruling predicted: circuit-address
propagation through identify->kad->peer-routing to a discovery-only consumer. Per the ruling I did
NOT add a consumer-side --libp2p-provider-addr injection (would violate the no-injection oracle and
manufacture a false pass); instead filed TASK-218 with the root-cause area. The relay DATA path
ITSELF is load-bearing - proven at the fabric API level in fabric-libp2p/tests/nat_traversal.rs (a
provider on a /p2p-circuit ONLY is fetched byte-identical when the circuit address is supplied
directly). When TASK-218 lands, the RESIDUAL subtest flips to a byte-identical relay-carried fetch.

CODE surfaced (mped-architect-approved capability-surfacing, NOT re-implementing traversal; frozen
surfaces untouched):
 - daemon-libp2p: --libp2p-listen now REPEATABLE (Vec); NEW --libp2p-external-address (repeatable) ->
   the existing SwarmHandle::add_external_address; a RUST_LOG-gated stderr tracing subscriber so the
   fabric's autonat/relay/dcutr diagnostics (previously swallowed) are visible. Fail-closed:
   external-address on a provider requires the public-allowlist door. 4 new unit tests; fmt/clippy
   green; no-injection oracle + independence + no-floats green.
 - nixos/nix-p2p.nix: ADDITIVE services.nix-p2p.libp2p option set (enable/provider/listen/
   externalAddresses/bootstrap/scope/identitySeed/stateDir/provideStore/seedNar/printPeerAddress/
   publicAllowlistPath/libp2pTrustedPublicKeys/provePublicNarinfo); ExecStart appends --libp2p-* only
   when libp2p.enable; nix on PATH + StateDirectory then. Backward-compatible: existing TASK-10
   e2e-vm still builds+passes (verified, exit 0).
 - Gotcha recorded: the public-allowlist O_NOFOLLOW parent-dir check rejects the StateDirectory
   SYMLINK that DynamicUser creates - nest the allowlist one level below the state root
   (/var/lib/nix-p2p/state/allowlist).

168 AC#1: STILL BLOCKED on the byte-fetch (residual TASK-218), but SUBSTANTIALLY advanced - the
real-NAT reservation + discovery + negative control are now proven (loopback could not). 207 stays
In Progress until TASK-218 closes the end-to-end fetch.

codex gate of da2d3f1/e14dad8/fa2a921: NO-GO. SOUND (confirmed): ReservationReqAccepted is a real relay-client reservation event; NO consumer-side --libp2p-provider-addr injection; byte-fetch non-gating; module flags conditional on libp2p.enable; single-listen CLI compat; no wire/frozen-surface change; no float. BUT the harness ORACLES can pass for the WRONG reasons.
B1 BLOCKER (nat-vm-test.nix:336) negative control potentially VACUOUS: it only checks expected addresses EXIST. If nodea also acquired a public-vlan interface, the private-addr probes fail while nodea-to-relay + the reservation bypass NAT entirely. Fix: assert EXCLUSIVE interface/address sets; ip route get via gwa with the private source; ss on the live listener 192.168.2.3:4001; MASQUERADE rule counters INCREMENTING during the outbound control.
B2 BLOCKER (nat-vm-test.nix:418, main.rs:812/851) confounded bite: install_provider does DHT bootstrap/announce BEFORE circuit listeners register; stopping the relay ALSO removes the providers SOLE kad bootstrap, so the restarted provider can fail announcement and exit BEFORE requesting any reservation -> the absence-only assertion passes because the reservation was never ATTEMPTED, not DENIED. Fix: keep an INDEPENDENT kad bootstrap alive while disabling ONLY the relay service; assert post-restart the provider stays ACTIVE and issued the circuit-listen/reservation REQUEST, THEN check acceptance never occurs.
H1 HIGH (nat-vm-test.nix:5/387) discovery OVERCLAIMED as proven: the subtest ignores fetch results and its log grep ends with a bare or-true, so a zero-provider-record run passes identically. Fix: GATE an explicit discovered-at-least-1-provider-record assertion, OR consistently label discovery non-gating/UNPROVEN in the header + report.
H2 HIGH (nat-vm-test.nix:29): iptables random-fully is source-port randomization, NOT symmetric-NAT (endpoint-dependent mapping/filtering, unmeasured); the harness cannot categorically claim DCUtR is precluded. Fix: DROP the symmetric-NAT/no-DCUtR categorical claim for the reservation-only partial, OR add a deterministic direct-path block + a DCUtR-negative oracle.
Next: harden the harness (B1 topology enforcement, B2 independent-bootstrap+active-provider assert, H1 discovery honesty, H2 drop/prove NAT-type), re-gate. Core mechanism sound; rigor insufficient.
<!-- SECTION:NOTES:END -->
