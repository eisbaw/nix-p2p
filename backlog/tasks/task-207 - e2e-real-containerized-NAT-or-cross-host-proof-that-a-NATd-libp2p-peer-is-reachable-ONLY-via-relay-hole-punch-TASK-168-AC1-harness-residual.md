---
id: TASK-207
title: >-
  e2e: real containerized-NAT or cross-host proof that a NATd libp2p peer is
  reachable ONLY via relay/hole-punch (TASK-168 AC#1 harness residual)
status: To Do
assignee: []
created_date: '2026-08-14 17:19'
updated_date: '2026-08-15 08:42'
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
<!-- SECTION:NOTES:END -->
