---
id: TASK-207
title: >-
  e2e: real containerized-NAT or cross-host proof that a NATd libp2p peer is
  reachable ONLY via relay/hole-punch (TASK-168 AC#1 harness residual)
status: Done
assignee:
  - phase3-task207
created_date: '2026-08-14 17:19'
updated_date: '2026-08-17 23:17'
labels:
  - libp2p
  - fabric
  - nat
  - hardening
  - e2e
  - owner-approved-env
dependencies:
  - TASK-218
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-168 AC#1 CODE landed (commit e2dcbac): AutoNAT/DCUtR/relay circuit-v2 are wired onto the shared swarm and a loopback integration test proves the relay data path is load-bearing. Loopback cannot prove a real NAT barrier or that the provider is genuinely not directly dialable. This task carries the real-NAT proof: a traversal-only byte-identical positive fetch followed by a warm single-variable bite that observes no DCUtR direct upgrade, stops the sole relay, retains the same consumer/provider daemons, positively attributes circuit UNREACHABLE, and only then demonstrates scoped already-raw upstream fallback.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 A libp2p peer with NO directly-dialable address (behind a real NAT or on a second host) is discovered via kad and fetched byte-identical ONLY via relay/hole-punch, against a NAT topology not loopback/mutually-routable
- [x] #2 Warm single-variable delta: after proving no DCUtR direct upgrade occurred, stopping the sole provider relay makes a fresh fetch fail with circuit UNREACHABLE on the same converged consumer and unchanged daemon; only then, exposing the same signed raw NAR at the unchanged Compression:none fixed-point HTTP URL makes production upstream fallback realise the byte-identical path
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Seed a systemd-owned RuntimeDirectory with metadata only and stage the signed already-raw payloadA NAR outside the served root.
2. Preserve AC#1 byte-identical relay fetch and the warm relay-UP/relay-DOWN bite through its positive attribution, no-DCUtR, sole-relay, and provider-process assertions; pin the converged consumer PID through every later phase.
3. After the relay-down bite, atomically expose the staged raw NAR at the same fixed-point URL; use fresh journal cursors and retry the same path on the same daemon, gating UNREACHABLE -> p2p miss -> upstream fallback, an exact HTTP 200, and signed NarHash.
4. Keep compressed-to-raw fallback explicitly out of scope, mutation-test activation RED, restore it, and run e2e-nat-vm plus repository gates before independent parallel review.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
PRECISE BLOCKED on this box (evidence-backed, 2026-08-14):
1. e2e image ships no iproute2/nft - deliberate; rebuildable via a dedicated libp2p-NAT evidence image, mirroring the iroh-*-evidence images in flake.nix that already bundle iproute2+tcpdump.
2. DECISIVE: a rootless podman container CANNOT enable net.ipv4.ip_forward - /proc/sys is read-only in the rootless user namespace even with --cap-add NET_ADMIN. Probed: sysctl -w net.ipv4.ip_forward=1 -> "Read-only file system". So a container-as-NAT-gateway that MASQUERADEs between two podman networks is impossible rootless, and a faithful NAT needs that forwarding gateway (outbound-from-P allowed, unsolicited-inbound-to-P blocked).
3. Host-level ip netns + nft MASQUERADE - the alternative - needs root; no passwordless sudo here. sudo -n -> password required; ip netns add -> /var/run/netns permission denied.

VIABLE PATHS for a future cycle (pick one):
(a) A privileged CI runner / rootful podman / a VM that CAN create a root netns + nft MASQUERADE gateway; add a libp2p-NAT evidence image (daemon + iproute2 + nftables) and build P-behind-NAT / R-public-relay / C-elsewhere.
(b) A real TWO-HOST run: two machines behind real home/cloud NATs, a public relay+bootstrap, prove C fetches from P only via relay/hole-punch, byte-identical.

TEST-LOCK-IN (final warm single-variable form; supersedes the original disable-relay/DCUtR-together proposal): the NATd peer fetches byte-identical through the sole relay while a successful DCUtR direct upgrade is observed absent; stop only that relay on the same converged consumer and require a fresh circuit-UNREACHABLE failure with unchanged daemons; only afterward activate the already-raw fixed-point upstream NAR and require production fallback. This avoids a restart/discovery confound and does not claim compressed-to-raw fallback.

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

FINALIZATION landed + orchestrator-verified (recovery commit d602839; the finalization agent left it uncommitted after the VM run). codex B1/H1/H2 findings ADDRESSED, B2 honestly deferred:
B1 FIXED: negative control now enforces the NAT topology (exclusive interfaces/addresses, ip route get via gwa with the private source, live listener via ss, MASQUERADE counters increment during the outbound control) -> no longer passes on a stray public interface.
H1 FIXED: discovery gated (observed discovered>=1 provider record; the bare or-true removed); dial-address-resolution + byte-fetch kept explicitly non-gating / UNPROVEN (TASK-218); header/report wording matches.
H2 FIXED: dropped the unfounded symmetric-NAT-therefore-no-DCUtR categorical claim; unit renamed symmetric-nat to nat-masquerade; framed as a reservation-only partial.
B2 RESOLVED-AS-DEFERRED: NOT shipped as a tautological provider-side bite (libp2p 0.18 connection-scoped reservation renewal makes an in-process re-attempt unobservable). Keeps the real reservation EVENT as positive proof + supporting structural guards, incl. a NEW additive --libp2p-no-relay-server (module services.nix-p2p.libp2p) so zboot runs kad-only and no ALTERNATIVE relay path exists. The LOAD-BEARING consumer-side end-to-end reachability bite (relay-up fetch-through-relay / relay-down fresh-fetch-fails) is DEFERRED to TASK-218.
VERIFIED (orchestrator): nix build .#nat-vm-test PASSED (daemon-libp2p tests all green during the VM run, VMs cleaned up); cargo test daemon-libp2p + daemon 0-failed; fmt + clippy -D-warnings + no-floats clean; frozen surfaces untouched; module additive (existing TASK-10 e2e-vm unaffected). No co-author.
STATUS: In Progress. The FINAL codex re-gate of the complete NAT harness happens when TASK-218 lands the byte-fetch + the load-bearing reachability bite. 168 AC#1 still blocked on 218.

2026-08-17 phase3-task207 start: onboarding confirmed TASK-218 is complete and already proves byte-identical relay carriage plus the warm relay-UP/relay-DOWN load-bearing bite. TASK-207 AC#2 remains literal because narinfoUpstream intentionally strips signedCache/nar, so production FallbackNarSource reaches HTTP after peer Unreachable but receives 404. Root fix is a runtime-mutable HTTP root activated only after the existing relay bite; no transport redesign or direct Nix HTTP substituter.

2026-08-17 mutation + root-cause correction: with staged-NAR activation deliberately disabled, `nix develop -c just e2e-nat-vm` went RED exactly in the new AC#2 retry (exit 1): AC#1 passed in 298.83s; B2 relay-UP/relay-DOWN attribution passed in 13.14s; the final same-consumer retry logged fresh NAR fetch UNREACHABLE -> p2p miss/fallback and HTTP 404, then failed its required realise. Restored activation. The trace exposed a fixture/rewrite representation mismatch: the original store-hash URL was a valid opaque binary-cache token, but production rewrite::to_raw changes an already-raw URL to the signed NarHash digest and UpstreamHttp later fetches that exact rewritten token. Aligned this test fixture with that fixed point (nixos/sign-narinfo.py + signedCache): `.narinfo` stays store-hash-keyed, while this URL and raw NAR filename use narDigest; a build-time URL self-check was added. Production transport remains unchanged; cache-timing priming was rejected. This does not close the known compressed-to-raw fallback gap.

2026-08-18 pre-review implementation evidence (subsequently accepted after the reviewer findings below were fixed):

ROOT CAUSE / FIX: TASK-218 already supplied the real-NAT byte carriage and warm relay-UP/relay-DOWN bite, but the immutable narinfo-only upstream made literal AC#2 impossible: production fallback correctly reached HTTP and got 404. The harness now seeds a systemd RuntimeDirectory with metadata only, stages the signed raw NAR outside the served root, and atomically hard-links it into the unchanged live HTTP root only after B2. The already-raw fixture was aligned with the daemon rewrite fixed point: `.narinfo` stays keyed by store-path hash while this Compression:none URL and raw NAR filename use the signed NarHash digest. Binary-cache URL tokens remain opaque, and compressed-to-raw fallback is not claimed. Production Rust/transport code is unchanged.

MUTATION RED: replacing the activation hard link with a no-op made exact command nix develop -c just e2e-nat-vm exit 1 at the new final realise after fresh NAR fetch UNREACHABLE -> p2p miss/fallback and exact HTTP 404. Earlier proofs remained green: AC#1 298.83s, B2 13.14s. Activation was restored.

GREEN: nix develop -c just e2e-nat-vm exit 0. AC#1 byte-identical real-NAT relay fetch 298.73s; B2 warm same-consumer relay-UP succeeds / relay-DOWN UNREACHABLE 13.56s; new AC#2 fallback 1.03s; total VM script 371.01s. Fresh post-activation journals contained NAR fetch UNREACHABLE, p2p miss, falling back to upstream, and exactly one HTTP 200 for /nar/<NarHash-digest>.nar. The observed nodeb daemon and HTTP service MainPIDs survived; realised hash equalled signed NarHash. Independent QA then found that the consumer PID was not pinned before relay loss, so the final harness now captures it immediately after convergence and requires that exact PID through relay-UP, relay-DOWN, and fallback.

REPOSITORY GATES: nix develop -c just build lint test exit 0 in 711.88s (workspace/all-target build 2m21s; evidence-feature build 5m29s; both clippy -D warnings passes; 1085/1088 listed workspace Rust tests passed with 3 intentional ignored tests; evidence fixture 2/2; deterministic Python properties 3/3; all scripted source/fixture/golden/mutation self-checks green). nix develop -c just e2e exit 0 in 283.04s: 9/9 scenarios, 107/107 checks, 256.6s harness time. git diff --check clean. No commit or staging performed.

2026-08-17 warm-consumer PID mutation: after AC#1 convergence and a successful relay-UP byte fetch, a temporary deliberate restart of nodeb nix-p2p-daemon changed MainPID 725 -> 1121. The fresh VM run went RED exactly at the new B2 warm-process assertion with `AssertionError: B2 relay-UP must use the converged nodeb daemon`; upstream stayed 404 through AC#1 and the relay byte oracle passed first. Wall 374.06s, expected exit 1. The restart mutation was removed before the final green re-gate.

2026-08-17 FINAL REVIEWED GREEN: qa-test-runner GO and mped-architect GO with no remaining findings. Final fresh six-VM run exit 0: 360.64s VM / 390.57s wall; nodeb MainPID 720 remained identical from post-AC#1 convergence through relay-UP, relay-DOWN, and already-raw fallback. Final build/lint/test exit 0 in 104.29s. Required exact just e2e exit 0: 9/9 scenarios, 107/107 checks, 249.8s harness / 274.22s wall. git diff checks clean; no mutation remains.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Completed the real-NAT residual with a reviewed six-VM proof. A kad-discovered provider behind one egress-only NAT is fetched byte-identically by a consumer behind another through the sole circuit-v2 relay. On the same converged daemon, relay-UP re-fetch succeeds; no DCUtR upgrade is observed; stopping only the relay yields fresh circuit UNREACHABLE while provider and consumer PIDs remain unchanged. Only after that attribution, the test atomically exposes an already-raw Compression:none fixed-point NAR at the unchanged upstream URL and proves production fallback plus signed NarHash.

Root fix: the HTTP fixture is systemd-owned and metadata-only until the bite; the already-raw URL is deliberately aligned with the rewrite::to_raw NarHash token. No production transport workaround or cache priming was added. This does not claim compressed-to-raw dead-provider fallback; TASK-247 now requires and owns that concurrency/fallback proof and any root fix.

Biting evidence: disabling NAR activation failed at the final fallback after AC#1/B2 stayed green; deliberately restarting nodeb changed PID 725->1121 and failed exactly at the new warm-consumer assertion. Final QA: build/lint/test green; fresh NAT VM green with PID 720 unchanged; exact full E2E 9/9 and 107/107. Independent qa-test-runner and mped-architect both returned GO.
<!-- SECTION:FINAL_SUMMARY:END -->
