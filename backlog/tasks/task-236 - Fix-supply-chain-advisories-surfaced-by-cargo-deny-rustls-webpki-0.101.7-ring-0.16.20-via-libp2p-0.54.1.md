---
id: TASK-236
title: >-
  Fix supply-chain advisories surfaced by cargo-deny (rustls-webpki 0.101.7 +
  ring 0.16.20 via libp2p 0.54.1)
status: Done
assignee:
  - '@claude'
created_date: '2026-08-16 11:17'
updated_date: '2026-08-17 04:15'
labels:
  - supply-chain
  - hardening
  - security
dependencies:
  - TASK-234
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
cargo-deny (added in TASK-234, run via just audit) reports 4 real RustSec vulnerabilities on the current tree. All are transitive, pinned by libp2p 0.54.1 through libp2p-tls 0.5.0 -> libp2p-quic 0.11.1 (rustls-webpki) and rcgen 0.11.3 (ring 0.16.20). Fixing them requires bumping libp2p (0.54.1 -> a release whose tls/quic stack pulls rustls-webpki >=0.103.13 and rcgen that drops ring 0.16). This is a dependency-graph change, out of scope for the TASK-234 tooling gate, hence this follow-up. Findings: RUSTSEC-2026-0099 (rustls-webpki, wildcard name-constraint accepted), RUSTSEC-2026-0104 (rustls-webpki, reachable panic in CRL parsing), RUSTSEC-2026-0098 (rustls-webpki, URI name-constraint incorrectly accepted), RUSTSEC-2025-0009 (ring 0.16.20, AES/QUIC header-protection may panic with overflow checks). Severity note: these are in the QUIC/TLS cert path; reachable only via misissued certs or attacker-influenced CRL/AES paths - real but not trivially remote-exploitable in the current peer-auth flow. Do NOT paper over by adding advisory ignores to deny.toml; fix the versions. If a temporary ignore is unavoidable, it must reference THIS task id and a dated re-check.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 rustls-webpki resolves to >=0.103.13 (or the alpha range the advisory names) in Cargo.lock
- [x] #2 ring 0.16.20 no longer appears in Cargo.lock (only >=0.17.x)
- [x] #3 just audit exits 0 (advisories ok, licenses ok, bans ok, sources ok) with no advisory ignores added to deny.toml
- [x] #4 full gate (just test + just e2e) still green after the libp2p bump
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
TASK-236 progress (implementer): bumped libp2p 0.54.1 -> 0.56.0 and libp2p-stream 0.2.0-alpha -> 0.4.0-alpha in fabric-libp2p/Cargo.toml; regenerated Cargo.lock. Version analysis: only libp2p-tls 0.6.2 clears BOTH advisories (webpki/rustls-webpki ^0.103 + rcgen ^0.13 dropping ring 0.16); it needs libp2p-swarm 0.47 / core 0.43.1, which only libp2p 0.56.0 provides (0.55.0 stays on libp2p-tls 0.6.1 with vulnerable rustls-webpki 0.101). Cargo.lock now: rustls-webpki 0.103.13 only (AC#1), ring 0.17.14 only, 0.16.20 gone (AC#2). just audit exits 0: advisories ok, bans ok, licenses ok, sources ok, NO deny.toml ignores added, NO new transitive advisory (AC#3). NO fabric-libp2p src change required - the kad/swarm/NetworkBehaviour/SwarmBuilder/identify/autonat/dcutr/relay/Multiaddr/libp2p-stream call sites are source-compatible across the two-major bump. Gate so far: cargo build+all-targets clean, clippy -D warnings clean, fmt clean, no-floats clean, golden byte-identical, discovery-no-shortcut self-test bites. just test JUST_TEST_RC=0 (all cargo suites incl nat_traversal/nat_dht_resolve circuit-v2 relay tests; one iroh fixed-port rebind test flaked once on shared-box port contention then passed on rerun - unrelated to libp2p). just e2e JUST_E2E_RC=0 (8/8 scenarios incl s6-p2p, s9-libp2p-grow, libp2p-leech). TASK-218 circuit construction re-validated in-tree. NAT-VM test running; commit pending its result.

TASK-236 FINAL (implementer; NOT marking Done - owner decides). Committed 5ad9dec (explicit pathspec: Cargo.lock + fabric-libp2p/Cargo.toml only; no AI credit; not pushed). libp2p 0.54.1 -> 0.56.0, libp2p-stream 0.2.0-alpha -> 0.4.0-alpha. Cargo.lock: rustls-webpki 0.103.13 only (AC#1); ring 0.17.14 only, 0.16.20 gone (AC#2). just audit = cargo deny check exits 0: advisories ok, bans ok, licenses ok, sources ok; NO deny.toml ignores; NO new transitive advisory (AC#3). AC#4 full gate GREEN: just test JUST_TEST_RC=0, just e2e JUST_E2E_RC=0 (8/8 scenarios: s1-byte-and-counts, narinfo-default-cache-offload, s2-fallback, tamper-narhash, chain-s1-and-counts, s6-p2p, s9-libp2p-grow, libp2p-leech). Also clean: cargo build --all-targets, clippy -D warnings, fmt, check-no-floats, check-golden-vectors (byte-identical, BLAKE3 matches committed golden), check-discovery-no-shortcut --self-test. ZERO fabric-libp2p src change needed. TASK-218 circuit-v2 construction NOT regressed by the bump - proven by in-tree fabric-libp2p tests on 0.56: nat_traversal (provider_reachable_only_via_relay_circuit_fetches_byte_identical, swarm_builds_and_listens_with_nat_behaviours_active, relay_server_opt_out_declines_reservations) + nat_dht_resolve (known_relays_compose_distinct_circuits_for_different_providers).

NAT-VM (nix build .#nat-vm-test) FAILED, but PRE-EXISTING and UNRELATED to this bump - NOT a TASK-218 circuit regression. It fails at subtest 2 (services come up FIRST), a precondition BEFORE any circuit/discovery subtest. Cause: nix-p2p-daemon.service on relay + zboot exits with "--profile upstream-only disagrees with the profile the flags imply (consume-only)". That check lives in daemon-libp2p/src/main.rs:459, introduced by commit 4f5d524 (TASK-120 operator-contract, contract.profile GATES runtime) - version-independent of libp2p, would fail identically on 0.54. Root cause: nixos/nat-vm-test.nix relay+zboot set libp2p.enable=true with listen+bootstrap but no role, so nix-p2p.nix emits the default --profile upstream-only alongside --libp2p-bootstrap/--libp2p-listen; the TASK-120 daemon derives consume-only from those flags and fail-closes. This is TASK-120 module-wiring drift (nat-vm module not reconciled with the new profile/flag agreement), consistent with TASK-120 Done-with-residual + TASK-240. OUT OF SCOPE for this isolated libp2p-bump cycle (fixing it means editing the NixOS module / operator-contract, not the libp2p pins). Recommend a separate task to reconcile nat-vm-test.nix relay/zboot profile with the TASK-120 contract, after which the full NAT-VM proof can re-run on 0.56. KVM was available (/dev/kvm present); the VMs booted and ran - this is a real config failure, not KVM-unavailable. Bounded de-flake note: one iroh fixed-port rebind test (shutdown_cancels_an_active_lookup_and_releases_its_fixed_iroh_port) flaked once on shared-box port contention then passed on rerun - unrelated to libp2p.

DONE (LIGHT gate). Commit 5ad9dec. libp2p 0.54.1->0.56.0 clears all 4 advisories with ZERO src changes (only libp2p-tls 0.6.2 via 0.56.0 works; 0.55 insufficient). just audit exit 0 (no new advisory, no ignore); rustls-webpki 0.103.13-only, ring 0.17.14-only; just test RC=0 + e2e 8/8; golden byte-identical; TASK-218 circuit suites pass on 0.56. NOTE: the NAT-VM test fails at a PRECONDITION due to a TASK-120 regression (nat-vm-test.nix relay/zboot default to --profile upstream-only which the fail-closed contract rejects vs their bootstrap flags) - NOT a libp2p regression; filed as a follow-up.
<!-- SECTION:NOTES:END -->
