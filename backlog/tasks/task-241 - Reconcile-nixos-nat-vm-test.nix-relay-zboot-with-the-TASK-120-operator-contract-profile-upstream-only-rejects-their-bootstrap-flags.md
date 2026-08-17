---
id: TASK-241
title: >-
  Reconcile nixos/nat-vm-test.nix relay/zboot with the TASK-120
  operator-contract (--profile upstream-only rejects their bootstrap flags)
status: In Progress
assignee:
  - '@claude'
created_date: '2026-08-17 04:15'
updated_date: '2026-08-17 05:13'
labels:
  - ci
  - nixos
  - operator
  - regression
  - nat
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-120 (operator contract, commit 4f5d524) made --profile validation fail-closed: a node with --libp2p-bootstrap under --profile upstream-only is rejected (daemon-libp2p/src/main.rs:459). nixos/nat-vm-test.nix configures the relay + zboot nodes as libp2p.enable=true with listen+bootstrap but NO explicit role/profile, so nixos/nix-p2p.nix (profile->flag mapping ~L36-38) emits the DEFAULT --profile upstream-only alongside --libp2p-bootstrap -> nix-p2p-daemon.service exits at boot, and the NAT-VM test fails at subtest 2 (services come up FIRST) before ANY circuit/discovery subtest. The daemon behavior is CORRECT (fail-closed working); the TEST MODULE drifted. Surfaced by TASK-236 (libp2p 0.56 bump) re-running the NAT-VM; NOT a libp2p regression (would fail identically on 0.54). FIX: give the nat-vm relay/zboot nodes an explicit valid profile (a bootstrap/relay node is a provider or a router, not upstream-only) OR fix the nix-p2p.nix default profile for a libp2p.enable+bootstrap node. Then re-run nix build .#nat-vm-test on libp2p 0.56 to complete TASK-236 AC#4 NAT proof + re-validate TASK-218. The TASK-120 just-e2e gate did not catch this because the NAT-VM is not in just e2e - consider adding a nix flake check of the NixOS module to the operator-contract gate.
<!-- SECTION:DESCRIPTION:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
ROOT CAUSE confirmed: 4-profile model cannot express a content-less kad-SERVER+relay ROUTER. nat-vm relay/zboot have libp2p.enable+listen+bootstrap+externalAddress but no profile -> default upstream-only -> daemon fail-closes (check_runtime_preconditions refuses --libp2p-bootstrap under upstream-only). Option 1 INFEASIBLE: consume-only derives kad CLIENT (cannot be a bootstrap root); lan-share/public-share require content-to-serve AND reject external-address-without-allowlist. Pre-TASK-120 the relay worked as kad-server because DEFAULT_KAD_SERVER=true and source_config set relay unconditionally; TASK-120 tied kad_server=profile.serves(). Chose Option 2: add MINIMAL explicit router profile (kad-SERVER + relay, serves/announces NOTHING, never a default). Restores pre-120 relay wire behaviour behind an explicit contract-accepted mode. No weakening of upstream-only default or fail-closed validation.

Implemented Option 2: added SharingProfile::Router to daemon-core (serves/announces NOTHING, runs_dht_server()=true -> kad SERVER + relay; fail-closed RouterServes if combined with any give-side; ContractRequest.is_router; dependencies/describe/parse/as_str arms). daemon-libp2p: --libp2p-router flag, parse-time give-side rejection, source_config keys kad_server+relay on runs_dht_server(), dht_role Router=>Server, honest ROUTER startup log, router-requires-listen precondition, router bite test. Composite daemon: is_router:false. NixOS module: profile enum +router, router bool option, emits --libp2p-router, +2 assertions (router-carries-no-content, router-requires-listen).

BROADER REGRESSION than task framing: the nat-vm build now PASSES subtest 2 (relay+zboot start as ROUTER kad-SERVER) but revealed nodea AND nodeb ALSO drifted the SAME way - they set low-level give-side/bootstrap flags but NO explicit profile, so the module emitted the DEFAULT --profile upstream-only which the daemon fail-closes against the derived public-share (nodea) / consume-only (nodeb). TASK-120 broke ALL FOUR libp2p nodes; the test never got past relay/zboot before to expose nodea/nodeb. Fix (conservative, preserves TASK-120 always-emit+cross-check invariant, no module re-architecture): set explicit profiles matching each node derived mode - nodea=public-share, nodeb=consume-only, relay/zboot=router. Consequence: nodea gains --libp2p-announce-after-fetch (inert; it never fetches), nodeb gains --libp2p-leech (it is a pure consumer). Re-running nat-vm build.

GATE GREEN (commit c528a08, NOT pushed). nix build .#nat-vm-test PASSES all 6 subtests exit 0: topology; services-come-up (relay+zboot start as ROUTER kad-SERVER - the original regression fixed); provider reserves (nodea public-share); NEGATIVE CONTROL; DISCOVERY+AC#1 byte-identical NAR fetch THROUGH the relay (re-validates TASK-218 circuit-v2 on libp2p 0.56, completes TASK-236 NAT AC#4); B2 LOAD-BEARING (relay-up fetch OK / relay-down FAILS, no DCUtR upgrade, provider MainPID unchanged, sole reservation relay was the stopped relay). just e2e 8/8 (incl S-LEECH mask). cargo test 1020 passed; TASK-120 safety bites (fresh_install upstream-only, fail-closed invalid-combo, derive-maps-each-intent) + new router bites (router_is_a_kad_server_that_gives_nothing, router_with_a_give_side_fails_closed=RouterServes, router_is_kad_server_relay_serving_nothing with kad_server/relay mutation) all green - fail-safe default NOT regressed. fmt/clippy -D warnings/no-floats/golden byte-identical all clean. Left In Progress for review (not marking Done).

CODEX NO-GO (narrow, item 4 only). PASS: router serves-nothing, explicit-only/never-default, NO TASK-120 regression, frozen/no-float; nat-vm 6/6 (re-validates 218 on 0.56 + completes 236 NAT AC#4). FAIL: a PUBLIC router (kad-server+relay at a public external address) reports public_dht_participation=false (public_participation() true only for PublicShare) - report!=wire, same honesty class TASK-120 fixed. Round-2 fix: public_dht_participation for Router reflects actual reachability (public addr/non-isolated -> true; LAN -> false) + a bite. Convergent.
<!-- SECTION:NOTES:END -->
