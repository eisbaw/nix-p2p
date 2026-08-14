---
id: TASK-208
title: >-
  relay circuit-v2 server resource bounds + opt-out (every node relays
  unconditionally with default caps)
status: In Progress
assignee: []
created_date: '2026-08-14 17:23'
updated_date: '2026-08-14 19:42'
labels:
  - libp2p
  - connectivity
  - resource-bounds
  - hardening
dependencies:
  - TASK-168
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Surfaced by TASK-168 AC#1: the swarm runs libp2p relay::Behaviour (circuit-v2 SERVER) UNCONDITIONALLY on every node with relay::Config::default() (fabric-libp2p/src/swarm.rs:1033), so any public node relays arbitrary traffic for NAT'd peers with no dedicated infra. This is the correct permissionless-swarm pattern, but 'unconditional + default caps on every node' is a real resource/abuse surface (bandwidth, reservation/circuit slots, connection limits). Add: (1) a NodeConfig opt-out (a node can decline to be a relay server); (2) explicit reservation/circuit/bandwidth/duration limits (do not rely on library defaults for a shipped node); (3) a bound test. Complements TASK-154 (kad resource bounds). Not a correctness bug - a deployment-safety hardening. Medium.
<!-- SECTION:DESCRIPTION:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Done (implementation). Opt-out: NodeConfig.relay_server_enabled (default true = DEFAULT_RELAY_SERVER_ENABLED, permissionless-swarm intent) + builder with_relay_server(bool). Behaviour.relay changed relay::Behaviour -> Toggle<relay::Behaviour>; opt-out builds Toggle::from(None) so the circuit-v2 SERVER behaviour is ABSENT (no reservation/circuit accepted), while relay_client/autonat/dcutr stay installed (node still USES relays). Derive BehaviourEvent::Relay(ev) still matches (Toggle::ToSwarm == relay::Event); event arm unchanged.

Explicit bounds (relay_server_config(), TASK-208): starts from relay::Config::default() to KEEP its per-peer/per-IP RATE limiters, then overrides the hard caps for a shipped HOME node (not public relay infra): max_reservations 32 (lib 128), max_reservations_per_peer 2 (lib 4), reservation_duration 10min (lib 1h), max_circuits 8 (lib 16), max_circuits_per_peer 2 (lib 4), max_circuit_duration 2min (lib default kept), max_circuit_bytes 128KiB=1<<17 (lib default kept). Rationale: relay is DIAL-ASSISTANCE; dcutr upgrades to DIRECT for bulk NAR, so the relay carries hole-punch handshake + small control only. Worst-case concurrent forwarded volume ~ MAX_CIRCUITS*MAX_CIRCUIT_BYTES ~= 1MiB. All integer / integer Duration (no-float).

Pinned relay::Config API (libp2p-relay 0.18.0 via libp2p 0.54.1): Config is a struct with PUBLIC fields max_reservations/max_reservations_per_peer/reservation_duration/max_circuits/max_circuits_per_peer/max_circuit_duration/max_circuit_bytes + two pub Vec<Box<dyn RateLimiter>> (reservation_rate_limiters, circuit_src_rate_limiters). No setter methods for the numeric caps -> set via struct FRU: relay::Config { max_..: .., ..relay::Config::default() }. (There ARE builder methods reservation_rate_per_peer/_ip and circuit_src_per_peer/_ip for ADDING rate limiters, unused here.)

Tests: (1) unit swarm::tests::relay_server_config_carries_explicit_bounds_not_library_defaults - asserts every cap threads from its RELAY_* const AND is strictly tighter than relay::Config::default(); bites a revert to default(). (2) unit relay_server_opt_out_threads_through_node_config - default ON, with_relay_server(false) => off. (3) integration tests/nat_traversal.rs::relay_server_opt_out_declines_reservations - opted-out relay grants NO reservation (no /p2p-circuit listen addr in a bounded ~6s window); minimal pair to provider_reachable_only_via_relay_circuit_fetches_byte_identical (server ON -> reservation DOES appear + byte-identical fetch), which stays GREEN.

Gate (bounded, nix develop -c): cargo build 0; cargo test -p fabric-libp2p all suites pass (nat_traversal 3/3 incl new opt-out; decentralized_discovery 1/1; node_locator_discovery 1/1; lib +2 new); cargo fmt --all --check 0; cargo clippy --locked -p fabric-libp2p --all-targets -D warnings 0; just independence 0 (shaping guard: 82 src files clean). Shaping tokens avoided in shipped-src comments.

Limits/honesty: opt-out proof is at the reservation boundary (behaviour absent) not a full multi-circuit reservation-saturation integration test (a real max_reservations/max_circuits saturation test is DEFERRED - would need N>caps concurrent NAT'd clients in-process; the unit test asserts the values reach relay::Config, which is the config-threading floor the task requires). max_circuit_duration/max_circuit_bytes kept at library defaults (already conservative for a home relay); only the slot/lifetime caps were tightened below default.
<!-- SECTION:NOTES:END -->
