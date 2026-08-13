# Iroh relay capability v1

`iroh-relay-capability-v1` is the routed evidence that the deterministic
TASK-139 relay transport (`daemon/src/iroh_relay.rs`) carries a REAL peer
connection through a locally operated relay when the direct peer-to-peer path is
blocked, and that a direct path is never falsely credited to the relay. It
completes TASK-139's deferred AC#2/#5/#6. It is NOT a public-Internet or
NAT-traversal proof: the relay is a locally operated, self-signed relay reached
over a routed private network, so the evidence is labelled
`production-shaped-local`. No n0/public relay is ever contacted.

## Capability and boundary

The transport is default-off and owns none of the policy beyond turning exactly
one explicitly configured, locally operated relay URL into a daemon-owned
`RelayMode::Custom(RelayMap)`. Enabling relay performs no DNS/pkarr publication,
no NodeId lookup, no content lookup, and no LAN discovery. External/public (n0)
relay contact requires a named owner and an explicit authorization reference and
is refused by this transport even then; only a locally operated routed relay is
driven.

Each relayed connect attempt gets one absolute 10,000 ms deadline
(`RELAY_CONNECT_DEADLINE`) with at most 1,000 ms scheduler grace
(`RELAY_SCHEDULER_GRACE`). The peer measures the REAL connect duration
(`connect_ms`) around its own bounded connect and emits it UNCLAMPED; the
finalizer gates `connect_ms <= 11000 ms` and, unlike the old container-wall-clock
`elapsed_ms` (which was clamped to the schema max so an overrun was silently
censored), it now REJECTS any value past the bound rather than hiding it.
Honestly scoped: `connect_ms` is bounded by the peer's OWN 10000 ms connect
timeout, so a healthy run tops out near 10000 — the finalizer's 11000 ms gate is
a redundant re-assertion with grace slack, not an independent latency bound; and
`connect_ms` is a peer self-report whose only anchor is the git-blob-pinned peer
binary (it is not cross-checkable against the pcap). Its real signal is the
sub-deadline arms (a relayed connect completing in ~3 s, a fast direct control).
The container wall-clock `elapsed_ms` (which also covers connection close and the
post-connect exchange) is retained as informational-only and is never gated. The
sole config-time arm (`wrong-url`) is rejected before any network I/O and carries
no `connect_ms`. Path attribution uses the pure
`daemon::classify_connection_path` on the accepting side and iroh's own per-path
`is_relay()` on the selected path on the connecting side; only a `relayed` path
is credited to the relay.

## Routed topology and attribution

Two internal, DNS-disabled podman networks are bridged by a tiny L3 router. A
locally operated `iroh-relay-evidence-server` binds a self-signed relay on the
acceptor network at a fixed IP that both peers route to through the router, so
both rendezvous on the SAME relay URL. The connector peer is given ONLY a `/32`
route to the relay IP and NO route to the acceptor peer, so the direct path is
blocked at L3. A `tcpdump` capture inside the connector network namespace
records every TCP/UDP packet:

- **relay-success**: the connection establishes over the `relayed` path; the
  capture shows relay packets and ZERO direct-peer packets. Because the direct
  path is L3-blocked, "the relay carried it" is unfalsifiable here.
- **direct-positive control**: the connector additionally routes to the acceptor
  peer; the connection goes `direct` and is NOT credited to the relay.

## Typed failure matrix

Each adverse arm is a DISTINCT typed outcome within the deadline, driven by the
`iroh-relay-evidence-peer` connect role: `relay-outage`, `wrong-url`
(config-time `wrong_relay_url`), `wrong-certificate`, `wrong-identity`,
`half-open-stream`, and `forced-direct-failure`. Config-time reasons come
straight from `daemon::RelayTransportConfig`. Some network-time arms (relay
outage, wrong identity) may surface as a bounded `deadline` rather than a finer
reason: the peer reports only what iroh's connect observes, and causal
attribution is the harness topology and packet capture, not the peer
self-report.

## Finalizer and verdict

`scripts/finalize_iroh_relay_capability.py` emits
`iroh-relay-capability-artifact-v1`, validated against
`docs/iroh-relay-capability-artifact-v1.schema.json`, only from a clean reviewed
implementation commit and a canonical raw evidence directory. It binds the
implementation commit/tree and committed blob hashes, the raw evidence manifest
hash, the relay identity, per-arm typed outcomes and capture facts, and the
limitations above. The verdict is bound to the CAPTURED bytes, not to the
harness's self-reported numbers: the finalizer REQUIRES the exact per-arm pcap
set plus each arm's `capture.log`, RE-PARSES every pcap to re-derive the relay
and direct-peer packet counts (rejecting any disagreement with `run.json`), and
re-checks tcpdump's own capture-completeness counters (zero kernel drops,
captured == received-by-filter, and pcap records == captured) so a zero-direct
assertion cannot hide a dropped or truncated capture. The attribution
COORDINATES are not trusted as free text either: `relay_ip` and `acceptor_ip` are
re-derived from the (strict, canonical) acceptor subnet at their deterministic
`make_topology` offsets and the `relay_url` host must equal `relay_ip`, so a
forged `acceptor_ip` cannot point the direct counter at a decoy while a real leak
reaches the true peer. Attribution is IPv4-only, so every captured record must
decode to an IPv4 TCP/UDP flow (records == IPv4-flow count) — a non-IPv4 packet
would otherwise be unattributed. The raw pcaps + capture logs are retained
alongside the artifact so the counts stay independently re-derivable. Missing or invalid evidence is a fatal validation error,
never `no_go`; `no_go` is reserved for an evidenced capability constraint the
reviewed implementation cannot provide, and TASK-89 must propagate that verdict.

## Limitations

- Relay attribution holds for this L3-blocked routed topology; iroh may upgrade a
  relayed path to a direct one after hole-punching, so the block (not the
  classifier reading alone) is what makes attribution unfalsifiable.
- Production-shaped-local only: a locally operated self-signed relay, not a
  public-Internet / NAT-traversal proof.
- Some adverse arms may report a bounded `deadline` rather than a finer typed
  reason; the topology and capture, not the peer, establish the cause.
- Packet attribution is IPv4-only; the topology uses IPv4-only internal podman
  networks and the finalizer requires every captured record to decode to an IPv4
  TCP/UDP flow, so a non-IPv4 path cannot silently escape the zero-direct guard.
- `connect_ms` is a peer self-report bounded by the peer's own 10000 ms connect
  timeout; the finalizer's 11000 ms gate re-asserts the deadline (no longer
  clamps it) but is not an independent latency measurement.
