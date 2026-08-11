# Iroh NodeId lookup v1

`iroh-node-lookup-v1` is the explicit, default-off lookup half of global Iroh
peer discovery. It accepts exactly one asker-supplied, typed NodeId and returns
at most 16 signed direct/relay address candidates. There is no operation to list
peers, browse a namespace, discover content, publish the local endpoint, join a
relay, or activate LAN discovery.

## Capability and request boundary

The daemon enables this capability only with `--iroh-enable-node-lookup` and a
complete set of lookup companion options. Companion options without the switch
fail configuration. Enabling the capability registers one resolve-only Iroh
`AddressLookup` adapter but performs no request. `offline-test` rejects the
capability before endpoint bind. The endpoint builder starts from
`presets::Minimal`, clears every inherited address lookup, and installs only the
selected adapter.

The public query API accepts a `NodeId`, not a string, wildcard, namespace,
prefix, page token, or collection. Text is parsed once at the CLI boundary; a
non-canonical or non-Ed25519 identity is typed `invalid_node_id` before network
I/O. The Iroh adapter overrides only `resolve`. It deliberately inherits the
no-op `publish` implementation.

Each call gets one absolute 10,000 ms deadline at public API entry. Runtime task
admission, TCP connect, request write, response read, signature/record decode,
and replay/freshness validation all consume that same budget. Dropping the
asker drops the supervisor result receiver, cancels the owned operation, and
closes the pinned TCP request. Evidence allows no more than 1,000 ms additional
observer/scheduler grace.

## Pinned authority and signed validation

The resolver sends one canonical zero-body
`GET /pkarr/<canonical-z32-signer>` to one configured numeric socket and exact
Host label. It has no DNS resolver, proxy, redirect following, credential jar,
or ambient HTTP client configuration. A 200 body is the pkarr relay payload,
not trusted record bytes: `SignedPacket::from_relay_payload` verifies it against
the NodeId requested by the asker before `decode_node_record` is called.

The decoder is the same Task137 `iroh-node-publication-v1` decoder used by the
publisher/authority tests. Consequently lookup inherits—and the shared mutation
suite proves—exact signed schema/version/answer ordering, maximum 16 locations,
no duplicates, canonical decimal fields, exact expiry arithmetic, and rejection
of malformed, wildcard, unspecified, multicast, IPv4 broadcast, port-zero,
IPv4-mapped, and unscoped IPv6 link-local direct addresses. Global IPv6 and
scoped link-local IPv6 are valid. Relay-only is a valid syntactic result; Task139
owns activating relay transport and attempting that route.

After strict decode, lookup additionally requires exact requested NodeId,
configured namespace, and configured signed-recipient equality. It rejects a
sequence more than one second in the future. A live result returns:

- lookup schema and signed record schema;
- source `pinned-pkarr-http` and provenance `network_validated`;
- NodeId, namespace, signed recipient, TTL, sequence, and expiry;
- the bounded canonical candidate list;
- BLAKE3 of the exact verified signed packet.

The result fields are read-only. The adapter converts them into a real Iroh
`Item` with provenance `nix-p2p-pkarr-node-lookup-v1`; it does not transfer the
lifecycle policy to an ambient Iroh DNS/pkarr client.

In the pinned Iroh 1.0.3 API, `AddressLookup::Item` carries the signed sequence
through `last_updated`, but has no field for the Task138 TTL or absolute expiry.
Iroh may also retain a successfully learned remote path after the lookup stream
has ended. Task138 therefore proves freshness only up to the validated address
handoff; it does **not** prove that a later connection attempt cannot reuse an
expired learned path. Before Task89 can claim end-to-end stale-address
enforcement, its connection composition must force re-resolution at the policy
boundary and invalidate previously learned direct and relay paths when the
record expires, is withdrawn, or advances.

## Replay, cache, and freshness

One runtime owns a bounded table of 1,024 NodeIds. A new identity fails
`capacity` before network I/O when the table is full. For each identity the
table retains sequence, exact packet hash, monotonic observation time, original
remaining validity, and the last accepted result:

- a lower sequence is `stale_sequence`;
- the same sequence and hash is idempotent;
- the same sequence with different signed bytes is `conflicting_replay`;
- a higher expired or withdrawn record advances high-water before returning its
  typed unavailable result, so an older live packet cannot resurrect it.

Concurrent calls await the async replay-state guard within their existing
absolute deadline; ordinary guard contention is never reported as `capacity`.
Expiry while waiting is typed `deadline`. A preflight wait that reaches that
deadline sends no authority GET. The guard covers only the serialized wall-clock
observation and bounded high-water check/update.

Every invocation still performs and validates a new GET. Cached data is never
returned after 404, refusal, timeout, malformed response, or any other authority
error. Even an identical packet is returned only after its exact bytes were
received and verified on that invocation, hence provenance remains
`network_validated` rather than `fresh_cache`.

Freshness is fail-closed against both clocks. Wall time must not move backward
within the runtime. Expiry is checked against wall time and against monotonic
elapsed time from the first observation, so a frozen or adjusted wall clock
cannot extend a packet's original remaining lifetime.

The 1,024 entries are a deliberately non-reclaiming runtime-lifetime high-water
table. Expired and withdrawn identities keep their slots because reclaiming one
would permit an older live record to resurrect inside the same process. The
operational consequence is also explicit: after 1,024 distinct NodeIds, a
long-lived process rejects every previously unseen identity until restart. That
is a conservative v1 safety boundary, not yet a real-world admission/eviction
policy; later measurement must determine whether durable high-water state or an
externally witnessed eviction policy is required.

Replay state is intentionally process-lifetime in v1. Restarting a resolver
loses its local high-water table; the separately durable Task137 authority is
the cross-process replay barrier for the locally operated deployment. Claims
against a malicious authority that rolls back its complete durable directory
require an external monotonic witness and are not made by this version.

## Typed UNAVAILABLE taxonomy

Lookup never returns content `MISS`. Its typed reasons cover disabled, invalid
NodeId, empty authority namespace (404), untrusted configuration, unsupported
external authority, authority status/refusal/connect/write/read/protocol,
deadline, bad signature, malformed/untrusted signed record, namespace,
recipient or NodeId mismatch, stale sequence, conflicting equal-sequence replay,
expired, withdrawn, no dialable candidate, capacity, clock rollback, and closed
runtime. A Task137 live-empty packet is still rejected by the record decoder,
whose typed `NoDialableCandidate` kind maps without error-string matching.

## Authority policy and evidence

Plain HTTP is permitted only to a private/local numeric recipient with a named
owner and is labelled `production-shaped-local`. Public n0, public DNS/pkarr,
accounts, credentials, cost, or infrastructure require a named owner and an
explicit authorization reference, but remain fail-closed until an authenticated
external transport exists. This version does not claim Internet production
operation.

Routed evidence places resolver and authority on two separate internal Podman
networks created with `--disable-dns`; an explicit L3 router joins both. Capture
inside the resolver network namespace records all IPv4 and IPv6 traffic. The
finalizer admits only resolver↔authority TCP on port 18080 and rejects DNS or
any other destination. The positive, empty-namespace, and signed-withdrawal
arms use the real Task137 authority; the live and withdrawal outcomes are bound
to the exact preserved signed packet hash and sequence. The publisher is absent
during lookup capture. A feature-gated fixture is limited to responses that the
real fail-closed authority correctly refuses to store: bad signature, stale
lower sequence, conflicting equal sequence, expired, validly signed live-empty,
and a hanging response whose client-side cancellation is observed. A separate
inert routed recipient proves typed connection refusal.

Every network arm sends only the canonical zero-body GET for its one signer.
The finalizer independently parses classic pcap bytes and rejects surplus TCP
connection attempts as well as publication PUT, content paths, relay
connections, LAN discovery, DNS, or unrelated egress. Default-off,
offline-disabled, and offline-enabled controls each require zero captured IP
packets. Every attempt must complete within the 10,000 ms deadline plus at most
1,000 ms observer grace; the hanging arm must also consume at least 9,000 ms.

The finalizer in `scripts/finalize_iroh_node_lookup.py` emits
`iroh-node-lookup-artifact-v1`, validated against
`docs/iroh-node-lookup-artifact-v1.schema.json`, only from a clean reviewed
implementation commit and a canonical raw evidence directory. It records the
implementation commit/tree, committed specification/schema/blob hashes, raw
evidence manifest hash, image revision, topology, per-scenario typed outcome,
timing, exact packet bindings, and the Iroh TTL/path-cache and runtime replay
limitations above. Ordinary implementation/test defects are failure, never
`no_go`. `no_go` is reserved for an evidenced capability constraint that the
reviewed implementation cannot provide, and Task89 must propagate that verdict.
