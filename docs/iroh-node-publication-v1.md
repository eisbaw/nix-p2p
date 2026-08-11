# Iroh node publication v1

`iroh-node-publication-v1` is the signed, default-off NodeId-to-location
publication capability. It publishes where one already-known Iroh node can be
reached. It does not discover NodeIds, resolve records, enable relay transport,
perform LAN discovery, or publish Nix content inventory.

## Signed packet schema

The packet is an Iroh/pkarr `SignedPacket`: public key, Ed25519 signature,
big-endian pkarr timestamp/sequence, and one canonical DNS reply. The public key
is both the signer and the stable TASK-115 Iroh NodeId. The signature covers the
sequence and the complete DNS bytes.

All records are class `IN`, type `TXT`, have one uniform positive TTL, and are
under the signer's canonical z-base-32 name. No questions, authority records,
additional records, unknown TXT attributes, duplicate attributes, or trailing
bytes are accepted.

`_iroh.<signer>` contains the stock-Iroh address fields:

- `addr=<canonical SocketAddr>` for each direct address;
- `relay=<canonical HTTPS URL>` for each relay URL.

`_nix-p2p-iroh.<signer>` contains exactly one of each lifecycle field:

- `schema=iroh-node-publication-v1`
- `namespace=<run-unique lower-case token>`
- `signer=<canonical z-base-32 public key>`
- `node-id=<lower-case hexadecimal NodeId>`
- `recipient=<configured authority identity>`
- `ttl-seconds=<positive u32>`
- `sequence=<unsigned decimal u64>`
- `expires-unix-micros=<unsigned decimal u64>`
- `state=live|withdrawn`

A record expiry is exactly `sequence + ttl-seconds * 1_000_000`, using checked
u64 arithmetic. Both encoders and consumers reject any other value or overflow.
A publisher whose durable sequence is ahead of its wall clock therefore retains
the full configured lifetime while preserving monotonic sequence ordering.

A live packet has at least one location. A withdrawal has no location records.
Live packets contain at most 16 locations; publishers and consumers reject an
over-limit set and never truncate it. Locations are sorted and deduplicated
before signing. Port zero, unspecified, multicast, IPv4 broadcast,
non-canonical IPv4-mapped IPv6, and unscoped IPv6 link-local direct addresses
are rejected. Relay URLs require HTTPS and an explicit host and reject
credentials, query strings, fragments, and values that cannot be represented
as one canonical TXT attribute. A relay domain remains allowed, but an IP
literal relay host cannot be unspecified, multicast, or IPv4 broadcast,
including IPv4-mapped IPv6 spellings.

There is deliberately no field for `NarHash`, store path, closure membership,
availability, content digest, content key, or inventory. Adding any such field
is a new schema and a separately reviewed content-discovery capability.

## Publisher state machine

Publication is disabled unless `--iroh-publish-node` and every required
companion option are present. Companion options without that switch fail
configuration. Offline-test endpoints reject publication. Enabling publication
does not enable address lookup, relay, or LAN discovery.

The publisher owns one state directory and one stable Iroh identity. A
transition is ordered as follows:

1. allocate and atomically persist the latest desired-location revision;
2. construct one signed packet at `max(wall_clock, durable_high_water + 1)`;
3. atomically persist its exact bytes as `pending` and fsync the directory;
4. PUT that exact packet to the pinned authority recipient;
5. GET and verify byte-identical visibility;
6. atomically move `pending` to `committed` and fsync the directory.

Concurrent address churn is serialized only after each valid intent has been
recorded, so the final transition converges on the greatest desired revision.
A failed update is retried once, inside the same five-second absolute deadline,
from that latest durable intent. Invalid or unauthorized locations fail before
revision allocation and cannot be disguised as a successful refresh of an old
record. An empty latest intent is a withdrawal and is never replaced by a
previous non-empty location during retry or refresh.

An unexpired pending packet is retried byte-for-byte after restart only when it
has enough remaining lifetime for one submission plus the next retry reserve.
An expired or near-expiry pending packet is discarded while its sequence
high-water remains, then replaced with a freshly signed higher sequence. Each
packet is bound to the desired revision that created it; a pending packet older
than a newer durable desired revision is retired locally and never replayed. Reusing
an unexpired committed packet performs an idempotent exact PUT followed by an
exact GET; this both verifies visibility and repairs an empty/reinitialized
authority without waiting for the refresh margin. A conflicting equal sequence
is not overwritten. Shutdown first advances the durable desired revision to an
empty withdrawal intent, then publishes its signed packet before the Iroh
endpoint is closed. A later process start records its configured non-empty
initial locations as a newer live intent before recovery, so a clean withdrawal
does not make the state unrestartable. Startup failure after a possible live PUT
uses the same durable withdrawal ordering before returning the error. A
committed or recovered packet is
reusable only when its signed TTL equals the current configuration; changing
TTL always advances to a new packet. An ambiguous unexpired pending packet may
first be recovered exactly, but a TTL mismatch is followed immediately by a
higher-sequence packet using the current TTL.

Publisher state and lock files are single-link, current-UID regular files with
mode `0600` inside a current-UID mode-`0700` directory. Writes use a checksummed
replacement file, rename, and directory fsync under an exclusive flock.
Corruption, concurrent ownership, ambiguous post-rename failure, or sequence
overflow fails closed. Ordered durability assumes a responsive local
filesystem; a blocked local fsync can exceed the network timing envelope and is
an operational failure, not silently detached work.

A separately checksummed publisher anchor witnesses the identity, desired
revision and location hash, sequence high-water, and latest packet hash
independently of the main state file. It rejects a missing main file and
one-file/partial rollback. As with the authority anchor, restoring the complete
mutable directory (state and anchor together) to a mutually consistent old
snapshot is outside this local witness's threat model and requires an external
monotonic root.

## Local routed authority

The production-shaped authority is a separate `iroh-node-authority` process.
It exposes only standard pkarr relay paths:

- `PUT /pkarr/<signer>` accepts an Iroh relay payload;
- `GET /pkarr/<signer>` returns the exact current Iroh relay payload until its
  expiry, including a signed withdrawal packet.

It requires an exact HTTP `Host`, a non-empty explicit signer ACL, a run-unique
namespace, a signed recipient identity, and a named operator. It rejects stale
or conflicting equal sequences, mismatched signer/signature/schema/namespace/
recipient, expired packets, and packets whose expiry exceeds TTL plus the
one-second clock allowance. The durable high-water and one-way expiry latch
remain after withdrawal or expiry, so old packets cannot resurrect a node.
A v1-aware lookup must interpret `state=withdrawn` as absent even though the
authority returns the tombstone for visibility acknowledgement and replay
defence. Stock Iroh clients prove only pkarr framing and `_iroh` address syntax
interoperability; they do not enforce the `_nix-p2p-iroh` namespace, sequence,
expiry, or withdrawal lifecycle. TASK-138 owns that strict lookup behavior.

Because this process serves plain HTTP, its listen address is restricted to
loopback, RFC1918 IPv4, IPv4 link-local, IPv6 unique-local, or scoped IPv6
link-local unicast. Wildcard, multicast, broadcast, unscoped link-local, and
public Internet binds fail configuration before socket bind.

Authority state uses the same descriptor-relative permission, lock, checksum,
rename, and fsync discipline as publisher state. A separately checksummed anchor
detects a missing file and one-file/partial rollback. It does **not** detect an
attacker or backup system restoring the complete mutable state directory,
including state and anchor, to one mutually consistent older snapshot. Claims
against complete-directory rollback require an external monotonic root and are
outside v1.

The HTTP transport is intentionally pinned plain HTTP to one locally controlled
socket, with no DNS, proxy, redirect, credentials, or ambient environment
lookup. Public/external pkarr authorization is represented in configuration but
fails closed in v1 because this transport is not HTTPS-compatible. External n0
or public DNS/pkarr operation therefore remains unsupported until it has a named
owner, explicit authorization, and an authenticated transport implementation.

## Timing and evidence boundary

The provider process captures the 10-second startup-to-visible deadline before
argument parsing and Iroh startup. Each refresh, address-churn update, and
withdrawal has a 5-second transition deadline; evidence may allow at most one
additional second for scheduler observation. A normal transition and committed
recovery each issue at most two authority requests: one PUT and one visibility
GET. Startup error cleanup can add one bounded PUT+GET withdrawal attempt.

The retry reserve is the smaller of five seconds and four configured request
deadlines (PUT+GET for each of two attempts). A separate one-second completion
margin covers scheduler wake-up, locking, persistence, signing, and the strict
expiry boundary. Configuration requires
`ttl > max(2 * reserve + margin, refresh_interval + reserve + margin)`. With the
daemon's two-second request deadline and a four-second refresh interval, the
minimum whole-second TTL is therefore 12 seconds. This is a deliberate fail-fast
contract: a `ttl=6s, refresh=4s` configuration cannot prove continuous visibility
and is rejected. Refresh sleep is capped by
`signed_expiry - retry_reserve - completion_margin`, rather than being measured
only from transition completion. Slow startup or visibility verification can
therefore cause an immediate or early renewal instead of moving refresh to the
signed expiry boundary. Committed and pending reuse also require enough
remaining lifetime for submission, the following reserve, and the completion
margin.

Startup publication intersects the configured allowlist with addresses actually
observed from the live Iroh endpoint and waits within the startup deadline for a
non-empty intersection. A configured-but-unobserved address is not published,
and a withdrawal is never treated as readiness. Identical endpoint watch
observations are no-ops. A persistent refresh failure, unexpected address-watch
termination, or endpoint closure while the watcher is live latches fatal health;
the daemon observes that health channel, leaves its serve loop, and reports
failure instead of continuing with stale advertised reachability.

The TASK-137 evidence run uses an empty, run-unique authority state directory
and places the publisher and authority in distinct routed network namespaces.
It is labelled `production-shaped-local`, not public Internet evidence.

The final `iroh-node-publication-v1` artifact must hash:

- this versioned schema document;
- the raw routed evidence data;
- the reviewed implementation tree.

`implementation_tree` means the Git tree/commit containing the reviewed code
and schema before the evidence/tracker-only follow-up. This definition avoids a
self-referential artifact hash. The artifact separately records its own schema
version, verdict, failed constraints, timing observations, topology, and the
evidence hash. Ordinary implementation or test defects are failures, not a
`no_go`; `no_go` is reserved for an evidenced capability constraint that cannot
be met by this implementation.
