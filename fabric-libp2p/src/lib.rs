//! `fabric-libp2p` - the libp2p BACKEND behind the `peer-fabric` seam, and the
//! project's MANDATORY decentralized content-discovery layer (owner: libp2p-PRIMARY,
//! 2026-08-12; `PRD.md` "Pluggable P2P substrate", `docs/peer-fabric-seam.md`).
//!
//! It implements [`peer_fabric::ProviderDirectory`] and
//! [`peer_fabric::AvailabilityAnnouncer`] over `rust-libp2p`'s `kad::Behaviour` - the
//! robust existing Kademlia. We do NOT hand-roll Kademlia and do NOT run
//! Kademlia-over-iroh. The FROZEN `peer_fabric` `ContentKey` / `ProviderRecord` /
//! `record_codec` are used verbatim as the record wire form (no frozen byte is
//! touched here).
//!
//! The only cross edge is `daemon -> fabric-libp2p`; this crate never depends on the
//! daemon, and `testproxy` depends on none of it (`scripts/check-independence.py`).
//!
//! # ADR (TASK-103): how the frozen record maps onto libp2p-kad - HYBRID
//!
//! libp2p-kad offers two primitives, and NEITHER alone fits our frozen record:
//!
//!   * **provider records** (`start_providing` / `get_providers`): a key -> {`PeerId`}
//!     set, multi-provider, with built-in TTL and republish. But a provider record
//!     carries NO value - just the `PeerId` - so it cannot carry `offers` / `sequence`
//!     / `expiry` / the signature, and a signed [`peer_fabric::ProviderRecord`] must be
//!     learnable WITHOUT the provider being online (AC#6). Insufficient alone.
//!   * **opaque value store** (`put_record` / `get_record`): a key -> ONE opaque
//!     `Vec<u8>`. It carries our signed bytes, but it is single-valued: the default
//!     `MemoryStore` holds one record per key per node, and every provider's
//!     `put_record` for a `ContentKey` converges on the SAME k-closest nodes, so
//!     provider B's put overwrites provider A's. Keying by `ContentKey` alone would
//!     structurally break multi-provider (AC#5/#6 concurrent providers).
//!
//! **Decision - HYBRID:** use the provider-record set as the multi-provider INDEX and
//! the value store for the per-provider signed record, under a per-provider COMPOSITE
//! key so the two never collide:
//!
//!   * [`AvailabilityAnnouncer::announce`](peer_fabric::AvailabilityAnnouncer::announce):
//!     `start_providing(RecordKey = ContentKey bytes)` (the exact-key, no-enumeration
//!     multi-provider index) **and** `put_record(RecordKey = derive_key(VALUE_KEY_CONTEXT,
//!     ContentKey || PeerId) -> encode_provider_record(record))`. One provider per
//!     composite key => no collision; stored on the k-closest => learnable offline.
//!   * [`ProviderDirectory::find_providers`](peer_fabric::ProviderDirectory::find_providers):
//!     `get_providers(ContentKey)` -> `{PeerId}`; for each, `get_record(composite)` ->
//!     [`peer_fabric::decode_provider_assertion`]`(value, expected_key = ContentKey, now)`
//!     with the FROZEN codec (self-verifying ed25519, SSOT key check, expiry). Collect
//!     `Vec<ProviderRecord>`.
//!
//! The signed record lives in the value store (learnable offline); `get_providers` is
//! added ONLY as the multi-provider index the value store cannot provide without
//! enumeration. The composite key uses `PeerId::to_bytes()` - exactly what
//! `get_providers` returns - so the resolver needs no ed25519<-PeerId extraction (it
//! DOES do the cheap FORWARD check: it derives the fetched record's `provider` ed25519
//! back to a `PeerId` and rejects a record that does not match the index entry, closing
//! provider-spoofing of the index). A node's libp2p identity is built from the SAME
//! ed25519 secret that signs its records, so `NodeId` (verifying key) == `provider` and
//! its `PeerId` corresponds. The `request-response` alternative for carrying the record
//! (online only) is TASK-151's shared path; the value store is primary here.
//!
//! ## Honest caveats (do not let this ADR overclaim)
//!
//!   * SEAM-DOC TENSION: `peer_fabric`'s frozen trait doc says "Kademlia VALUE store
//!     ... NOT `get_providers`, on every backend." This backend DOES use
//!     `get_providers` - for the index only, never to carry the record. We read that
//!     frozen sentence as *illustrative of where the SIGNED RECORD lives* (the value
//!     store, learnable offline), which we honor, not as forbidding a provider index;
//!     a pure value-store backend cannot be multi-provider (see above). Flagged for the
//!     owner as a real reconciliation, not papered over (TASK-147 doc-sync territory).
//!   * NON-ATOMIC, TWO KEYSPACES: the index (`ContentKey`) and the value
//!     (`derive_key(ctx, ContentKey||PeerId)`) are separate keys on separate k-closest
//!     sets, written by two operations with independent TTLs. They can transiently
//!     desync (index present, value not-yet/expired - or the reverse). The resolver
//!     classifies these honestly (below); full lifecycle reconciliation is TASK-152.
//!   * "OFFLINE-LEARNABLE" is bounded: a record is learnable for up to its TTL after
//!     the provider was last online; republish of both the value and the provider entry
//!     needs the publisher online. Not unconditional.
//!
//! `Lookup` arms (as the code classifies them):
//!   * `Found` = at least one provider-index entry resolved to a valid, in-date,
//!     provider-matched signed record.
//!   * `Miss` = a healthy completed lookup with NO positive record and NO consultation
//!     failure: either `get_providers` was empty, or the indexed providers' records
//!     were all withdrawn / expired / absent (`Ok(None)`). Authoritative absence.
//!   * `Unavailable(reason)` = the lookup could not be trusted: `InsufficientRouting`
//!     (empty k-buckets - see the honest limit that this is a TOTAL-routing bar, not a
//!     near-the-key bar; TASK-174. TASK-153 added the >=3-bootstrap join set + proved an
//!     admitted network survives losing any one bootstrap, and documents in `directory.rs`
//!     why BootstrapOutage vs Partition is not cleanly detectable at the read path),
//!     `DeadlineExceeded` (budget), or `Backend` when the
//!     index named providers but their value records could not be CONSULTED (a
//!     `get_record` failure), which must never collapse to `Miss`.
//!
//! # What is here vs deferred
//!
//! Here (TASK-103 cornerstone): the crate, the swarm worker, the kad-backed
//! [`Libp2pProviderDirectory`] + [`Libp2pAvailabilityAnnouncer`], a `Libp2pFabric`
//! exposing the directory, and the multi-node decentralized-discovery test. Deferred:
//! the libp2p `NarTransfer` / `NarServer` transport and node discovery / NAT traversal
//! (TASK-151, shares this crate's `Swarm`), and the hardening / evidence ACs
//! (withdrawal/expiry/replay/partition, sybil/eclipse bounds, packet guards, the
//! `decentralized-content-discovery-v1` artifact, TASK-132 cold journey).

mod announcer;
mod directory;
mod fabric;
mod keys;
mod locator;
mod nar;
mod server;
mod swarm;
mod transport;

pub use announcer::Libp2pAvailabilityAnnouncer;
pub use directory::Libp2pProviderDirectory;
pub use fabric::Libp2pFabric;
pub use keys::VALUE_KEY_CONTEXT;
pub use locator::Libp2pNodeLocator;
pub use nar::{
    Libp2pNarSupplier, MemoryNarSupplier, NarCodec, NarSupplyPlan, ServeCounters, ServeGate,
};
pub use server::Libp2pServer;
pub use swarm::{Node, NodeConfig, NodeError, SwarmHandle};
pub use transport::Libp2pTransport;

// Re-export libp2p's address/peer types the composition root and tests need to drive
// connectivity, so a consumer does not depend on libp2p directly for the seam-level
// wiring.
pub use libp2p::{Multiaddr, PeerId};

/// Current Unix time in seconds, for the record expiry gate and TTL reconciliation. A
/// clock BEFORE the epoch is a real system fault; it is logged and treated as `0`
/// (which, on the read path, makes every record appear fresh - a conscious fail-soft
/// so a transient clock glitch never drops a valid provider; the frozen decode's own
/// `Stale` check and the store TTL remain the authoritative freshness gates).
pub(crate) fn unix_now() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(dur) => dur.as_secs(),
        Err(err) => {
            tracing::error!(%err, "system clock is before the Unix epoch; using 0");
            0
        }
    }
}
