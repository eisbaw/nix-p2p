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
//! This honors the frozen seam rationale ("the signed record lives in the value store,
//! learnable offline") and adds `get_providers` ONLY as the multi-provider index the
//! value store cannot provide without enumeration. The composite key uses
//! `PeerId::to_bytes()` - exactly what `get_providers` returns - so the resolver needs
//! no ed25519<-PeerId extraction. A node's libp2p identity is built from the SAME
//! ed25519 secret that signs its records, so `NodeId` (verifying key) == `provider` and
//! its `PeerId` corresponds. The `request-response` alternative for carrying the record
//! (online only) is TASK-151's shared path; the value store is primary here for offline
//! learnability.
//!
//! `Lookup` arms: `Found` = a healthy non-empty hit; `Miss` = a healthy
//! `get_providers` empty result over a populated routing table; `Unavailable(reason)`
//! = insufficient-routing (empty k-buckets), deadline, or bootstrap/partition.
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
mod swarm;

pub use announcer::Libp2pAvailabilityAnnouncer;
pub use directory::Libp2pProviderDirectory;
pub use fabric::Libp2pFabric;
pub use keys::VALUE_KEY_CONTEXT;
pub use swarm::{Node, NodeConfig, NodeError, SwarmHandle};

// Re-export libp2p's address/peer types the composition root and tests need to drive
// connectivity, so a consumer does not depend on libp2p directly for the seam-level
// wiring.
pub use libp2p::{Multiaddr, PeerId};
