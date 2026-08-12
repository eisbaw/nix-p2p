//! Identity and DHT-key derivation: how a `peer_fabric` [`NodeId`] and the frozen
//! [`ContentKey`] map onto libp2p's `PeerId` / `kad::RecordKey`.
//!
//! A node's libp2p identity is built from the SAME 32-byte ed25519 secret that signs
//! its [`peer_fabric::ProviderRecord`]s, so `NodeId` (the ed25519 VERIFYING key) equals
//! the record `provider` and the node's `PeerId` corresponds to it. See the crate ADR.

use libp2p::PeerId;
use libp2p::identity::Keypair;
use libp2p::kad;
use peer_fabric::{ContentKey, NodeId};

/// The `derive_key` context domain-separating the per-provider VALUE-record key from
/// every other keyspace (the frozen `ContentKey` recipe, the content hash, the raw
/// `ContentKey` used as the provider INDEX key). Versioned so a future layout change
/// lands on a fresh keyspace.
pub const VALUE_KEY_CONTEXT: &str = "nix-p2p/libp2p-kad/provider-record-value/v1";

/// Build a libp2p ed25519 [`Keypair`] from a raw 32-byte ed25519 secret. This is the
/// SAME secret whose verifying key signs the node's provider records, so identity and
/// signing authority are one key (self-serve v1). The input is copied because libp2p's
/// constructor zeroizes the buffer it is handed.
pub fn keypair_from_seed(seed: &[u8; 32]) -> Keypair {
    let mut secret_bytes = *seed;
    let secret = libp2p::identity::ed25519::SecretKey::try_from_bytes(&mut secret_bytes)
        .expect("32 bytes is a valid ed25519 secret length");
    Keypair::from(libp2p::identity::ed25519::Keypair::from(secret))
}

/// The `peer_fabric` [`NodeId`] (the raw 32-byte ed25519 verifying key) of a libp2p
/// [`Keypair`]. Panics if the keypair is not ed25519 - this backend only ever
/// constructs ed25519 identities (see [`keypair_from_seed`]).
pub fn node_id_of(keypair: &Keypair) -> NodeId {
    let ed = keypair
        .public()
        .try_into_ed25519()
        .expect("fabric-libp2p identities are always ed25519");
    NodeId::from_bytes(ed.to_bytes())
}

/// The multi-provider INDEX key: the raw [`ContentKey`] bytes, used with
/// `start_providing` / `get_providers`. Exact-key only (a lookup names the key it
/// already holds); the provider set is the native multi-provider index.
pub fn provider_index_key(content_key: &ContentKey) -> kad::RecordKey {
    kad::RecordKey::new(content_key.as_bytes())
}

/// The per-provider VALUE-record key: `derive_key(VALUE_KEY_CONTEXT, ContentKey ||
/// PeerId)`. One provider per key => no collision in the single-valued value store, so
/// the frozen signed record is stored and retrieved intact and learnable offline. The
/// resolver recomputes it from the `PeerId` `get_providers` returned, so no
/// ed25519<-PeerId extraction is needed.
pub fn provider_value_key(content_key: &ContentKey, provider: &PeerId) -> kad::RecordKey {
    let mut hasher = blake3::Hasher::new_derive_key(VALUE_KEY_CONTEXT);
    hasher.update(content_key.as_bytes());
    hasher.update(&provider.to_bytes());
    kad::RecordKey::new(hasher.finalize().as_bytes())
}
