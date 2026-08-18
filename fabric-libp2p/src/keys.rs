//! Identity and DHT-key derivation: how a `peer_fabric` [`NodeId`] and the frozen
//! [`ContentKey`] map onto libp2p's `PeerId` / `kad::RecordKey`.
//!
//! A node's libp2p identity is built from the SAME 32-byte ed25519 secret that signs
//! its [`peer_fabric::ProviderRecord`]s, so `NodeId` (the ed25519 VERIFYING key) equals
//! the record `provider` and the node's `PeerId` corresponds to it. See the crate ADR.

use std::collections::BTreeSet;
use std::time::Duration;

use libp2p::identity::Keypair;
use libp2p::kad;
use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, PeerId};
use peer_fabric::{ContentKey, MAX_LIBP2P_RELAY_HINTS, NodeId, RelayHints, RelayHintsError};

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

/// The libp2p `PeerId` a `peer_fabric` [`NodeId`] (an ed25519 verifying key) MUST
/// correspond to. `None` if the bytes are not a valid ed25519 point. Used to BIND a
/// signed record's `provider` to the `PeerId` it was indexed under: a resolver rejects
/// a record whose `provider` does not derive to the queried provider (a peer re-storing
/// a third party's record under its own composite key). This is the FORWARD direction
/// (verifying key -> PeerId), always computable - the reverse (PeerId -> key) is the
/// extraction the composite key was designed to avoid.
pub fn peer_id_of_provider(provider: &NodeId) -> Option<PeerId> {
    let public = libp2p::identity::ed25519::PublicKey::try_from_bytes(provider.as_bytes()).ok()?;
    Some(PeerId::from_public_key(&libp2p::identity::PublicKey::from(
        public,
    )))
}

/// Recover the strict ed25519 [`NodeId`] embedded in `peer`.
///
/// This inverse exists for relay hints only: the signed record carries relay identities as
/// raw ed25519 verifying keys, while a live `/p2p-circuit` listener names its relay as a
/// libp2p [`PeerId`]. Ed25519 public keys are short enough that libp2p represents their PeerIds
/// as an identity multihash containing the protobuf-encoded public key, so the conversion is
/// lossless for every identity this backend creates.
///
/// Fail closed for hashed PeerIds, malformed protobuf, non-ed25519 keys, and non-canonical
/// identity digests. The final forward round-trip is deliberate: a permissive protobuf decoder
/// must not let two distinct PeerId encodings name the same signed [`NodeId`].
pub fn node_id_of_peer_id(peer: &PeerId) -> Option<NodeId> {
    const IDENTITY_MULTIHASH_CODE: u64 = 0;
    let multihash = peer.as_ref();
    if multihash.code() != IDENTITY_MULTIHASH_CODE {
        return None;
    }
    let public = libp2p::identity::PublicKey::try_decode_protobuf(multihash.digest()).ok()?;
    let ed25519 = public.try_into_ed25519().ok()?;
    let node = NodeId::from_bytes(ed25519.to_bytes());
    (peer_id_of_provider(&node).as_ref() == Some(peer)).then_some(node)
}

/// Why the live listener set could not be represented by the signed, bounded relay-hint type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayHintDerivationError {
    /// The swarm worker could not report its current listener set.
    ListenerReadFailed { reason: String },
    /// Reading even one current listener snapshot exceeded the caller's absolute deadline.
    ListenerReadTimedOut { timeout: Duration },
    /// Requested reservations did not all appear in the live listener set before the deadline.
    RequestedReservationsNotLive {
        requested: usize,
        live: usize,
        timeout: Duration,
    },
    /// A live circuit listener did not name a relay immediately before `/p2p-circuit`.
    CircuitMissingRelayPeer { address: Multiaddr },
    /// The relay PeerId cannot be losslessly represented as the wire's ed25519 [`NodeId`].
    RelayPeerNotEd25519 { peer: PeerId, address: Multiaddr },
    /// The relay's ed25519 key is weak/invalid under the frozen strict wire rules.
    RelayIdentityRejected {
        relay: NodeId,
        reason: RelayHintsError,
    },
    /// The already-sorted set failed the final typed constructor (an invariant violation).
    CanonicalizationFailed { reason: RelayHintsError },
    /// A provider cannot reserve through itself in its own signed record.
    ProviderIsRelay { found: NodeId },
    /// More distinct live reservations exist than the wire can represent. Never truncated.
    TooMany { found: usize, cap: usize },
}

impl std::fmt::Display for RelayHintDerivationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ListenerReadFailed { reason } => {
                write!(f, "cannot read the swarm's current listener set: {reason}")
            }
            Self::ListenerReadTimedOut { timeout } => write!(
                f,
                "reading the swarm's current listener set exceeded the absolute {timeout:?} deadline"
            ),
            Self::RequestedReservationsNotLive {
                requested,
                live,
                timeout,
            } => write!(
                f,
                "requested {requested} relay reservation(s), but only {live} appeared in the live /p2p-circuit listener set within {timeout:?}"
            ),
            Self::CircuitMissingRelayPeer { address } => write!(
                f,
                "live circuit listener {address} has no relay /p2p/<PeerId> immediately before /p2p-circuit"
            ),
            Self::RelayPeerNotEd25519 { peer, address } => write!(
                f,
                "live circuit listener {address} names relay {peer}, whose PeerId is not an inline canonical ed25519 identity"
            ),
            Self::RelayIdentityRejected { relay, reason } => {
                write!(f, "live relay identity {relay} is not wire-safe: {reason}")
            }
            Self::CanonicalizationFailed { reason } => write!(
                f,
                "canonical live relay set unexpectedly failed the signed hint constructor: {reason}"
            ),
            Self::ProviderIsRelay { found } => write!(
                f,
                "provider {found} appears as its own live relay; self-relay hints are forbidden"
            ),
            Self::TooMany { found, cap } => write!(
                f,
                "provider has {found} distinct live relay reservations, exceeds signed hint cap {cap}; refusing instead of truncating"
            ),
        }
    }
}

impl std::error::Error for RelayHintDerivationError {}

/// Derive the signed relay-hint value from the swarm's CURRENT listener set.
///
/// Only addresses that already contain an accepted `/p2p-circuit` listener contribute. Direct
/// listeners are ignored. The relay is the [`PeerId`] immediately before `P2pCircuit`, converted
/// losslessly to its ed25519 [`NodeId`]. Identities are deduplicated and sorted because listener
/// order is runtime timing, while the signed wire requires canonical ascending order. More than
/// two distinct live relays is a startup/announce error, never a silent truncation.
pub fn relay_hints_from_circuit_addresses(
    provider: NodeId,
    listeners: &[Multiaddr],
) -> Result<RelayHints, RelayHintDerivationError> {
    let mut hints = BTreeSet::new();
    for address in listeners {
        let mut immediately_preceding_peer = None;
        for protocol in address.iter() {
            match protocol {
                Protocol::P2p(peer) => immediately_preceding_peer = Some(peer),
                Protocol::P2pCircuit => {
                    let peer = immediately_preceding_peer.take().ok_or_else(|| {
                        RelayHintDerivationError::CircuitMissingRelayPeer {
                            address: address.clone(),
                        }
                    })?;
                    let relay = node_id_of_peer_id(&peer).ok_or_else(|| {
                        RelayHintDerivationError::RelayPeerNotEd25519 {
                            peer,
                            address: address.clone(),
                        }
                    })?;
                    if relay == provider {
                        return Err(RelayHintDerivationError::ProviderIsRelay { found: relay });
                    }
                    RelayHints::try_from_nodes(&[relay]).map_err(|reason| {
                        RelayHintDerivationError::RelayIdentityRejected { relay, reason }
                    })?;
                    hints.insert(relay);
                }
                _ => immediately_preceding_peer = None,
            }
        }
    }
    if hints.len() > MAX_LIBP2P_RELAY_HINTS {
        return Err(RelayHintDerivationError::TooMany {
            found: hints.len(),
            cap: MAX_LIBP2P_RELAY_HINTS,
        });
    }
    let canonical: Vec<NodeId> = hints.into_iter().collect();
    RelayHints::try_from_nodes(&canonical)
        .map_err(|reason| RelayHintDerivationError::CanonicalizationFailed { reason })
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::Multiaddr;

    #[test]
    fn identity_node_id_and_peer_id_agree_across_the_seam() {
        // The node identity (libp2p) and the record provider (ed25519 verifying key)
        // are ONE key: node_id_of(keypair) must derive to the same PeerId that
        // keypair.public() yields, or the S1 provider<->PeerId binding would reject a
        // node's own honest records.
        let keypair = keypair_from_seed(&[7u8; 32]);
        let node_id = node_id_of(&keypair);
        assert_eq!(
            peer_id_of_provider(&node_id),
            Some(keypair.public().to_peer_id()),
            "a node's provider NodeId must derive to its own PeerId"
        );
        assert_eq!(
            node_id_of_peer_id(&keypair.public().to_peer_id()),
            Some(node_id),
            "the inline ed25519 PeerId must round-trip to the signed NodeId"
        );
    }

    #[test]
    fn peer_id_inverse_rejects_an_identity_digest_that_is_not_an_ed25519_public_key() {
        // `PeerId::random` uses an identity multihash over arbitrary 32 bytes. It is a valid
        // libp2p PeerId, but those bytes are NOT the protobuf encoding of an ed25519 public key,
        // so it cannot become a signed relay NodeId.
        assert_eq!(node_id_of_peer_id(&PeerId::random()), None);
    }

    #[test]
    fn peer_id_of_provider_rejects_a_non_point() {
        // 0xdf..df is a y-coordinate ed25519 cannot decompress to a point (the same
        // non-point the frozen record_codec test uses); the binding must fail closed
        // (None) rather than fabricate a PeerId. Note this is defense-in-depth: the
        // frozen decode already rejects a non-point provider (BadProviderKey) before the
        // binding check ever runs, so in the real path the bytes are always valid.
        assert_eq!(peer_id_of_provider(&NodeId::from_bytes([0xdf; 32])), None);
    }

    #[test]
    fn distinct_providers_get_distinct_value_keys() {
        // The composite key must separate providers of the SAME content, or the value
        // store would collide - the whole reason for the hybrid mapping.
        let key = ContentKey::from_bytes([0x01; 32]);
        let a = keypair_from_seed(&[1u8; 32]).public().to_peer_id();
        let b = keypair_from_seed(&[2u8; 32]).public().to_peer_id();
        assert_ne!(provider_value_key(&key, &a), provider_value_key(&key, &b));
        // And the index key (raw ContentKey) is distinct from any value key.
        assert_ne!(
            provider_index_key(&key).to_vec(),
            provider_value_key(&key, &a).to_vec()
        );
    }

    #[test]
    fn live_circuit_listeners_become_sorted_deduplicated_signed_hints() {
        let provider = node_id_of(&keypair_from_seed(&[9u8; 32]));
        let relay_a = keypair_from_seed(&[1u8; 32]);
        let relay_b = keypair_from_seed(&[2u8; 32]);
        let a_peer = relay_a.public().to_peer_id();
        let b_peer = relay_b.public().to_peer_id();
        let direct: Multiaddr = "/ip4/127.0.0.1/tcp/4000".parse().unwrap();
        let through_b: Multiaddr = format!("/ip4/127.0.0.1/tcp/4002/p2p/{b_peer}/p2p-circuit")
            .parse()
            .unwrap();
        let through_a: Multiaddr = format!("/ip4/127.0.0.1/tcp/4001/p2p/{a_peer}/p2p-circuit")
            .parse()
            .unwrap();

        let hints = relay_hints_from_circuit_addresses(
            provider,
            &[direct, through_b.clone(), through_a.clone(), through_b],
        )
        .expect("accepted circuit listeners yield hints");
        let mut expected = [node_id_of(&relay_a), node_id_of(&relay_b)];
        expected.sort();
        assert_eq!(hints.as_slice(), &expected);
    }

    #[test]
    fn malformed_or_unrepresentable_live_circuit_listener_fails_closed() {
        let provider = node_id_of(&keypair_from_seed(&[9u8; 32]));
        let missing_peer: Multiaddr = "/ip4/127.0.0.1/tcp/4001/p2p-circuit".parse().unwrap();
        assert!(matches!(
            relay_hints_from_circuit_addresses(provider, std::slice::from_ref(&missing_peer)),
            Err(RelayHintDerivationError::CircuitMissingRelayPeer { address })
                if address == missing_peer
        ));

        let self_peer = peer_id_of_provider(&provider).unwrap();
        let self_relay: Multiaddr = format!("/ip4/127.0.0.1/tcp/4002/p2p/{self_peer}/p2p-circuit")
            .parse()
            .unwrap();
        assert!(matches!(
            relay_hints_from_circuit_addresses(provider, &[self_relay]),
            Err(RelayHintDerivationError::ProviderIsRelay { found }) if found == provider
        ));

        let random_peer = PeerId::random();
        let not_ed25519: Multiaddr =
            format!("/ip4/127.0.0.1/tcp/4003/p2p/{random_peer}/p2p-circuit")
                .parse()
                .unwrap();
        assert!(matches!(
            relay_hints_from_circuit_addresses(provider, &[not_ed25519]),
            Err(RelayHintDerivationError::RelayPeerNotEd25519 { peer, .. })
                if peer == random_peer
        ));
    }

    #[test]
    fn more_than_two_distinct_live_relays_is_rejected_never_truncated() {
        let provider = node_id_of(&keypair_from_seed(&[9u8; 32]));
        let listeners: Vec<Multiaddr> = [1u8, 2, 3]
            .into_iter()
            .map(|seed| {
                let peer = keypair_from_seed(&[seed; 32]).public().to_peer_id();
                format!("/ip4/127.0.0.1/tcp/4{seed:03}/p2p/{peer}/p2p-circuit")
                    .parse()
                    .unwrap()
            })
            .collect();
        assert!(matches!(
            relay_hints_from_circuit_addresses(provider, &listeners),
            Err(RelayHintDerivationError::TooMany { found: 3, cap: 2 })
        ));
    }
}
