//! The content-routing value types: the discovery key, the signed record it maps
//! to, and the dial coordinates that stay BELOW the seam.
//!
//! The freeze surface these name ([`ContentKey`] derivation, [`ProviderRecord`]
//! codec) is TASK-126's to pin, INSIDE an opaque value the substrate merely stores
//! (`ContentKey -> signed opaque bytes`). This crate names the SHAPE the seam and
//! the freeze must agree on; it deliberately does NOT implement the derivation or a
//! wire codec (no serde here), so TASK-126 can choose them against the adopted
//! backend without a churn dependency on this crate.

use crate::ids::{Blake3Digest, NodeId, TransportOffer};

/// Length in bytes of a [`ContentKey`].
pub const CONTENT_KEY_LEN: usize = 32;

/// The algorithm tag prefixing the canonical string form (`contentkey:<hex>`).
pub const CONTENT_KEY_PREFIX: &str = "contentkey:";

/// A domain-separated discovery key derived from the signed `NarHash`: the key a
/// [`ProviderDirectory`](crate::ProviderDirectory) looks up and an
/// [`AvailabilityAnnouncer`](crate::AvailabilityAnnouncer) publishes under.
///
/// It is a SEPARATE identity from the content's `NarHash`/[`Blake3Digest`] on
/// purpose: the DHT key space and the signed trust anchor should not be the same
/// bytes, so nodes merely ROUTING a lookup toward the key see only the derived key,
/// not the signed `NarHash`. Stated honestly, this is NOT full privacy: the k
/// closest STORING nodes hold the [`ProviderRecord`], whose `content`
/// [`Blake3Digest`] they therefore learn - the separation narrows who sees what, it
/// does not hide the content identity from a storing node. The adversarial exposure
/// analysis is TASK-132's, not this key's.
///
/// The exact derivation (`NarHash -> ContentKey`) is FROZEN by TASK-126 against the
/// adopted backend; that freeze also decides whether the record's `content` field is
/// LEARNED from the record or already KNOWN by the asker (see
/// [`ProviderRecord::content`]). This type is the 32-byte opaque result, with a
/// canonical `contentkey:<hex>` string for logs. `from_bytes` is the only
/// constructor until TASK-126 pins the derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContentKey([u8; CONTENT_KEY_LEN]);

impl ContentKey {
    /// Wrap the 32 raw derived-key bytes. The `NarHash -> ContentKey` derivation
    /// that PRODUCES these bytes is TASK-126's freeze; this crate carries the
    /// result, not the recipe.
    pub const fn from_bytes(bytes: [u8; CONTENT_KEY_LEN]) -> Self {
        ContentKey(bytes)
    }

    /// The raw 32 bytes (the opaque DHT key).
    pub const fn as_bytes(&self) -> &[u8; CONTENT_KEY_LEN] {
        &self.0
    }
}

impl std::fmt::Display for ContentKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{CONTENT_KEY_PREFIX}")?;
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Length in bytes of a [`ProviderRecord`] signature (ed25519).
pub const PROVIDER_SIGNATURE_LEN: usize = 64;

/// WHO can serve WHAT, HOW, until WHEN - signed. The value a
/// [`ProviderDirectory`](crate::ProviderDirectory) returns and an
/// [`AvailabilityAnnouncer`](crate::AvailabilityAnnouncer) publishes.
///
/// Backed by a Kademlia VALUE store (`put_record`/`get_record`, NOT `get_providers`)
/// on every backend, so the whole signed record - offers, expiry, signature - is
/// learnable WITHOUT the provider being online (AC#6). It carries NO dialable
/// address and NO store path: the address is resolved separately via
/// [`NodeLocator`](crate::NodeLocator) (it stays a [`DialInfo`] below the seam), and
/// the store-path name is a secret that never enters the directory.
///
/// The content identity ([`Blake3Digest`]) appears EXACTLY ONCE (in `content`); the
/// `offers` are pure locators, so a record can never name two blobs.
///
/// The exact byte codec, the record-size cap, and how `expiry` reconciles with the
/// substrate's own record TTL (AC#6) are FROZEN by TASK-126 - this is the field
/// shape that freeze must realise, not the codec itself. TASK-126 must also settle
/// two SSOT questions this shape raises (see the field docs): the `key` field vs the
/// DHT storage key, and whether `content` is redundant with what the asker already
/// holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderRecord {
    /// The discovery key this record answers.
    ///
    /// SSOT INVARIANT (TASK-126 to enforce in the codec): `key` MUST equal the DHT
    /// storage key the record is stored under, and the `signature` MUST bind it (so
    /// a record cannot be replayed under another key). It is carried IN the record so
    /// the signature covers it; the codec validates `record.key == storage_key`
    /// fail-fast on read. Whether to keep the field or reconstruct it for signing is
    /// TASK-126's call - stated here so the duplication is a decision, not an
    /// accident.
    pub key: ContentKey,
    /// The content identity being offered (single, by construction).
    ///
    /// OPEN (TASK-126): is this LEARNED from the record, or already KNOWN by an asker
    /// who possessed the `NarHash` to derive `key` and to run gate-1 verification? If
    /// the latter, it may be redundant and droppable; if a record can be discovered
    /// by `key` alone without the asker knowing the content digest, it must stay.
    /// Frozen with the codec, not guessed here.
    pub content: Blake3Digest,
    /// The provider's node identity (the holder to dial, via [`NodeLocator`]).
    pub provider: NodeId,
    /// HOW to fetch it: pure per-transport locators. Several offers let the fetch
    /// side pick a [`TransportTag`](crate::TransportTag) at request time.
    pub offers: Vec<TransportOffer>,
    /// Monotonic per-provider version, so a fresher record supersedes a stale one
    /// for the same `(key, provider)`.
    pub sequence: u64,
    /// When the provider signed it (seconds since the Unix epoch).
    pub issued_at: u64,
    /// When it stops being valid (seconds since the Unix epoch). Reconciled against
    /// the substrate's record TTL by TASK-126 (AC#6): the effective lifetime is the
    /// MIN of this and what the store will hold.
    pub expiry: u64,
    /// The ed25519 signature over the record, so a consumer can attribute it to
    /// `provider` (claim-spam mitigation, PRD risk 6). Verification lives at the
    /// backend/policy boundary, not in this shape.
    pub signature: [u8; PROVIDER_SIGNATURE_LEN],
}

/// What a [`NodeLocator`](crate::NodeLocator) yields: the direct/relay coordinates
/// to actually dial a [`NodeId`]. OPAQUE above the seam BY DESIGN - it is consumed
/// INSIDE the fabric (by transfer/announce), and never surfaces to the serving
/// core, so the core cannot accidentally depend on a stack's address shape. What
/// DOES surface to policy is the exposure a locate incurs (recorded to the
/// [`ExposureLedger`](crate::ExposureLedger)) and the resolution policy chosen, not
/// these bytes. The concrete address representation is a backend concern (TASK-141).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DialInfo {
    /// Opaque direct/relay location strings. The seam treats them as opaque; a
    /// backend gives them meaning (an iroh `NodeAddr`, a libp2p `Multiaddr`).
    pub locations: Vec<String>,
}

impl DialInfo {
    /// A dial info from opaque location strings.
    pub fn new(locations: impl IntoIterator<Item = String>) -> Self {
        DialInfo {
            locations: locations.into_iter().collect(),
        }
    }
}

/// How a [`NodeLocator`](crate::NodeLocator) is ALLOWED to resolve an address - the
/// POLICY choice, decided above the seam (TASK-120) and handed down. This is the
/// axis-2 knob the PRD makes gate-able: an explicit peer list leaks nothing, while
/// pkarr/Mainline/DNS resolution discloses the queried `NodeId` to third parties.
/// The fabric enforces the mechanism bound it is handed; it does not choose it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolutionPolicy {
    /// Resolve ONLY from an explicitly configured peer address book - no third
    /// party is consulted, so no address lookup is disclosed.
    ExplicitPeersOnly,
    /// Consult decentralized public infrastructure (pkarr / Mainline / DNS). This
    /// discloses the queried `NodeId` to that infrastructure - the leak
    /// [`Recipient`](crate::Recipient)s a locate then records.
    PublicInfrastructure,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::InfoHash;

    fn sample_record() -> ProviderRecord {
        ProviderRecord {
            key: ContentKey::from_bytes([0x01; CONTENT_KEY_LEN]),
            content: Blake3Digest::from_bytes([0x02; 32]),
            provider: NodeId::from_bytes([0x03; 32]),
            offers: vec![
                TransportOffer::Iroh {
                    node: NodeId::from_bytes([0x03; 32]),
                },
                TransportOffer::BitTorrent {
                    infohash: InfoHash::V1([0x04; 20]),
                },
            ],
            sequence: 7,
            issued_at: 1_000,
            expiry: 2_000,
            signature: [0x05; PROVIDER_SIGNATURE_LEN],
        }
    }

    #[test]
    fn content_key_renders_with_prefix() {
        let key = ContentKey::from_bytes([0xcd; CONTENT_KEY_LEN]);
        assert_eq!(key.to_string(), format!("contentkey:{}", "cd".repeat(32)));
    }

    #[test]
    fn provider_record_carries_signed_who_how_until_when() {
        let r = sample_record();
        // The single content identity, several pure-locator offers, a signature.
        assert_eq!(r.offers.len(), 2);
        assert!(r.expiry > r.issued_at);
        assert_eq!(r.signature.len(), PROVIDER_SIGNATURE_LEN);
        // Equality is structural (used by the fake directory's tests).
        assert_eq!(r, sample_record());
    }

    #[test]
    fn dial_info_is_opaque_locations() {
        let d = DialInfo::new(["direct:1.2.3.4:9000".to_string(), "relay:eu".to_string()]);
        assert_eq!(d.locations.len(), 2);
    }
}
