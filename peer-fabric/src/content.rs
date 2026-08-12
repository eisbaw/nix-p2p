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

/// Length in bytes of the signed SHA-256 `NarHash` a [`ContentKey`] is derived
/// from. Nix signs a `sha256` NarHash, so the derivation input is 32 raw bytes.
pub const NAR_HASH_LEN: usize = 32;

/// The BLAKE3 `derive_key` CONTEXT string that domain-separates the discovery key
/// (TASK-126 FREEZE). This is the DELIBERATE OPPOSITE of the content identity's
/// recipe: [`Blake3Digest`] is PLAIN, UNKEYED BLAKE3 with NO domain separation
/// (`BLAKE3_DOMAIN_SEPARATION == None`) so it EQUALS the iroh-blobs blob hash a peer
/// fetches by; the discovery [`ContentKey`] MUST be domain-separated so a node merely
/// ROUTING a lookup toward the key sees a value in a DISTINCT keyspace, not the signed
/// `NarHash` and not the BLAKE3 content hash. The `/v1` suffix is the schema version:
/// a future recipe bumps it, which lands every key on a fresh point (the
/// cross-version golden vector proves this). Reproducible by any second
/// implementation with `blake3::derive_key` / `b3sum --derive-key` / python
/// `blake3(..., derive_key_context=...)` — see `scripts/check-content-key-derivation.py`.
pub const CONTENT_KEY_CONTEXT: &str = "nix-p2p/discovery/ContentKey/v1";

/// The recipe pin, as a COMPILE-TIME assertion (mirror of
/// `BLAKE3_DOMAIN_SEPARATION`'s assert in `ids.rs`, but the INVERSE decision). An
/// empty context would collapse the domain separation and leak the signed `NarHash`
/// keyspace into the DHT routing layer; this fails the BUILD in every profile the
/// moment someone empties it, so the freeze is greppable and a reviewer sees the
/// decision, not its absence.
const _: () = assert!(
    !CONTENT_KEY_CONTEXT.is_empty(),
    "the discovery ContentKey is DELIBERATELY domain-separated (unlike Blake3Digest, \
     which must be plain unkeyed BLAKE3 to equal the iroh-blobs blob hash); an empty \
     derive_key context would collapse that separation and leak the signed NarHash \
     into the DHT keyspace"
);

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
/// PRIVACY FRAMING — RESOLVED (TASK-126, forward-carried note 3): the freeze AFFIRMS
/// this narrows-not-hides posture and makes it structural. Because
/// [`ContentKey::derive_from_signed_nar_hash`] is a domain-separated `derive_key`
/// (not a plain hash of the `NarHash`), a node that only ROUTES toward the key
/// (never in the k-closest storing set) learns neither the signed `NarHash` nor the
/// content [`Blake3Digest`] - it sees an opaque point in a separate keyspace. A
/// STORING node unavoidably learns `content` (it holds the record). No further
/// privacy machinery is frozen here; the adversarial exposure ledger is TASK-132.
///
/// The derivation (`signed NarHash -> ContentKey`) is FROZEN by TASK-126
/// ([`ContentKey::derive_from_signed_nar_hash`]): `BLAKE3 derive_key` in the
/// versioned [`CONTENT_KEY_CONTEXT`] domain. This type is the 32-byte opaque result,
/// with a canonical `contentkey:<hex>` string for logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContentKey([u8; CONTENT_KEY_LEN]);

impl ContentKey {
    /// Wrap 32 raw derived-key bytes (e.g. a key read off the wire / a DHT storage
    /// key). Does NOT derive anything; for the frozen recipe use
    /// [`ContentKey::derive_from_signed_nar_hash`].
    pub const fn from_bytes(bytes: [u8; CONTENT_KEY_LEN]) -> Self {
        ContentKey(bytes)
    }

    /// THE FROZEN DISCOVERY-KEY RECIPE (TASK-126): domain-separated `BLAKE3`
    /// `derive_key` over the signed SHA-256 `NarHash`, in the versioned
    /// [`CONTENT_KEY_CONTEXT`].
    ///
    /// This is a KDF, not a plain hash, and that is the point: `derive_key` mixes the
    /// context string into BLAKE3's key-derivation mode (a distinct internal flag from
    /// `hash` mode), so the result is CRYPTOGRAPHICALLY SEPARATED from both the signed
    /// `NarHash` (SHA-256) and the content [`Blake3Digest`] (plain unkeyed BLAKE3) -
    /// separated in the sense that recovering one from another is a preimage break,
    /// not that collision is impossible (it is ~2^-256). A node routing a lookup
    /// toward this key therefore learns neither the trust anchor nor the fetch
    /// identity from the key alone (the honest privacy caveat — a k-closest STORING
    /// node still holds the record and its `content` — is documented on the type).
    ///
    /// FROZEN and reproducible: `blake3::derive_key(CONTENT_KEY_CONTEXT, nar_hash)`,
    /// equal to `b3sum --derive-key "<context>"` over the 32 hash bytes and to python
    /// `blake3(nar_hash, derive_key_context=CONTENT_KEY_CONTEXT)`. The golden vectors
    /// pin it; `scripts/check-content-key-derivation.py` is the independent
    /// second-implementation anchor.
    pub fn derive_from_signed_nar_hash(nar_hash_sha256: &[u8; NAR_HASH_LEN]) -> Self {
        ContentKey(blake3::derive_key(CONTENT_KEY_CONTEXT, nar_hash_sha256))
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
/// The byte codec, the record-size cap ([`MAX_PROVIDER_RECORD_BYTES`]), the
/// bounded-offers cap ([`MAX_OFFERS_PER_RECORD`]) and the signing preimage are FROZEN
/// by TASK-126 in [`crate::record_codec`]; the validation rules (monotonic sequence,
/// idempotent refresh, signed withdrawal, expiry, replay/resurrection rejection,
/// concurrent-provider merge) are frozen in [`crate::record_store`]. This struct is
/// the field shape those realise. The two SSOT questions this shape raised are now
/// RESOLVED (see the `key` and `content` field docs).
///
/// `expiry` reconciles with the substrate's own record TTL (AC#6) at the effective
/// lifetime = MIN(this, what the store holds); the codec pins the field, the backend
/// (TASK-103) enforces the MIN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderRecord {
    /// The discovery key this record answers.
    ///
    /// SSOT INVARIANT — RESOLVED (TASK-126, forward-carried note 1): `key` is KEPT in
    /// the record AND covered by the `signature`, and [`crate::record_codec`]'s decode
    /// takes the DHT storage key as `expected_key` and REJECTS
    /// (`RecordDecodeError::WrongKey`) any record whose `key` differs. Keeping the
    /// field (rather than reconstructing it for signing) is deliberate: the signature
    /// must BIND the key so a stored value cannot be replayed under a different
    /// storage key, and carrying it makes the opaque value self-describing and
    /// verifiable standalone. The duplication with the storage key is therefore a
    /// checked invariant, not an accident.
    pub key: ContentKey,
    /// The content identity being offered (single, by construction).
    ///
    /// RESOLVED (TASK-126, forward-carried note 2): this is LEARNED from the record
    /// and is NOT redundant, so it STAYS. The asker possesses the signed SHA-256
    /// `NarHash` (that is what it derives `key` from), but `content` is the
    /// [`Blake3Digest`] = plain unkeyed `BLAKE3(RawNarV1)`, the iroh-blobs FETCH
    /// identity - an INDEPENDENT hash of the same NAR. Neither hash is derivable from
    /// the other, so an asker who found the record by `key` alone still needs this
    /// field to know what blob to fetch and stream-verify (gate 1). It appears EXACTLY
    /// ONCE (offers are pure locators), so a record can never name two blobs.
    pub content: Blake3Digest,
    /// The provider's node identity (the holder to dial, via [`NodeLocator`]).
    pub provider: NodeId,
    /// HOW to fetch it: pure per-transport locators. Several offers let the fetch
    /// side pick a [`TransportTag`](crate::TransportTag) at request time.
    pub offers: Vec<TransportOffer>,
    /// Monotonic per-provider version, so a fresher record supersedes a stale one
    /// for the same `(key, provider)`.
    pub sequence: u64,
    /// When the provider signed it (seconds since the Unix epoch). INFORMATIONAL
    /// ONLY: validation NEVER orders on `issued_at` (the monotonic `sequence` orders,
    /// `expiry` gates liveness). Trusting a wall-clock field for ordering would
    /// reintroduce a clock-skew replay bug, so a future consumer must not.
    pub issued_at: u64,
    /// When it stops being valid (seconds since the Unix epoch). Reconciled against
    /// the substrate's record TTL by TASK-126 (AC#6): the effective lifetime is the
    /// MIN of this and what the store will hold.
    pub expiry: u64,
    /// The ed25519 signature over the frozen signing preimage (TASK-126;
    /// [`crate::record_codec::provider_record_signing_bytes`]), so a consumer can
    /// attribute it to `provider` (claim-spam mitigation, PRD risk 6). The `provider`
    /// [`NodeId`] IS the ed25519 verifying key, so the record is SELF-VERIFYING:
    /// [`crate::record_codec::decode_provider_assertion`] checks this signature with no
    /// external key material.
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
    fn content_key_derivation_is_domain_separated_from_the_content_hash() {
        // The DISCOVERY key and the CONTENT identity are the SAME 32 bytes hashed two
        // deliberately different ways: the discovery key is a domain-separated
        // derive_key, the content id would be plain BLAKE3. They MUST NOT collide, or
        // the domain separation that keeps routing nodes from seeing the content id
        // (and the signed NarHash) is vacuous.
        let nar_hash = [0x11u8; NAR_HASH_LEN];
        let key = ContentKey::derive_from_signed_nar_hash(&nar_hash);
        assert_ne!(
            key.as_bytes(),
            &nar_hash,
            "the ContentKey must not be the NarHash passed through"
        );
        assert_ne!(
            key.as_bytes(),
            blake3::hash(&nar_hash).as_bytes(),
            "the domain-separated derive_key must not equal plain BLAKE3 of the same \
             bytes (that plain hash is the content-identity keyspace)"
        );
        // Deterministic: the frozen recipe is a pure function of its input.
        assert_eq!(key, ContentKey::derive_from_signed_nar_hash(&nar_hash));
    }

    #[test]
    fn content_key_context_bump_moves_every_key() {
        // The `/v1` in CONTENT_KEY_CONTEXT is the schema version; a bump must land on
        // a fresh point (proven here by simulating a v2 context). This is the
        // cross-version guarantee stated as a property; the byte-pinned cross-version
        // vector lives in tests/provider_record_golden.rs.
        let nar_hash = [0x11u8; NAR_HASH_LEN];
        let v1 = ContentKey::derive_from_signed_nar_hash(&nar_hash);
        let v2 = ContentKey::from_bytes(blake3::derive_key(
            "nix-p2p/discovery/ContentKey/v2",
            &nar_hash,
        ));
        assert_ne!(v1, v2, "a context/version bump must not collide with v1");
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
