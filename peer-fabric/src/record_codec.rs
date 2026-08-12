//! The FROZEN `ProviderRecord` opaque-value wire codec (TASK-126).
//!
//! ## What is frozen here, and why it is a canonical BINARY codec (not JSON)
//!
//! A [`ProviderRecord`] / [`ProviderWithdrawal`] is stored in the DHT as ONE opaque,
//! ed25519-SIGNED byte value keyed by a [`ContentKey`]. Two facts force a canonical,
//! fixed-layout binary encoding rather than the daemon's JSON claim codec:
//!
//!   * THE SIGNATURE IS OVER THE BYTES. A record's authenticity is an ed25519
//!     signature over the exact preimage; two independent implementations must
//!     produce the SAME bytes for the same fields or a signature made by one fails to
//!     verify at the other. JSON has many byte encodings of one value (key order,
//!     whitespace, number forms); a fixed-layout binary encoding has exactly one.
//!   * NO UNASKED FIELD CAN EXIST (AC#2). The layout is a fixed sequence of typed
//!     positions, so there is no map in which an IP, a port, a relay address, a
//!     StorePath, a second content digest, or any unasked key could ride along - the
//!     way `deny_unknown_fields` + duplicate-key rejection had to be BOLTED ONTO the
//!     JSON claim wire. Here it is structural: a decoder reads the fields it knows and
//!     rejects anything left over ([`RecordDecodeError::TrailingBytes`]).
//!
//! This is a DELIBERATE contrast with `daemon::claim`, whose JSON wire tolerates and
//! DROPS unknown transport kinds for forward-compatibility. The claim wire is a
//! peer-to-peer velocity surface; this is a FROZEN, SIGNED opaque value where every
//! byte is under signature, so an unknown offer tag or a bad version FAILS CLOSED
//! rather than being skipped - skipping would either desync a variable-length parse
//! or admit bytes the signer did not commit to. A genuinely new transport or record
//! shape is a VERSIONED evolution ([`PROVIDER_RECORD_SCHEMA_VERSION`]), not a silent
//! tolerated field.
//!
//! ## The signing preimage
//!
//! The signature covers `SIGNING_DOMAIN || body`, where `body` is every byte of the
//! wire value EXCEPT the trailing 64-byte signature. The domain tag prevents a
//! signature made for another nix-p2p message (a claim, a hold answer) from being
//! replayed as a ProviderRecord, and the `kind` byte inside the body prevents a
//! `Provide` signature from being read as a `Withdraw`. The `provider` [`NodeId`] IS
//! the ed25519 verifying key, so a record is SELF-VERIFYING: decode needs no external
//! key material.
//!
//! ## Signature canonicality policy (must match across implementations)
//!
//! "The signature is over the bytes" is only sound if a signature has exactly ONE
//! acceptable encoding, or a second implementation could accept a MALLEABLE variant the
//! first rejects. This codec verifies with ed25519-dalek v3 `verify_strict`; the FROZEN
//! policy a conformant re-implementation MUST match is:
//!
//!   * REJECT a non-canonical scalar `S` (require `S < L`, the group order). Adding `L`
//!     to a valid `S` yields `S+L` with `[S+L]B = [S]B`, so a verifier that SKIPS the
//!     range check accepts it - the classic ed25519 malleability. ed25519-dalek v3
//!     `verify_strict`, libsodium's `crypto_sign_verify_detached`, and OpenSSL/`cryptography`
//!     all enforce `S < L` and reject `S+L`. This codec ALSO checks `S < L` explicitly
//!     ([`signature_scalar_is_canonical`]) so the policy is pinned independently of the
//!     dalek version and gets a distinct typed rejection; the golden
//!     `reject_malleable_signature` vector proves `S+L` is refused.
//!   * REJECT small-order / torsion public keys `A` AND commitments `R`, using
//!     COFACTORLESS verification (`[S]B = R + [k]A`, no cofactor multiplication). This is
//!     NORMATIVE, and it is the exact point where a permissive library verifier diverges
//!     from `verify_strict`: with `A = R =` the small-order IDENTITY point and `S = 0`,
//!     the equation `[0]B = R + [k]A` holds as `identity = identity`, so a verifier that
//!     skips the small-order check ACCEPTS a record "signed" by the identity key WITH NO
//!     SECRET - a full identity forgery. `verify_strict` rejects it (small-order `A`); a
//!     conformant second implementation MUST reject small-order `A` and `R` too, or it
//!     will accept records this codec rejects. The golden `reject_identity_forgery`
//!     vector pins this, and `scripts/check-content-key-derivation.py` re-checks it with
//!     a from-scratch ed25519 verifier (NOT a library) so the two agree byte-for-byte on
//!     which signatures are valid.
//!
//! ## Canonical offer list + iroh self-serve identity
//!
//!   * OFFERS ARE CANONICALLY ORDERED. The offer list is STRICTLY ASCENDING by each
//!     offer's wire encoding, which forbids duplicates and gives ONE signed encoding per
//!     logical set (findings #2). Both encode and decode enforce it; a non-canonical
//!     order - even one whose signature verifies - is a distinct rejected value
//!     ([`RecordDecodeError::OffersNotCanonical`]).
//!   * IROH OFFERS ARE SELF-SERVE (v1). An [`crate::ids::TransportOffer::Iroh`] `node`
//!     MUST equal the record's `provider`: a provider vouches for content reachable at
//!     ITS OWN iroh NodeId (an ed25519 identity it controls), so an offer cannot point
//!     discovery at an unauthorized third party. Decode rejects a mismatch
//!     ([`RecordDecodeError::IrohNodeNotProvider`]); this also validates the node is a
//!     valid curve point, since `provider` is validated and the node equals it.
//!     Delegation (offering a DIFFERENT node) would need that node's authorization and
//!     is deferred to a later schema version.
//!
//! ## Fail-closed decode (AC#4)
//!
//! [`decode_provider_assertion`] rejects, with a distinct typed
//! [`RecordDecodeError`], every one of: oversized, truncated/malformed, trailing
//! bytes, unknown version, unknown kind, unknown offer tag, a bad infohash version,
//! too many offers, offers not in canonical order, an iroh offer whose node is not the
//! provider, a provider id that is not a valid ed25519 point, a NON-CANONICAL
//! signature scalar (`S >= L`), a bad signature, a record whose carried `key` does not
//! match the DHT storage key it was fetched under (the SSOT invariant), and a stale
//! (expired) record. Each rule has a negative test that BITES: remove the guard and
//! the corresponding test fails.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::content::{ContentKey, PROVIDER_SIGNATURE_LEN, ProviderRecord};
use crate::ids::{BLAKE3_DIGEST_LEN, Blake3Digest, InfoHash, NODE_ID_LEN, NodeId, TransportOffer};

/// Wire schema version of the ProviderRecord opaque value. A decoder REJECTS any
/// other version ([`RecordDecodeError::UnknownVersion`]); a breaking change to the
/// layout or the signing preimage bumps this (and moves the golden vectors to a new
/// file), exactly like the daemon claim wire's `schema_version`.
pub const PROVIDER_RECORD_SCHEMA_VERSION: u16 = 1;

/// The maximum number of transport offers ONE [`ProviderRecord`] may carry. The
/// content behind a key has ONE identity per transport KIND, so a handful of pure
/// locators is all a record ever needs; the cap makes an over-stuffed record a hard
/// [`RecordDecodeError::TooManyOffers`] rather than an unbounded parse. 4 mirrors the
/// daemon claim wire's `MAX_OFFERS_PER_ANSWER`.
pub const MAX_OFFERS_PER_RECORD: usize = 4;

/// The maximum on-wire size of the opaque value, checked BEFORE any parse. A record
/// is a few fixed fields plus <= [`MAX_OFFERS_PER_RECORD`] small locators (worst case
/// ~324 bytes), so 1024 is generous headroom and past it the input is not a
/// well-formed record. 1024 is also the `data` cap of `iroh-dht-experiment`'s
/// `ED25519SignedMessage` carrier (TASK-126 spike), so this value keeps that fallback
/// backend viable on size even though the primary freeze target is libp2p-kad
/// `put_record` (whose opaque `value: Vec<u8>` is the model this codec realises).
pub const MAX_PROVIDER_RECORD_BYTES: usize = 1024;

/// Domain tag mixed into the signing preimage so a signature over another nix-p2p
/// message cannot be replayed as a ProviderRecord. Versioned with the schema. Ends
/// with a NUL, matching the repo's other ed25519/checksum signing domains
/// (`iroh_publication_authority`, `iroh_runtime`): the terminator makes the domain
/// UNAMBIGUOUS - no domain string can be a prefix of another - which a fixed constant
/// prefix does not guarantee on its own.
const SIGNING_DOMAIN: &[u8] = b"nix-p2p/discovery/ProviderRecord/v1\0";

// The `kind` discriminant (the 3rd body byte). A Provide carries content + offers; a
// Withdraw is a bare signed tombstone. The byte is inside the signed preimage, so a
// Provide signature never verifies as a Withdraw.
const KIND_PROVIDE: u8 = 0;
const KIND_WITHDRAW: u8 = 1;

// Transport-offer tags.
const OFFER_IROH: u8 = 0;
const OFFER_BITTORRENT: u8 = 1;
// BitTorrent infohash version bytes (length-disambiguated on the wire too).
const INFOHASH_V1: u8 = 1;
const INFOHASH_V2: u8 = 2;

/// The fixed body header common to both kinds: version(2) + kind(1) + key(32) +
/// provider(32) + sequence(8) + issued_at(8) + expiry(8). Used to reject a body too
/// short to even hold the header.
const BODY_HEADER_LEN: usize = 2 + 1 + 32 + 32 + 8 + 8 + 8;

/// An explicit, signed request to REMOVE a provider's record for a key (AC#3). It is
/// a distinct wire kind from [`ProviderRecord`] - a withdrawal has no content and no
/// offers, it only asserts "provider P no longer serves key K, as of sequence N". It
/// is sequenced in the SAME per-`(key, provider)` space as the records it retracts,
/// so a withdrawal must be strictly NEWER than the record it supersedes and a replayed
/// old withdrawal is rejected. `expiry` bounds the tombstone's lifetime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderWithdrawal {
    /// The discovery key being withdrawn from (SSOT-checked against the storage key,
    /// like [`ProviderRecord::key`]).
    pub key: ContentKey,
    /// The provider retracting its record (the ed25519 verifying key).
    pub provider: NodeId,
    /// Monotonic per-`(key, provider)` version; must exceed the record it retracts.
    pub sequence: u64,
    /// When the provider signed the withdrawal (Unix seconds).
    pub issued_at: u64,
    /// When the tombstone stops being valid (Unix seconds).
    pub expiry: u64,
    /// ed25519 signature over the frozen withdrawal preimage.
    pub signature: [u8; PROVIDER_SIGNATURE_LEN],
}

/// A decoded, signature-VERIFIED assertion about a `(key, provider)`: either a
/// positive [`ProviderRecord`] or a [`ProviderWithdrawal`]. This is what
/// [`decode_provider_assertion`] yields and what [`crate::record_store`] applies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderAssertion {
    /// "Provider P serves key K, here is how and until when."
    Provide(ProviderRecord),
    /// "Provider P no longer serves key K, as of sequence N."
    Withdraw(ProviderWithdrawal),
}

impl ProviderAssertion {
    /// The discovery key this assertion is about.
    pub fn key(&self) -> &ContentKey {
        match self {
            ProviderAssertion::Provide(r) => &r.key,
            ProviderAssertion::Withdraw(w) => &w.key,
        }
    }
    /// The provider (ed25519 identity) that signed it.
    pub fn provider(&self) -> &NodeId {
        match self {
            ProviderAssertion::Provide(r) => &r.provider,
            ProviderAssertion::Withdraw(w) => &w.provider,
        }
    }
    /// The monotonic per-`(key, provider)` sequence.
    pub fn sequence(&self) -> u64 {
        match self {
            ProviderAssertion::Provide(r) => r.sequence,
            ProviderAssertion::Withdraw(w) => w.sequence,
        }
    }
    /// When it stops being valid (Unix seconds).
    pub fn expiry(&self) -> u64 {
        match self {
            ProviderAssertion::Provide(r) => r.expiry,
            ProviderAssertion::Withdraw(w) => w.expiry,
        }
    }
    /// Whether this is a withdrawal (a tombstone) rather than a positive record.
    pub fn is_withdrawal(&self) -> bool {
        matches!(self, ProviderAssertion::Withdraw(_))
    }
}

/// Why a [`ProviderRecord`]/[`ProviderWithdrawal`] could not be ENCODED. Fail fast on
/// the SENDER so a bug (an over-cap record) is refused here, at the point of the
/// mistake, rather than exported to a peer - the same posture as the daemon claim
/// codec's encode-side checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordEncodeError {
    /// More than [`MAX_OFFERS_PER_RECORD`] offers.
    TooManyOffers { found: usize, cap: usize },
    /// The serialized value exceeds [`MAX_PROVIDER_RECORD_BYTES`].
    Oversized { len: usize, cap: usize },
    /// The offer list is not in CANONICAL order: offers must be STRICTLY ASCENDING by
    /// their wire encoding (which also forbids exact duplicates). One logical offer set
    /// then has exactly ONE signed encoding - mandatory for a content-addressed,
    /// signature-over-bytes record. Refused on the sender so a peer never receives a
    /// non-canonical value (which decode would reject anyway).
    OffersNotCanonical,
    /// An Iroh offer advertises a `node` that is not the record's `provider`. In v1 an
    /// Iroh offer is SELF-SERVE: the provider vouches for content reachable at ITS OWN
    /// iroh NodeId (which is its ed25519 identity). Delegating to a different node would
    /// require that node's authorization and is deferred to a later version.
    IrohNodeNotProvider {
        offer_node: NodeId,
        provider: NodeId,
    },
}

impl std::fmt::Display for RecordEncodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecordEncodeError::TooManyOffers { found, cap } => {
                write!(
                    f,
                    "provider record carries {found} offers, exceeds the {cap} cap"
                )
            }
            RecordEncodeError::Oversized { len, cap } => {
                write!(
                    f,
                    "provider record is {len} bytes, exceeds the {cap}-byte cap"
                )
            }
            RecordEncodeError::OffersNotCanonical => {
                write!(
                    f,
                    "provider record offers are not strictly ascending by encoding \
                     (non-canonical order or a duplicate offer)"
                )
            }
            RecordEncodeError::IrohNodeNotProvider {
                offer_node,
                provider,
            } => write!(
                f,
                "iroh offer node {offer_node} is not the provider {provider} \
                 (v1 iroh offers are self-serve; delegation is not permitted)"
            ),
        }
    }
}

impl std::error::Error for RecordEncodeError {}

/// Why a wire byte string was not an acceptable [`ProviderAssertion`]. Distinct
/// variants so a caller and a log line name the EXACT fault (fail fast + verbosely).
/// Every variant is exercised by a bite test in this module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordDecodeError {
    /// The input exceeds [`MAX_PROVIDER_RECORD_BYTES`] (checked before any parse).
    Oversized { len: usize, cap: usize },
    /// The input ran out of bytes mid-field (a truncated / malformed value).
    Truncated { need: usize, have: usize },
    /// Bytes remained after a complete value was parsed (an oversmuggled field, or a
    /// signature signed over a longer body than the fields the decoder knows).
    TrailingBytes { extra: usize },
    /// The declared schema version is not [`PROVIDER_RECORD_SCHEMA_VERSION`].
    UnknownVersion { found: u16, expected: u16 },
    /// The `kind` byte is neither Provide nor Withdraw.
    UnknownKind { found: u8 },
    /// A transport offer carried an unrecognised transport tag.
    UnknownOffer { tag: u8 },
    /// A BitTorrent offer carried an unrecognised infohash version byte.
    BadInfoHash { version: u8 },
    /// The record names more than [`MAX_OFFERS_PER_RECORD`] offers.
    TooManyOffers { found: usize, cap: usize },
    /// The offer list is not STRICTLY ASCENDING by wire encoding: either out of
    /// canonical order or containing an exact-duplicate offer. A signature-over-bytes
    /// record must have exactly one encoding per logical offer set, so a non-canonical
    /// order is a distinct malformed value even though its signature may verify.
    OffersNotCanonical,
    /// An Iroh offer's `node` is not the record's `provider`. v1 Iroh offers are
    /// self-serve (provider serves its own content at its own iroh NodeId); a mismatch
    /// is rejected rather than silently trusting an unauthorized third-party locator.
    IrohNodeNotProvider {
        offer_node: NodeId,
        provider: NodeId,
    },
    /// The `provider` field is not a valid ed25519 verifying key (curve point).
    BadProviderKey,
    /// The signature's scalar `S` is NON-CANONICAL (`S >= L`, the group order). This is
    /// the ed25519 `S+L` malleability: `[S+L]B = [S]B`, so a verifier that skips the
    /// range check accepts it. Our verifier (ed25519-dalek v3 `verify_strict`) already
    /// enforces `S < L`, as do libsodium/OpenSSL; we ALSO check it explicitly so this
    /// distinct classification is pinned independently of the dalek version, keeping the
    /// signature-over-bytes wire single-encoding across implementations.
    NonCanonicalSignature,
    /// The signature did not verify against `provider` over the frozen preimage.
    BadSignature,
    /// The record's own `key` does not equal the DHT storage key it was fetched
    /// under (the SSOT invariant; a record cannot be replayed under another key).
    WrongKey {
        expected: ContentKey,
        found: ContentKey,
    },
    /// The record is already expired at `now` (`expiry <= now`).
    Stale { expiry: u64, now: u64 },
}

impl std::fmt::Display for RecordDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecordDecodeError::Oversized { len, cap } => {
                write!(
                    f,
                    "provider record is {len} bytes, exceeds the {cap}-byte cap"
                )
            }
            RecordDecodeError::Truncated { need, have } => {
                write!(
                    f,
                    "provider record truncated: needed {need} more bytes, had {have}"
                )
            }
            RecordDecodeError::TrailingBytes { extra } => {
                write!(
                    f,
                    "provider record has {extra} trailing bytes after a complete value"
                )
            }
            RecordDecodeError::UnknownVersion { found, expected } => {
                write!(
                    f,
                    "unsupported provider-record version {found} (this build speaks {expected})"
                )
            }
            RecordDecodeError::UnknownKind { found } => {
                write!(f, "unknown provider-record kind byte {found}")
            }
            RecordDecodeError::UnknownOffer { tag } => {
                write!(f, "unknown transport-offer tag {tag}")
            }
            RecordDecodeError::BadInfoHash { version } => {
                write!(f, "unknown bittorrent infohash version byte {version}")
            }
            RecordDecodeError::TooManyOffers { found, cap } => {
                write!(
                    f,
                    "provider record names {found} offers, exceeds the {cap} cap"
                )
            }
            RecordDecodeError::OffersNotCanonical => {
                write!(
                    f,
                    "provider record offers are not strictly ascending by encoding \
                     (non-canonical order or a duplicate offer)"
                )
            }
            RecordDecodeError::IrohNodeNotProvider {
                offer_node,
                provider,
            } => write!(
                f,
                "iroh offer node {offer_node} is not the provider {provider} \
                 (v1 iroh offers are self-serve; delegation is not permitted)"
            ),
            RecordDecodeError::BadProviderKey => {
                write!(f, "provider id is not a valid ed25519 verifying key")
            }
            RecordDecodeError::NonCanonicalSignature => {
                write!(
                    f,
                    "signature scalar S is non-canonical (S >= L; the S+L malleability)"
                )
            }
            RecordDecodeError::BadSignature => {
                write!(
                    f,
                    "provider-record signature did not verify against the provider id"
                )
            }
            RecordDecodeError::WrongKey { expected, found } => write!(
                f,
                "provider record carries key {found} but was stored under {expected} \
                 (SSOT violation; possible replay under a different key)"
            ),
            RecordDecodeError::Stale { expiry, now } => {
                write!(f, "provider record expired at {expiry}, now is {now}")
            }
        }
    }
}

impl std::error::Error for RecordDecodeError {}

// -------------------------------------------------------------------------
// Encode.
// -------------------------------------------------------------------------

fn write_offer(out: &mut Vec<u8>, offer: &TransportOffer) {
    match offer {
        TransportOffer::Iroh { node } => {
            out.push(OFFER_IROH);
            out.extend_from_slice(node.as_bytes());
        }
        TransportOffer::BitTorrent { infohash } => {
            out.push(OFFER_BITTORRENT);
            match infohash {
                InfoHash::V1(b) => {
                    out.push(INFOHASH_V1);
                    out.extend_from_slice(b);
                }
                InfoHash::V2(b) => {
                    out.push(INFOHASH_V2);
                    out.extend_from_slice(b);
                }
            }
        }
    }
}

/// The canonical wire encoding of a single offer, used ONLY to order and de-duplicate
/// offers (see [`offers_are_canonical`]). It is the exact bytes [`write_offer`] emits.
fn offer_encoding(offer: &TransportOffer) -> Vec<u8> {
    let mut v = Vec::new();
    write_offer(&mut v, offer);
    v
}

/// Whether an offer list is in CANONICAL order: STRICTLY ASCENDING by wire encoding.
/// Strictness forbids exact duplicates too, so one logical offer set has exactly one
/// valid signed encoding. Empty and single-offer lists are trivially canonical.
fn offers_are_canonical(offers: &[TransportOffer]) -> bool {
    offers
        .windows(2)
        .all(|w| offer_encoding(&w[0]) < offer_encoding(&w[1]))
}

/// The offer-list structural invariants a Provide must satisfy to be ENCODED, checked
/// on the sender (fail fast): the cap, canonical order, and iroh-offer self-serve
/// identity. Decode re-checks all of these on untrusted bytes.
fn check_provide_invariants(record: &ProviderRecord) -> Result<(), RecordEncodeError> {
    if record.offers.len() > MAX_OFFERS_PER_RECORD {
        return Err(RecordEncodeError::TooManyOffers {
            found: record.offers.len(),
            cap: MAX_OFFERS_PER_RECORD,
        });
    }
    if !offers_are_canonical(&record.offers) {
        return Err(RecordEncodeError::OffersNotCanonical);
    }
    for offer in &record.offers {
        if let TransportOffer::Iroh { node } = offer
            && node != &record.provider
        {
            return Err(RecordEncodeError::IrohNodeNotProvider {
                offer_node: *node,
                provider: record.provider,
            });
        }
    }
    Ok(())
}

/// The `body` (everything but the trailing signature) of a Provide value.
///
/// The offer count is narrowed to a `u8` length byte; this is reached by the PUBLIC
/// [`provider_record_signing_bytes`] as well as by [`encode_provider_record`], so the
/// cap is a REAL `assert!` here (release too, finding #6): without it a record with
/// more than 255 offers would produce a length byte that disagrees with the appended
/// offers - a corrupted SIGNED preimage. A panic here is fail-closed (no bytes are
/// produced); the fallible [`encode_provider_record`] returns a typed `TooManyOffers`
/// BEFORE reaching this point, so only the raw signing-bytes path can trip the assert,
/// and only on the signer's OWN over-cap input (never attacker bytes, which go through
/// decode).
fn provide_body(record: &ProviderRecord) -> Vec<u8> {
    assert!(
        record.offers.len() <= MAX_OFFERS_PER_RECORD,
        "provide_body narrows offers.len() to a u8 on a SIGNED preimage; the {MAX_OFFERS_PER_RECORD}-offer cap must hold before signing"
    );
    let mut out = Vec::with_capacity(BODY_HEADER_LEN + BLAKE3_DIGEST_LEN + 1);
    out.extend_from_slice(&PROVIDER_RECORD_SCHEMA_VERSION.to_be_bytes());
    out.push(KIND_PROVIDE);
    out.extend_from_slice(record.key.as_bytes());
    out.extend_from_slice(record.provider.as_bytes());
    out.extend_from_slice(&record.sequence.to_be_bytes());
    out.extend_from_slice(&record.issued_at.to_be_bytes());
    out.extend_from_slice(&record.expiry.to_be_bytes());
    out.extend_from_slice(record.content.as_bytes());
    out.push(record.offers.len() as u8);
    for offer in &record.offers {
        write_offer(&mut out, offer);
    }
    out
}

/// The `body` of a Withdraw value.
fn withdraw_body(w: &ProviderWithdrawal) -> Vec<u8> {
    let mut out = Vec::with_capacity(BODY_HEADER_LEN);
    out.extend_from_slice(&PROVIDER_RECORD_SCHEMA_VERSION.to_be_bytes());
    out.push(KIND_WITHDRAW);
    out.extend_from_slice(w.key.as_bytes());
    out.extend_from_slice(w.provider.as_bytes());
    out.extend_from_slice(&w.sequence.to_be_bytes());
    out.extend_from_slice(&w.issued_at.to_be_bytes());
    out.extend_from_slice(&w.expiry.to_be_bytes());
    out
}

fn signing_preimage(body: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(SIGNING_DOMAIN.len() + body.len());
    m.extend_from_slice(SIGNING_DOMAIN);
    m.extend_from_slice(body);
    m
}

/// The EXACT bytes a provider must ed25519-sign to authenticate `record` (the frozen
/// preimage `SIGNING_DOMAIN || body`). The signature goes in [`ProviderRecord::signature`].
/// Public so a backend/announcer (TASK-103) signs with its own key material without
/// re-deriving the layout.
pub fn provider_record_signing_bytes(record: &ProviderRecord) -> Vec<u8> {
    signing_preimage(&provide_body(record))
}

/// The frozen preimage a provider must ed25519-sign to authenticate `withdrawal`.
pub fn provider_withdrawal_signing_bytes(withdrawal: &ProviderWithdrawal) -> Vec<u8> {
    signing_preimage(&withdraw_body(withdrawal))
}

fn check_encoded_size(len: usize) -> Result<(), RecordEncodeError> {
    if len > MAX_PROVIDER_RECORD_BYTES {
        Err(RecordEncodeError::Oversized {
            len,
            cap: MAX_PROVIDER_RECORD_BYTES,
        })
    } else {
        Ok(())
    }
}

/// Encode an already-signed [`ProviderRecord`] to its opaque wire bytes. Refuses to
/// EMIT an over-cap or oversize value (fail fast on the sender). Does NOT re-sign:
/// the `signature` field is written verbatim, so a caller signs
/// [`provider_record_signing_bytes`] first (or uses [`sign_provider_record`]).
pub fn encode_provider_record(record: &ProviderRecord) -> Result<Vec<u8>, RecordEncodeError> {
    check_provide_invariants(record)?;
    let mut out = provide_body(record);
    out.extend_from_slice(&record.signature);
    check_encoded_size(out.len())?;
    Ok(out)
}

/// Encode an already-signed [`ProviderWithdrawal`] to its opaque wire bytes.
pub fn encode_provider_withdrawal(
    withdrawal: &ProviderWithdrawal,
) -> Result<Vec<u8>, RecordEncodeError> {
    let mut out = withdraw_body(withdrawal);
    out.extend_from_slice(&withdrawal.signature);
    check_encoded_size(out.len())?;
    Ok(out)
}

/// Encode any [`ProviderAssertion`].
pub fn encode_provider_assertion(
    assertion: &ProviderAssertion,
) -> Result<Vec<u8>, RecordEncodeError> {
    match assertion {
        ProviderAssertion::Provide(r) => encode_provider_record(r),
        ProviderAssertion::Withdraw(w) => encode_provider_withdrawal(w),
    }
}

/// The sentinel `provider` a caller leaves in an unsigned record/withdrawal: all
/// zeros. `sign_*` sets the real provider from the key; a NON-zero provider that is
/// not the signer is a caller bug and fails fast in debug (see [`sign_provider_record`]).
const UNSET_PROVIDER: NodeId = NodeId::from_bytes([0u8; NODE_ID_LEN]);

/// Sign a [`ProviderRecord`] with `signing_key`, returning a copy whose `provider`
/// equals the key's verifying key and whose `signature` authenticates the frozen
/// preimage. The `provider` field is set FROM the key so the result is always
/// self-consistent (a record can only be signed by the identity it names).
///
/// FAIL FAST: the input's `provider` is OVERWRITTEN. To catch a caller who built a
/// record naming Alice and then signs it with Bob's key (silently yielding Bob's
/// record), a non-zero input `provider` that is not the signer's identity trips a
/// `debug_assert`. Leave `provider` as [`UNSET_PROVIDER`] (all zeros) in an unsigned
/// record, or set it to the signer's own id.
pub fn sign_provider_record(signing_key: &SigningKey, record: &ProviderRecord) -> ProviderRecord {
    let provider = NodeId::from_bytes(signing_key.verifying_key().to_bytes());
    debug_assert!(
        record.provider == UNSET_PROVIDER || record.provider == provider,
        "sign_provider_record overwrites `provider` with the signer's identity; a \
         non-zero provider that is not the signer is a caller bug (built for one \
         identity, signed by another)"
    );
    // Establish the offer-list invariants the decoder REQUIRES so the convenience path
    // cannot silently sign a record a peer would reject: iroh offers must be self-serve
    // (node == this signer), and offers are put in canonical (ascending) order. A
    // duplicate or a delegated iroh node is a caller bug and fails fast here.
    let mut offers = record.offers.clone();
    for offer in &offers {
        if let TransportOffer::Iroh { node } = offer {
            assert!(
                *node == provider,
                "sign_provider_record: an iroh offer must advertise the signer's own \
                 node id (v1 self-serve); delegation is not permitted"
            );
        }
    }
    offers.sort_by_key(offer_encoding);
    assert!(
        offers_are_canonical(&offers),
        "sign_provider_record: duplicate offers (identical wire encoding) are not permitted"
    );
    let mut signed = ProviderRecord {
        provider,
        offers,
        signature: [0u8; PROVIDER_SIGNATURE_LEN],
        ..record.clone()
    };
    let sig = signing_key.sign(&provider_record_signing_bytes(&signed));
    signed.signature = sig.to_bytes();
    signed
}

/// Sign a [`ProviderWithdrawal`] with `signing_key` (see [`sign_provider_record`] for
/// the `provider`-overwrite fail-fast contract).
pub fn sign_provider_withdrawal(
    signing_key: &SigningKey,
    withdrawal: &ProviderWithdrawal,
) -> ProviderWithdrawal {
    let provider = NodeId::from_bytes(signing_key.verifying_key().to_bytes());
    debug_assert!(
        withdrawal.provider == UNSET_PROVIDER || withdrawal.provider == provider,
        "sign_provider_withdrawal overwrites `provider` with the signer's identity; a \
         non-zero provider that is not the signer is a caller bug"
    );
    let mut signed = ProviderWithdrawal {
        provider,
        signature: [0u8; PROVIDER_SIGNATURE_LEN],
        ..withdrawal.clone()
    };
    let sig = signing_key.sign(&provider_withdrawal_signing_bytes(&signed));
    signed.signature = sig.to_bytes();
    signed
}

// -------------------------------------------------------------------------
// Decode.
// -------------------------------------------------------------------------

/// A bounds-checked forward byte reader that fails CLOSED (`Truncated`) the instant a
/// read would run past the end - never a silent partial read.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], RecordDecodeError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(RecordDecodeError::Truncated {
                need: n,
                have: self.buf.len() - self.pos,
            })?;
        if end > self.buf.len() {
            return Err(RecordDecodeError::Truncated {
                need: n,
                have: self.buf.len() - self.pos,
            });
        }
        let out = &self.buf[self.pos..end];
        self.pos = end;
        Ok(out)
    }
    fn u8(&mut self) -> Result<u8, RecordDecodeError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, RecordDecodeError> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().expect("2 bytes"),
        ))
    }
    fn u64(&mut self) -> Result<u64, RecordDecodeError> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().expect("8 bytes"),
        ))
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], RecordDecodeError> {
        Ok(self.take(N)?.try_into().expect("N bytes"))
    }
    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }
    fn is_empty(&self) -> bool {
        self.pos == self.buf.len()
    }
}

fn read_offer(r: &mut Reader) -> Result<TransportOffer, RecordDecodeError> {
    let tag = r.u8()?;
    match tag {
        OFFER_IROH => Ok(TransportOffer::Iroh {
            node: NodeId::from_bytes(r.array::<NODE_ID_LEN>()?),
        }),
        OFFER_BITTORRENT => {
            let version = r.u8()?;
            match version {
                INFOHASH_V1 => Ok(TransportOffer::BitTorrent {
                    infohash: InfoHash::V1(r.array::<20>()?),
                }),
                INFOHASH_V2 => Ok(TransportOffer::BitTorrent {
                    infohash: InfoHash::V2(r.array::<32>()?),
                }),
                other => Err(RecordDecodeError::BadInfoHash { version: other }),
            }
        }
        other => Err(RecordDecodeError::UnknownOffer { tag: other }),
    }
}

/// The ed25519 group order `L` in LITTLE-ENDIAN bytes (RFC 8032:
/// `L = 2^252 + 27742317777372353535851937790883648493`). A canonical signature scalar
/// `S` satisfies `S < L`.
const ED25519_ORDER_LE: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

/// Whether the signature's scalar `S` (the high 32 bytes, little-endian) is CANONICAL
/// (`S < L`). ed25519-dalek v3 `verify_strict` ALSO enforces `S < L` (so it rejects the
/// `S+L` malleability), as do libsodium and OpenSSL/`cryptography`. We check it EXPLICITLY
/// here anyway - defense in depth for an irreversible wire freeze: it PINS the canonical-S
/// policy in our own code (independent of the dalek version), gives a DISTINCT typed
/// rejection ([`RecordDecodeError::NonCanonicalSignature`]) separate from a plain bad
/// signature, and documents the invariant a second, non-dalek implementation must match.
/// Operates on public bytes, so a plain compare (not constant-time) is fine.
fn signature_scalar_is_canonical(sig_bytes: &[u8; 64]) -> bool {
    let s = &sig_bytes[32..64];
    // Little-endian compare S < L: scan from the most-significant byte down.
    for i in (0..32).rev() {
        if s[i] < ED25519_ORDER_LE[i] {
            return true;
        }
        if s[i] > ED25519_ORDER_LE[i] {
            return false;
        }
    }
    false // S == L is non-canonical.
}

fn verify(provider: &NodeId, body: &[u8], sig_bytes: &[u8; 64]) -> Result<(), RecordDecodeError> {
    // Explicit canonical-S check FIRST, so a non-canonical scalar gets its own precise
    // classification. `verify_strict` (below) also enforces S<L in dalek v3, so this is
    // defense in depth, not the sole guard - it pins the policy independently of the
    // dalek version and distinguishes "malleable scalar" from "wrong signature" in logs.
    if !signature_scalar_is_canonical(sig_bytes) {
        return Err(RecordDecodeError::NonCanonicalSignature);
    }
    let vk = VerifyingKey::from_bytes(provider.as_bytes())
        .map_err(|_| RecordDecodeError::BadProviderKey)?;
    let sig = Signature::from_bytes(sig_bytes);
    vk.verify_strict(&signing_preimage(body), &sig)
        .map_err(|_| RecordDecodeError::BadSignature)
}

/// Decode + fully VALIDATE an opaque ProviderRecord value (AC#4). `expected_key` is
/// the DHT storage key the value was fetched under (the SSOT anchor); `now` is the
/// current Unix time for the expiry gate.
///
/// ORDER IS DELIBERATE and each step is a fail-closed guard with a bite test:
/// oversize (before any parse / allocation) -> version -> kind -> fields -> offer cap
/// -> offers (iroh self-serve identity, then canonical order) -> no trailing bytes ->
/// canonical-S check -> signature verify (self-verifying via `provider`) -> key SSOT
/// match -> expiry. Parsing alone is never acceptance.
pub fn decode_provider_assertion(
    bytes: &[u8],
    expected_key: &ContentKey,
    now: u64,
) -> Result<ProviderAssertion, RecordDecodeError> {
    if bytes.len() > MAX_PROVIDER_RECORD_BYTES {
        return Err(RecordDecodeError::Oversized {
            len: bytes.len(),
            cap: MAX_PROVIDER_RECORD_BYTES,
        });
    }
    // The trailing 64 bytes are the signature; the rest is the signed body. A value
    // too short to hold even a header + signature is truncated.
    if bytes.len() < BODY_HEADER_LEN + PROVIDER_SIGNATURE_LEN {
        return Err(RecordDecodeError::Truncated {
            need: BODY_HEADER_LEN + PROVIDER_SIGNATURE_LEN,
            have: bytes.len(),
        });
    }
    let sig_start = bytes.len() - PROVIDER_SIGNATURE_LEN;
    let body = &bytes[..sig_start];
    let sig_bytes: [u8; PROVIDER_SIGNATURE_LEN] = bytes[sig_start..].try_into().expect("64 bytes");

    let mut r = Reader::new(body);
    let version = r.u16()?;
    if version != PROVIDER_RECORD_SCHEMA_VERSION {
        return Err(RecordDecodeError::UnknownVersion {
            found: version,
            expected: PROVIDER_RECORD_SCHEMA_VERSION,
        });
    }
    let kind = r.u8()?;
    let key = ContentKey::from_bytes(r.array()?);
    let provider = NodeId::from_bytes(r.array()?);
    let sequence = r.u64()?;
    let issued_at = r.u64()?;
    let expiry = r.u64()?;

    let assertion = match kind {
        KIND_PROVIDE => {
            let content = Blake3Digest::from_bytes(r.array()?);
            let offers_len = r.u8()? as usize;
            if offers_len > MAX_OFFERS_PER_RECORD {
                return Err(RecordDecodeError::TooManyOffers {
                    found: offers_len,
                    cap: MAX_OFFERS_PER_RECORD,
                });
            }
            let mut offers = Vec::with_capacity(offers_len);
            for _ in 0..offers_len {
                offers.push(read_offer(&mut r)?);
            }
            // Finding #3: an iroh offer must advertise the provider's OWN node id
            // (self-serve; v1 forbids delegation). This also transitively validates the
            // node is a valid ed25519 point, because `provider` is validated as a
            // verifying key below (BadProviderKey) and the node equals it.
            for offer in &offers {
                if let TransportOffer::Iroh { node } = offer
                    && node != &provider
                {
                    return Err(RecordDecodeError::IrohNodeNotProvider {
                        offer_node: *node,
                        provider,
                    });
                }
            }
            // Finding #2: offers must be STRICTLY ASCENDING by encoding (one signed
            // encoding per logical set; forbids duplicates). A non-canonical order whose
            // signature happens to verify is still a distinct malformed value.
            if !offers_are_canonical(&offers) {
                return Err(RecordDecodeError::OffersNotCanonical);
            }
            ProviderAssertion::Provide(ProviderRecord {
                key,
                content,
                provider,
                offers,
                sequence,
                issued_at,
                expiry,
                signature: sig_bytes,
            })
        }
        KIND_WITHDRAW => ProviderAssertion::Withdraw(ProviderWithdrawal {
            key,
            provider,
            sequence,
            issued_at,
            expiry,
            signature: sig_bytes,
        }),
        other => return Err(RecordDecodeError::UnknownKind { found: other }),
    };

    // Nothing may remain in the signed body after a complete value: a fixed layout
    // has exactly one length, so extra bytes are a smuggled field or a malformed
    // value (and, crucially, bytes the signer committed to that the fields do not
    // account for).
    if !r.is_empty() {
        return Err(RecordDecodeError::TrailingBytes {
            extra: r.remaining(),
        });
    }

    // The value is well-formed; now it must be AUTHENTIC, ADDRESSED-CORRECTLY, and
    // FRESH. Verify over the RAW received body (not a re-encode), so a signature is
    // checked against exactly the bytes on the wire.
    verify(&provider, body, &sig_bytes)?;
    if &key != expected_key {
        return Err(RecordDecodeError::WrongKey {
            expected: *expected_key,
            found: key,
        });
    }
    if expiry <= now {
        return Err(RecordDecodeError::Stale { expiry, now });
    }
    Ok(assertion)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content::NAR_HASH_LEN;

    // A deterministic test signer whose verifying key is a valid ed25519 point (so a
    // "good" record verifies) - the same seed everywhere so vectors are reproducible.
    fn signer() -> SigningKey {
        SigningKey::from_bytes(&[0x42u8; 32])
    }
    fn provider_of(sk: &SigningKey) -> NodeId {
        NodeId::from_bytes(sk.verifying_key().to_bytes())
    }
    fn a_key() -> ContentKey {
        ContentKey::derive_from_signed_nar_hash(&[0x11u8; NAR_HASH_LEN])
    }

    /// A fully-populated, correctly-signed provide over `key`, fresh at now<1000.
    fn good_record() -> (ProviderRecord, ContentKey) {
        let sk = signer();
        let key = a_key();
        let record = ProviderRecord {
            key,
            content: Blake3Digest::from_bytes([0xaa; BLAKE3_DIGEST_LEN]),
            provider: provider_of(&sk),
            offers: vec![
                TransportOffer::Iroh {
                    node: provider_of(&sk),
                },
                TransportOffer::BitTorrent {
                    infohash: InfoHash::V2([0xbb; 32]),
                },
            ],
            sequence: 7,
            issued_at: 100,
            expiry: 1_000,
            signature: [0u8; PROVIDER_SIGNATURE_LEN],
        };
        (sign_provider_record(&sk, &record), key)
    }

    #[test]
    fn provide_round_trips_and_verifies() {
        let (record, key) = good_record();
        let bytes = encode_provider_record(&record).expect("encode");
        let decoded = decode_provider_assertion(&bytes, &key, 500).expect("decode");
        assert_eq!(decoded, ProviderAssertion::Provide(record));
    }

    #[test]
    fn withdraw_round_trips_and_verifies() {
        let sk = signer();
        let key = a_key();
        let withdrawal = sign_provider_withdrawal(
            &sk,
            &ProviderWithdrawal {
                key,
                provider: provider_of(&sk),
                sequence: 9,
                issued_at: 200,
                expiry: 2_000,
                signature: [0u8; PROVIDER_SIGNATURE_LEN],
            },
        );
        let bytes = encode_provider_withdrawal(&withdrawal).expect("encode");
        let decoded = decode_provider_assertion(&bytes, &key, 500).expect("decode");
        assert_eq!(decoded, ProviderAssertion::Withdraw(withdrawal));
    }

    // --- fail-closed BITE tests (AC#4). Each crafts a value whose ONLY fault is the
    // guard under test, so removing that guard changes the result and fails the test.

    #[test]
    fn oversized_is_rejected_before_parse() {
        let big = vec![0u8; MAX_PROVIDER_RECORD_BYTES + 1];
        assert_eq!(
            decode_provider_assertion(&big, &a_key(), 0),
            Err(RecordDecodeError::Oversized {
                len: MAX_PROVIDER_RECORD_BYTES + 1,
                cap: MAX_PROVIDER_RECORD_BYTES,
            })
        );
    }

    #[test]
    fn truncated_is_rejected() {
        let (record, key) = good_record();
        let bytes = encode_provider_record(&record).unwrap();
        // Drop the last byte: the signature is now short, the body is one byte into
        // the signature - a truncated value however the split lands.
        let err = decode_provider_assertion(&bytes[..bytes.len() - 1], &key, 500);
        assert!(matches!(
            err,
            Err(RecordDecodeError::Truncated { .. }) | Err(RecordDecodeError::BadSignature)
        ));
        // A value shorter than a header+signature is unambiguously Truncated.
        assert!(matches!(
            decode_provider_assertion(&[0u8; 10], &key, 500),
            Err(RecordDecodeError::Truncated { .. })
        ));
    }

    #[test]
    fn unknown_version_is_rejected() {
        // Re-sign a body whose version word is 2, so the ONLY fault is the version:
        // signature is valid, key matches, not expired. Removing the version guard
        // would let this DECODE (proving the bite).
        let sk = signer();
        let key = a_key();
        let mut body = provide_body(&ProviderRecord {
            key,
            content: Blake3Digest::from_bytes([0xaa; BLAKE3_DIGEST_LEN]),
            provider: provider_of(&sk),
            offers: vec![],
            sequence: 1,
            issued_at: 0,
            expiry: 1_000,
            signature: [0u8; PROVIDER_SIGNATURE_LEN],
        });
        body[0..2].copy_from_slice(&2u16.to_be_bytes());
        let sig = sk.sign(&signing_preimage(&body));
        let mut wire = body;
        wire.extend_from_slice(&sig.to_bytes());
        assert_eq!(
            decode_provider_assertion(&wire, &key, 500),
            Err(RecordDecodeError::UnknownVersion {
                found: 2,
                expected: PROVIDER_RECORD_SCHEMA_VERSION,
            })
        );
    }

    #[test]
    fn unknown_kind_is_rejected() {
        let sk = signer();
        let key = a_key();
        let mut body = withdraw_body(&ProviderWithdrawal {
            key,
            provider: provider_of(&sk),
            sequence: 1,
            issued_at: 0,
            expiry: 1_000,
            signature: [0u8; PROVIDER_SIGNATURE_LEN],
        });
        body[2] = 9; // the kind byte
        let sig = sk.sign(&signing_preimage(&body));
        let mut wire = body;
        wire.extend_from_slice(&sig.to_bytes());
        assert_eq!(
            decode_provider_assertion(&wire, &key, 500),
            Err(RecordDecodeError::UnknownKind { found: 9 })
        );
    }

    #[test]
    fn unknown_offer_tag_is_rejected() {
        let sk = signer();
        let key = a_key();
        // One offer with an unknown transport tag (0x09), correctly signed so the
        // ONLY fault is the offer tag.
        let mut body = provide_body(&ProviderRecord {
            key,
            content: Blake3Digest::from_bytes([0xaa; BLAKE3_DIGEST_LEN]),
            provider: provider_of(&sk),
            offers: vec![],
            sequence: 1,
            issued_at: 0,
            expiry: 1_000,
            signature: [0u8; PROVIDER_SIGNATURE_LEN],
        });
        // Bump offers_len from 0 to 1 and append a bogus offer (tag 0x09 + 32 bytes).
        *body.last_mut().unwrap() = 1;
        body.push(0x09);
        body.extend_from_slice(&[0u8; 32]);
        let sig = sk.sign(&signing_preimage(&body));
        let mut wire = body;
        wire.extend_from_slice(&sig.to_bytes());
        assert_eq!(
            decode_provider_assertion(&wire, &key, 500),
            Err(RecordDecodeError::UnknownOffer { tag: 0x09 })
        );
    }

    #[test]
    fn too_many_offers_is_rejected() {
        let sk = signer();
        let key = a_key();
        // Craft the over-cap body BY HAND (not via provide_body, whose own cap assert
        // forbids >MAX offers on a signed preimage): a valid 0-offer body, then rewrite
        // the offers_len byte to MAX+1 and append that many iroh offers, then sign it.
        let mut body = provide_body(&ProviderRecord {
            key,
            content: Blake3Digest::from_bytes([0xaa; BLAKE3_DIGEST_LEN]),
            provider: provider_of(&sk),
            offers: vec![],
            sequence: 1,
            issued_at: 0,
            expiry: 1_000,
            signature: [0u8; PROVIDER_SIGNATURE_LEN],
        });
        *body.last_mut().unwrap() = (MAX_OFFERS_PER_RECORD + 1) as u8; // the offers_len byte
        for _ in 0..(MAX_OFFERS_PER_RECORD + 1) {
            body.push(0x00); // OFFER_IROH tag
            body.extend_from_slice(provider_of(&sk).as_bytes());
        }
        let sig = sk.sign(&signing_preimage(&body));
        let mut wire = body;
        wire.extend_from_slice(&sig.to_bytes());
        assert_eq!(
            decode_provider_assertion(&wire, &key, 500),
            Err(RecordDecodeError::TooManyOffers {
                found: MAX_OFFERS_PER_RECORD + 1,
                cap: MAX_OFFERS_PER_RECORD,
            })
        );
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        // A body with one stray byte after the offers, SIGNED over the extra byte too
        // (so the signature is valid). Only the trailing-bytes guard rejects it;
        // removing it would silently accept bytes the fields do not account for.
        let sk = signer();
        let key = a_key();
        let mut body = provide_body(&ProviderRecord {
            key,
            content: Blake3Digest::from_bytes([0xaa; BLAKE3_DIGEST_LEN]),
            provider: provider_of(&sk),
            offers: vec![],
            sequence: 1,
            issued_at: 0,
            expiry: 1_000,
            signature: [0u8; PROVIDER_SIGNATURE_LEN],
        });
        body.push(0xff); // stray trailing byte inside the signed body
        let sig = sk.sign(&signing_preimage(&body));
        let mut wire = body;
        wire.extend_from_slice(&sig.to_bytes());
        assert_eq!(
            decode_provider_assertion(&wire, &key, 500),
            Err(RecordDecodeError::TrailingBytes { extra: 1 })
        );
    }

    #[test]
    fn bad_signature_is_rejected() {
        let (record, key) = good_record();
        let mut bytes = encode_provider_record(&record).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01; // flip one signature bit
        assert_eq!(
            decode_provider_assertion(&bytes, &key, 500),
            Err(RecordDecodeError::BadSignature)
        );
    }

    #[test]
    fn bad_provider_key_is_rejected() {
        // Provider bytes that are not a valid ed25519 point. Craft a body with such a
        // provider and any signature; VerifyingKey::from_bytes fails first.
        let key = a_key();
        // 0xdf..df is a y-coordinate that ed25519 cannot decompress to a point, so
        // VerifyingKey::from_bytes rejects it (found by probing the curve). This makes
        // BadProviderKey a REACHABLE, distinct rejection ahead of signature checking.
        let bad_provider = NodeId::from_bytes([0xdfu8; NODE_ID_LEN]);
        let body = provide_body(&ProviderRecord {
            key,
            content: Blake3Digest::from_bytes([0xaa; BLAKE3_DIGEST_LEN]),
            provider: bad_provider,
            offers: vec![],
            sequence: 1,
            issued_at: 0,
            expiry: 1_000,
            signature: [0u8; PROVIDER_SIGNATURE_LEN],
        });
        let mut wire = body;
        wire.extend_from_slice(&[0u8; PROVIDER_SIGNATURE_LEN]);
        assert_eq!(
            decode_provider_assertion(&wire, &key, 500),
            Err(RecordDecodeError::BadProviderKey)
        );
    }

    #[test]
    fn wrong_key_is_rejected() {
        // A perfectly valid, signed record decoded under a DIFFERENT storage key. Only
        // the SSOT guard fires; removing it would let a record be replayed under any
        // key.
        let (record, _key) = good_record();
        let bytes = encode_provider_record(&record).unwrap();
        let other = ContentKey::from_bytes([0x99u8; 32]);
        assert_eq!(
            decode_provider_assertion(&bytes, &other, 500),
            Err(RecordDecodeError::WrongKey {
                expected: other,
                found: record.key,
            })
        );
    }

    #[test]
    fn stale_record_is_rejected() {
        let (record, key) = good_record(); // expiry = 1000
        let bytes = encode_provider_record(&record).unwrap();
        assert_eq!(
            decode_provider_assertion(&bytes, &key, 1_000),
            Err(RecordDecodeError::Stale {
                expiry: 1_000,
                now: 1_000,
            })
        );
        // ...and one second before expiry it still decodes.
        assert!(decode_provider_assertion(&bytes, &key, 999).is_ok());
    }

    #[test]
    fn the_wire_is_exactly_the_named_fields_and_nothing_else() {
        // AC#2 as a byte-count property: a fixed layout has exactly one length, so a
        // value carrying anything the layout does not name (an IP, a port, a relay
        // address, a StorePath, a second digest) would be LONGER than the sum of the
        // named fields. good_record() is header + content + offers_len + one iroh
        // offer + one bittorrent-v2 offer + signature.
        let (record, _key) = good_record();
        let bytes = encode_provider_record(&record).unwrap();
        let expected = BODY_HEADER_LEN            // version+kind+key+provider+seq+issued+expiry
            + BLAKE3_DIGEST_LEN                    // content
            + 1                                    // offers_len
            + (1 + NODE_ID_LEN)                    // iroh offer: tag + node
            + (1 + 1 + 32)                         // bittorrent v2 offer: tag + ver + 32
            + PROVIDER_SIGNATURE_LEN; // signature
        assert_eq!(
            bytes.len(),
            expected,
            "the value is exactly its named fields; any extra byte is a smuggled field"
        );
    }

    #[test]
    fn the_signing_domain_carries_the_schema_version() {
        // Finding #4: the record-codec version lives in TWO places - the numeric const
        // and the signing domain - that must bump together on a re-freeze. Tie them so
        // bumping one and forgetting the other fails here. (CONTENT_KEY_CONTEXT is a
        // SEPARATE freeze surface, versioned independently and pinned by its own
        // golden, so it is deliberately NOT tied to this number.)
        let suffix = format!("/v{PROVIDER_RECORD_SCHEMA_VERSION}\0");
        assert!(
            SIGNING_DOMAIN.ends_with(suffix.as_bytes()),
            "SIGNING_DOMAIN {:?} must end with {suffix:?}",
            std::str::from_utf8(SIGNING_DOMAIN)
        );
    }

    #[test]
    #[cfg(debug_assertions)]
    fn sign_helpers_reject_a_mismatched_provider_in_debug() {
        // The mismatched-provider guard in sign_* is a `debug_assert!` (the provider is
        // overwritten regardless, so it is a caller-hygiene check, not a security gate).
        // `debug_assert!` is a no-op under `--release`, so this test is compiled in ONLY
        // for debug builds - otherwise it fails under `cargo test --release` (round-3 #1).
        let sk = signer();
        let key = a_key();
        let built_for_someone_else = ProviderRecord {
            key,
            content: Blake3Digest::from_bytes([0xaa; BLAKE3_DIGEST_LEN]),
            provider: NodeId::from_bytes([0x01; NODE_ID_LEN]), // not the signer
            offers: vec![],
            sequence: 1,
            issued_at: 0,
            expiry: 1_000,
            signature: [0u8; PROVIDER_SIGNATURE_LEN],
        };
        let caught =
            std::panic::catch_unwind(|| sign_provider_record(&sk, &built_for_someone_else));
        assert!(
            caught.is_err(),
            "signing a record naming a non-signer provider must fail fast in debug"
        );
    }

    #[test]
    fn bittorrent_v1_offer_round_trips() {
        // Finding #5: a positive BitTorrent-v1 vector (20-byte infohash), so the v1
        // branch of the codec is exercised, not only v2.
        let sk = signer();
        let key = a_key();
        let record = sign_provider_record(
            &sk,
            &ProviderRecord {
                key,
                content: Blake3Digest::from_bytes([0xaa; BLAKE3_DIGEST_LEN]),
                provider: provider_of(&sk),
                offers: vec![TransportOffer::BitTorrent {
                    infohash: InfoHash::V1([0xcc; 20]),
                }],
                sequence: 3,
                issued_at: 0,
                expiry: 1_000,
                signature: [0u8; PROVIDER_SIGNATURE_LEN],
            },
        );
        let bytes = encode_provider_record(&record).expect("encode");
        assert_eq!(
            decode_provider_assertion(&bytes, &key, 500).expect("decode"),
            ProviderAssertion::Provide(record)
        );
    }

    #[test]
    fn bad_infohash_version_is_rejected() {
        // A bittorrent offer with an unknown infohash version byte (3), correctly signed
        // so the ONLY fault is the infohash-version guard (finding #5 bite).
        let sk = signer();
        let key = a_key();
        let mut body = provide_body(&ProviderRecord {
            key,
            content: Blake3Digest::from_bytes([0xaa; BLAKE3_DIGEST_LEN]),
            provider: provider_of(&sk),
            offers: vec![],
            sequence: 1,
            issued_at: 0,
            expiry: 1_000,
            signature: [0u8; PROVIDER_SIGNATURE_LEN],
        });
        *body.last_mut().unwrap() = 1; // offers_len = 1
        body.push(OFFER_BITTORRENT);
        body.push(3); // unknown infohash version
        body.extend_from_slice(&[0u8; 32]);
        let sig = sk.sign(&signing_preimage(&body));
        let mut wire = body;
        wire.extend_from_slice(&sig.to_bytes());
        assert_eq!(
            decode_provider_assertion(&wire, &key, 500),
            Err(RecordDecodeError::BadInfoHash { version: 3 })
        );
    }

    #[test]
    fn offers_out_of_canonical_order_are_rejected() {
        // Two offers SIGNED in descending order (bittorrent tag 0x01 before iroh tag
        // 0x00). The iroh node is the provider (identity guard passes) and the signature
        // is valid, so ONLY the canonical-order guard (finding #2) rejects it.
        let sk = signer();
        let key = a_key();
        let p = provider_of(&sk);
        let body = provide_body(&ProviderRecord {
            key,
            content: Blake3Digest::from_bytes([0xaa; BLAKE3_DIGEST_LEN]),
            provider: p,
            offers: vec![
                TransportOffer::BitTorrent {
                    infohash: InfoHash::V2([0xbb; 32]),
                },
                TransportOffer::Iroh { node: p },
            ],
            sequence: 1,
            issued_at: 0,
            expiry: 1_000,
            signature: [0u8; PROVIDER_SIGNATURE_LEN],
        });
        let sig = sk.sign(&signing_preimage(&body));
        let mut wire = body;
        wire.extend_from_slice(&sig.to_bytes());
        assert_eq!(
            decode_provider_assertion(&wire, &key, 500),
            Err(RecordDecodeError::OffersNotCanonical)
        );
    }

    #[test]
    fn duplicate_offers_are_rejected_as_non_canonical() {
        // Two IDENTICAL iroh offers: not strictly ascending, so rejected (finding #2).
        let sk = signer();
        let key = a_key();
        let p = provider_of(&sk);
        let body = provide_body(&ProviderRecord {
            key,
            content: Blake3Digest::from_bytes([0xaa; BLAKE3_DIGEST_LEN]),
            provider: p,
            offers: vec![
                TransportOffer::Iroh { node: p },
                TransportOffer::Iroh { node: p },
            ],
            sequence: 1,
            issued_at: 0,
            expiry: 1_000,
            signature: [0u8; PROVIDER_SIGNATURE_LEN],
        });
        let sig = sk.sign(&signing_preimage(&body));
        let mut wire = body;
        wire.extend_from_slice(&sig.to_bytes());
        assert_eq!(
            decode_provider_assertion(&wire, &key, 500),
            Err(RecordDecodeError::OffersNotCanonical)
        );
    }

    #[test]
    fn iroh_offer_node_not_provider_is_rejected() {
        // A single iroh offer whose node is NOT the provider, correctly signed, so ONLY
        // the self-serve identity guard (finding #3) rejects it.
        let sk = signer();
        let key = a_key();
        let stranger = NodeId::from_bytes([0x07; NODE_ID_LEN]);
        let body = provide_body(&ProviderRecord {
            key,
            content: Blake3Digest::from_bytes([0xaa; BLAKE3_DIGEST_LEN]),
            provider: provider_of(&sk),
            offers: vec![TransportOffer::Iroh { node: stranger }],
            sequence: 1,
            issued_at: 0,
            expiry: 1_000,
            signature: [0u8; PROVIDER_SIGNATURE_LEN],
        });
        let sig = sk.sign(&signing_preimage(&body));
        let mut wire = body;
        wire.extend_from_slice(&sig.to_bytes());
        assert_eq!(
            decode_provider_assertion(&wire, &key, 500),
            Err(RecordDecodeError::IrohNodeNotProvider {
                offer_node: stranger,
                provider: provider_of(&sk),
            })
        );
    }

    #[test]
    fn malleable_s_plus_l_signature_is_rejected_as_non_canonical() {
        // Finding #1: the S+L malleability. Adding L to a valid signature's scalar S
        // yields S+L with [S+L]B = [S]B, which a verifier that SKIPS the S<L range check
        // would accept. We add L to a valid signature and prove:
        //   (a) our decoder rejects it with the DISTINCT typed NonCanonicalSignature -
        //       our explicit S<L check fires before verify_strict. This is the BITE:
        //       remove `signature_scalar_is_canonical` and the classification changes to
        //       BadSignature (dalek's verifier catches it), failing this exact-match.
        //   (b) ed25519-dalek v3 verify_strict ALSO rejects S+L (it enforces S<L), so
        //       the malleable form is foreclosed at BOTH layers. Our explicit check pins
        //       the policy independently of the dalek version and gives the precise
        //       error, rather than being the sole line of defence.
        let sk = signer();
        let key = a_key();
        let rec = sign_provider_record(
            &sk,
            &ProviderRecord {
                key,
                content: Blake3Digest::from_bytes([0xaa; BLAKE3_DIGEST_LEN]),
                provider: provider_of(&sk),
                offers: vec![],
                sequence: 5,
                issued_at: 0,
                expiry: 1_000,
                signature: [0u8; PROVIDER_SIGNATURE_LEN],
            },
        );
        let wire = encode_provider_record(&rec).unwrap();
        let body_len = wire.len() - PROVIDER_SIGNATURE_LEN;
        let mut mal = wire.clone();
        let mut carry = 0u16;
        for i in 0..32 {
            let sum = rec.signature[32 + i] as u16 + ED25519_ORDER_LE[i] as u16 + carry;
            mal[body_len + 32 + i] = (sum & 0xff) as u8;
            carry = sum >> 8;
        }
        assert_eq!(carry, 0, "S+L overflowed 256 bits");
        assert_ne!(mal, wire, "S+L must differ from S");

        // (a) distinct typed rejection from our explicit canonical-S guard.
        assert_eq!(
            decode_provider_assertion(&mal, &key, 500),
            Err(RecordDecodeError::NonCanonicalSignature)
        );
        // (b) dalek verify_strict also rejects it (S<L is enforced by the verifier too).
        let vk = VerifyingKey::from_bytes(provider_of(&sk).as_bytes()).unwrap();
        let mut malsig = [0u8; 64];
        malsig.copy_from_slice(&mal[body_len..]);
        assert!(
            vk.verify_strict(
                &signing_preimage(&mal[..body_len]),
                &Signature::from_bytes(&malsig)
            )
            .is_err(),
            "dalek verify_strict must also reject S+L (it enforces S<L)"
        );
    }

    #[test]
    fn identity_forgery_small_order_key_is_rejected() {
        // Round-3 #2: a no-secret-key forgery. provider A = the small-order IDENTITY
        // point (01||00x31), signature R = identity, S = 0. The cofactorless equation
        // [0]B = R + [k]A holds (identity == identity), so a verifier that SKIPS the
        // small-order check ACCEPTS a record "signed" by an identity nobody controls.
        // verify_strict rejects small-order A -> BadSignature. VerifyingKey::from_bytes
        // accepts the identity encoding (it is a valid point), so this reaches - and is
        // caught by - the signature check, not BadProviderKey.
        let key = a_key();
        let mut identity = [0u8; NODE_ID_LEN];
        identity[0] = 0x01;
        let body = provide_body(&ProviderRecord {
            key,
            content: Blake3Digest::from_bytes([0xaa; BLAKE3_DIGEST_LEN]),
            provider: NodeId::from_bytes(identity),
            offers: vec![],
            sequence: 1,
            issued_at: 0,
            expiry: 1_000,
            signature: [0u8; PROVIDER_SIGNATURE_LEN],
        });
        let mut forged_sig = [0u8; PROVIDER_SIGNATURE_LEN];
        forged_sig[0] = 0x01; // R = identity, S = 0
        let mut wire = body;
        wire.extend_from_slice(&forged_sig);
        assert_eq!(
            decode_provider_assertion(&wire, &key, 500),
            Err(RecordDecodeError::BadSignature)
        );
    }
}
