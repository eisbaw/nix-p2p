//! `peer-fabric` - the intention-level P2P seam for nix-p2p.
//!
//! This crate names WHAT the daemon wants of ANY peer substrate - find providers,
//! announce availability, locate a node, fetch a NAR, serve a NAR, ask a peer,
//! discover LAN peers - never HOW a stack does it. It carries **zero** iroh and
//! **zero** libp2p dependencies: that is the whole point (AC#8). iroh and libp2p
//! become *backends* behind this seam, each in its own future `fabric-*` crate, so
//! the backend is a compile-time selection (one backend per binary) and the serving
//! frontend stays stack-neutral by construction. See `docs/peer-fabric-seam.md` for
//! the full design and `PRD.md` for the durable decisions.
//!
//! ## What is here (TASK-140)
//!
//!   * the seven capability traits ([`ProviderDirectory`], [`AvailabilityAnnouncer`],
//!     [`NodeLocator`], [`NarTransfer`], [`NarServer`], [`PeerHoldQuery`],
//!     [`LocalPeerDiscovery`]) mapped to the PRD's six participation axes;
//!   * the umbrella [`PeerFabric`] (dynamic dispatch: `Option<Arc<dyn ...>>`
//!     accessors, `None` == this profile turned this axis off);
//!   * the 3-way [`Lookup`] outcome (MISS ≠ UNAVAILABLE) and its [`Unavailable`]
//!     reasons;
//!   * the single-sink [`ExposureLedger`] plus the a-priori [`ExposureSurface`];
//!   * the value types [`ContentKey`], [`ProviderRecord`], [`DialInfo`], and the
//!     canonical primitive newtypes [`NodeId`], [`Blake3Digest`], [`TransportTag`],
//!     [`TransportOffer`] (this crate is their canonical home; TASK-141 re-points
//!     the daemon at them and deletes its duplicates);
//!   * the budgets [`DiscoveryBudget`], [`AnnounceBudget`], [`SafetyEnvelope`],
//!     [`ServeBudget`];
//!   * a [`FakeFabric`] and one fake per axis, so the seam - and eventually the
//!     whole daemon-core - is unit-testable with no p2p stack linked.
//!
//! ## What is NOT here (TASK-141, the reconciliation)
//!
//! The concrete `IrohFabric`/`Libp2pFabric` backends, the feature-gated
//! `type Fabric = ...` alias / two per-backend binaries, the composition-root
//! assertion of a profile's required axes, and re-pointing the daemon's duplicate
//! value types at this crate. This crate is consumed by nobody yet; it exists
//! standalone and CAN be depended on.

mod budget;
mod capabilities;
mod codec;
mod content;
mod exposure;
mod fabric;
mod fake;
mod hexfmt;
mod ids;
mod outcome;
mod record_codec;
mod record_store;
mod require;

pub use budget::{AnnounceBudget, DiscoveryBudget, SafetyEnvelope, ServeBudget};
pub use capabilities::{
    AnnounceError, AvailabilityAnnouncer, HoldAnswer, HoldMisalignment, LocalPeerDiscovery,
    NarServer, NarTransfer, NodeLocator, PeerHoldQuery, PeerHoldReply, PeerHoldRequest,
    ProviderDirectory, Receipt, ServeError, ServeHandle, TransferError,
};
pub use codec::{
    ACCEPT_RAW, ACCEPT_RAW_AND_ZSTD, ACCEPT_ZSTD, BoundedZstdDecoder, CODEC_RAW, CODEC_ZSTD,
    CodecChoiceReason, DEFAULT_ZSTD_LEVEL, DecodeError, NoCommonCodec, ServeCodecPolicy,
    StreamingZstdEncoder, WireCodec, ZSTD_WINDOW_LOG_MAX, compress_zstd, negotiate_serve_codec,
};
pub use content::{
    CONTENT_KEY_CONTEXT, CONTENT_KEY_LEN, CONTENT_KEY_PREFIX, ContentKey, DialInfo, NAR_HASH_LEN,
    PROVIDER_SIGNATURE_LEN, ProviderRecord, ResolutionPolicy,
};
pub use exposure::{Disclosed, Exposure, ExposureLedger, ExposureSurface, Recipient};
pub use fabric::{PeerFabric, TransferRegistry};
pub use fake::{
    FakeAvailabilityAnnouncer, FakeFabric, FakeLocalPeerDiscovery, FakeNarServer, FakeNarTransfer,
    FakeNodeLocator, FakePeerHoldQuery, FakeProviderDirectory,
};
pub use ids::{
    BLAKE3_DIGEST_LEN, BLAKE3_DOMAIN_SEPARATION, BLAKE3_PREFIX, Blake3Digest, DigestParseError,
    InfoHash, InfoHashParseError, NODE_ID_LEN, NodeId, NodeIdParseError, STREAM_CHUNK_BYTES,
    TransportOffer, TransportTag,
};
pub use outcome::{Lookup, Unavailable};
pub use record_codec::{
    MAX_OFFERS_PER_RECORD, MAX_PROVIDER_RECORD_BYTES, PROVIDER_RECORD_SCHEMA_VERSION,
    ProviderAssertion, ProviderWithdrawal, RecordDecodeError, RecordEncodeError,
    decode_provider_assertion, encode_provider_assertion, encode_provider_record,
    encode_provider_withdrawal, provider_record_signing_bytes, provider_withdrawal_signing_bytes,
    sign_provider_record, sign_provider_withdrawal,
};
pub use record_store::{ApplyOutcome, ProviderRecordSet, SlotFloor};
pub use require::{Axis, MissingAxes, require_axes};
