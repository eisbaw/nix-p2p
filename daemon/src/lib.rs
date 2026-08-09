//! nix-p2p product daemon: a transparent Nix binary-cache substituter whose
//! only cleverness is STRUCTURE (PRD wave 0).
//!
//! The daemon serves the tiny Nix binary-cache HTTP API - `nix-cache-info`,
//! `*.narinfo`, `nar/*` - passing signed metadata and NAR payloads through from
//! an upstream cache, behind two capability seams:
//!
//!   * [`NarinfoSource`] - narinfo lookup;
//!   * [`NarSource`] - NAR resolution by content identity to a verified stream.
//!
//! Both have a single [`UpstreamHttp`] impl in wave 1. The seam carries a TYPED
//! [`NarKey`] (a signed NarHash on the normal path, learned by correlating each
//! narinfo as it passes through - see [`catalog`]), which is exactly the key a
//! wave-2 iroh/p2p `NarSource` resolves. The trait boundary is frozen; what wave
//! 2 adds is the iroh impl and the narinfo URL rewrite, not a serving-layer
//! change. See [`source`] for the precise scope.
//!
//! This crate is a library + a thin binary so the in-process integration tests
//! can drive the real serving stack over loopback (`tests/`), the same code the
//! container harness (task-5) will drive over a socket.

pub mod availability;
mod body;
pub mod cacheinfo;
pub mod catalog;
pub mod claim;
pub mod content_id;
pub mod discovery;
mod hexfmt;
pub mod narinfo_cache;
mod nixbase32;
pub mod rewrite;
pub mod server;
pub mod source;
pub mod transport;
pub mod transport_fetch;
pub mod transport_iroh;
pub mod upstream;

pub use availability::{
    AnnounceSink, AvailabilityError, AvailabilityIndex, CommandNarDumper, DumpError, IndexStore,
    JsonFileStore, NarDumper, NullAnnounce, NullStore, PersistError, StorePath,
};
pub use cacheinfo::CacheInfo;
pub use catalog::{CorrelationStore, NarCatalog, NarMeta, NullCorrelation};
pub use claim::{
    CLAIM_SCHEMA_VERSION, Claim, ClaimCodecError, ClaimSignature, HoldAnswer, HoldQuery,
    HoldResponse, KnownPayload, KnownTransport, MAX_CLAIM_WIRE_BYTES, NAR_HASH_LEN,
    NAR_HASH_PREFIX, NarHashKey, NarHashKeyParseError, QUERY_SCHEMA_VERSION, SignedNarinfoRelay,
    decode_claim, decode_hold_query, decode_hold_response, encode_claim, encode_hold_query,
    encode_hold_response,
};
pub use content_id::{
    BLAKE3_DIGEST_LEN, BLAKE3_DOMAIN_SEPARATION, BLAKE3_PREFIX, Blake3Digest, DigestParseError,
};
pub use discovery::{
    DirectDiscovery, Discovery, FallbackNarSource, InMemoryDiscovery, InProcessPeerQuery,
    PROBE_TIMEOUT, PeerQuery, PeerQueryError,
};
pub use narinfo_cache::{Clock, NarinfoDiskCache, SystemClock};
pub use rewrite::{NoRawServe, RawRewrite, RawServeDecision, RewriteError, to_raw};
pub use server::{App, serve};
pub use source::{
    NarBody, NarHash, NarKey, NarPathToken, NarSource, NarinfoSource, RawUpstream, SourceError,
    StoreHash, UpstreamResponse,
};
pub use transport::{BitTorrentInfoHash, IROH_BLOBS_ALPN, NODE_ID_LEN, NodeId, NodeIdParseError};
pub use transport_fetch::{
    FakeTransport, FetchError, Transport, TransportError, TransportNarSource, TransportRegistry,
    TransportTag, fetch_via_offers, verify_blake3,
};
pub use transport_iroh::{
    FETCH_TIMEOUT, IrohError, IrohPeerAddr, IrohProvider, IrohTransport, iroh_blobs_alpn,
};
pub use upstream::UpstreamHttp;
