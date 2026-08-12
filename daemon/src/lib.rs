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
pub mod narinfo_cache;
mod nixbase32;
pub mod rewrite;

// TASK-144 increment 1: the node-discovery / runtime / publication cluster and
// the generic process supervisor MOVED to the `fabric-iroh` backend crate (the
// iroh weld isolated behind the peer-fabric seam). They are re-exported here as
// crate-root modules so every existing `crate::iroh_runtime::...`,
// `crate::process_group::...` and `crate::pinned_http::...` path inside the
// daemon - and the flat `daemon::AddressLookupCapability`-style re-exports below
// (which name `iroh_runtime::{...}` etc.) - keep resolving unchanged. The only
// cross edge is daemon -> fabric-iroh; `transport_iroh` (the iroh-blobs transfer,
// still welded to the serving core) stays in this crate until increment 2.
pub use fabric_iroh::{
    iroh_node_lookup, iroh_node_record, iroh_publication, iroh_publication_authority, iroh_relay,
    iroh_runtime, pinned_http, process_group,
};
pub mod server;
pub mod source;
pub mod source_libp2p;
mod supply_catalog;
pub mod transport;
pub mod transport_fetch;
pub mod transport_iroh;
pub mod upstream;

pub use availability::{
    AnnounceSink, AvailabilityError, AvailabilityIndex, CommandNarDumper, DerivedNar, DumpError,
    IndexStore, JsonFileStore, MemoryNarDumper, NarDumper, NullAnnounce, NullStore, PersistError,
    RegularFileNarDumper, StorePath,
};
pub use cacheinfo::CacheInfo;
pub use catalog::{CorrelationStore, NarCatalog, NarMeta, NullCorrelation};
pub use claim::{
    BatchHoldAnswer, BatchHoldQuery, BatchHoldResponse, CLAIM_SCHEMA_VERSION, Claim,
    ClaimCodecError, ClaimSignature, HoldAnswer, HoldQuery, HoldResponse, KnownPayload,
    KnownTransport, MAX_BATCH_HOLD_KEYS, MAX_BATCH_HOLD_OFFERS, MAX_CLAIM_WIRE_BYTES, NAR_HASH_LEN,
    NAR_HASH_PREFIX, NarHashKey, NarHashKeyParseError, OfferIndex, QUERY_SCHEMA_VERSION,
    SignedNarinfoRelay, decode_batch_hold_query, decode_batch_hold_response, decode_claim,
    decode_hold_query, decode_hold_response, encode_batch_hold_query, encode_batch_hold_response,
    encode_claim, encode_hold_query, encode_hold_response,
};
pub use content_id::{
    BLAKE3_DIGEST_LEN, BLAKE3_DOMAIN_SEPARATION, BLAKE3_PREFIX, Blake3Digest, DigestParseError,
};
pub use discovery::{
    DirectDiscovery, Discovery, FallbackNarSource, InMemoryDiscovery, InProcessPeerQuery,
    PROBE_TIMEOUT, PeerQuery, PeerQueryError,
};
pub use iroh_node_lookup::{
    MAX_NODE_LOOKUP_TRACKED_IDS, NODE_LOOKUP_DEADLINE, NODE_LOOKUP_PROVENANCE,
    NODE_LOOKUP_SCHEDULER_GRACE, NODE_LOOKUP_SCHEMA, NODE_LOOKUP_SOURCE,
    NodeLookupAuthorityAuthorization, NodeLookupConfig, NodeLookupHandle, NodeLookupProvenance,
    NodeLookupResult, NodeLookupUnavailable, NodeLookupUnavailableKind,
};
pub use iroh_node_record::{
    IROH_RECORD_NAME, MAX_NODE_LOCATIONS, METADATA_RECORD_NAME, NODE_PUBLICATION_SCHEMA,
    NodeLocation, NodeRecord, NodeRecordError, NodeRecordErrorKind, PublicationState,
    decode_node_record, encode_node_record, validate_namespace, validate_recipient,
};
pub use iroh_publication::{
    NodePublicationCapability, NodePublicationConfig, NodePublicationHandle,
    PUBLICATION_STARTUP_DEADLINE, PUBLICATION_STATE_FILENAME, PUBLICATION_TRANSITION_DEADLINE,
    PublicationAuthorityAuthorization, PublicationError, PublicationErrorKind, PublicationReceipt,
};
pub use iroh_publication_authority::{
    AUTHORITY_STATE_FILENAME, AuthorityError, AuthoritySignerAdmission, PublicationAuthority,
    PublicationAuthorityConfig,
};
pub use iroh_relay::{
    RELAY_CONNECT_DEADLINE, RELAY_SCHEDULER_GRACE, RelayConnectionPath, RelayHealth,
    RelayPreflightStatus, RelayTransportAuthorization, RelayTransportConfig,
    RelayTransportUnavailable, RelayTransportUnavailableKind, classify_connection_path,
    redact_fingerprint,
};
pub use iroh_runtime::{
    AddressLookupCapability, EndpointCapabilityState, EndpointProfile, EndpointScope,
    IROH_IDENTITY_FILENAME, IROH_SHUTDOWN_DEADLINE, IdentitySource, IrohEndpointHandle,
    IrohNodeRuntime, IrohRuntimeBuilder, IrohRuntimeError, RelayCapability, ShutdownOutcome,
    TaskSupervisor, TaskSupervisorHandle,
};
pub use narinfo_cache::{Clock, NarinfoDiskCache, SystemClock};
pub use rewrite::{
    AllowlistRawServe, AnyRawServe, NoRawServe, RawRewrite, RawServeDecision, RewriteError, to_raw,
};
pub use server::{App, serve};
pub use source::{
    NarBody, NarHash, NarKey, NarPathToken, NarSource, NarinfoSource, RawUpstream, SourceError,
    StoreHash, UpstreamResponse,
};
pub use source_libp2p::{
    Libp2pNarSource, Libp2pRawServe, Libp2pSourceConfig, build_libp2p_nar_source,
    build_libp2p_provider_source, sign_libp2p_provider_record,
};
pub use supply_catalog::SupplyCatalogHandle;
pub use transport::{BitTorrentInfoHash, IROH_BLOBS_ALPN, NODE_ID_LEN, NodeId, NodeIdParseError};
pub use transport_fetch::{
    FakeTransport, FetchError, Transport, TransportError, TransportNarSource, TransportRegistry,
    TransportTag, fetch_via_offers, verify_blake3,
};
pub use transport_iroh::{
    BODY_IDLE_TIMEOUT, DEFAULT_MAX_INFLIGHT_NAR_BYTES, DEFAULT_MAX_SERVE_DURATION,
    DEFAULT_MAX_SERVE_NAR_BYTES, DIAL_TIMEOUT, FETCH_TIMEOUT, FileNarSupplier, IndexNarSupplier,
    IrohClientNode, IrohError, IrohNode, IrohNodeBuilder, IrohPeerAddr, IrohProvider,
    IrohProviderConfig, IrohProviderNode, IrohTransport, MemoryNarSupplier, NarSupplier,
    SafetyEnvelope, ServeBudget, ServeCounters, ServeDecline, ServeWindow, StoreResidency,
    StoreRetention, SupplyError, copy_regular_raw_nar, iroh_blobs_alpn, raw_nar_helper_authorized,
};
pub use upstream::UpstreamHttp;
