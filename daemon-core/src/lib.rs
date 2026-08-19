//! `daemon-core` - the nix-p2p product daemon's STACK-NEUTRAL serving frontend.
//!
//! A transparent Nix binary-cache substituter whose only cleverness is STRUCTURE (PRD
//! wave 0). It serves the tiny Nix binary-cache HTTP API - `nix-cache-info`, `*.narinfo`,
//! `nar/*` - passing signed metadata and NAR payloads through from an upstream cache,
//! behind two capability seams:
//!
//!   * [`NarinfoSource`] - narinfo lookup;
//!   * [`NarSource`] - NAR resolution by content identity to a verified stream.
//!
//! ## Stack-neutral by construction (TASK-146, docs/peer-fabric-seam.md "Crate topology")
//!
//! This crate depends on `peer-fabric` (the P2P intention seam + frozen value types) and
//! `proc-supervisor` (generic task/subprocess supervision) ONLY. It has ZERO p2p-lib deps:
//! no iroh, no libp2p, no `fabric-*` backend crate. The decentralized content path is a
//! property of the SEAM ([`PeerFabricNarSource`] over `Arc<dyn PeerFabric>`), not of any
//! one stack, so the frontend compiles and unit-tests substrate-free against a
//! `peer_fabric::FakeFabric`.
//!
//! The product is a set of thin per-backend binaries, each `daemon-core` + exactly one
//! `fabric-*`: `daemon-libp2p` = daemon-core + fabric-libp2p; `daemon-iroh` = daemon-core +
//! fabric-iroh. Each binary constructs its fabric and calls [`run`]. Because a binary links
//! one backend, its dependency closure contains one stack - a real crate-graph guarantee,
//! not a content ratchet.

pub mod availability;
mod body;
pub mod cacheinfo;
pub mod catalog;
pub mod claim;
pub mod content_id;
pub mod derive_ledger;
pub mod discovery;
pub mod narinfo_cache;
mod nixbase32;
pub mod observ;
pub mod operator;
pub mod peer_source;
pub mod post_fetch;
pub mod profile_budget;
// Property-test support (TASK-112): the shared, determinism-controlled proptest
// runner used by the `prop_*` tests in `claim` and `narinfo_cache`. Test-only.
#[cfg(test)]
mod prop_support;
pub mod public_allowlist;
pub mod rewrite;
pub mod run;
pub mod server;
pub mod source;
mod supply_catalog;
pub mod transport;
pub mod upstream;

pub use availability::{
    AnnounceSink, AvailabilityError, AvailabilityIndex, CommandNarDumper, DerivedNar, DumpError,
    IndexStore, JsonFileStore, MAX_BATCH_DERIVE_WORK, MemoryNarDumper, NarDumper, NarHashMismatch,
    NullAnnounce, NullStore, PersistError, PersistedRegistration, RegularFileNarDumper, StorePath,
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
pub use derive_ledger::{DeriveAdmission, MonotonicClock, PeerDeriveLedger};
pub use discovery::{
    DirectDiscovery, Discovery, FallbackNarSource, InMemoryDiscovery, InProcessPeerQuery,
    PROBE_TIMEOUT, PeerQuery, PeerQueryError,
};
pub use narinfo_cache::{
    Clock, NARINFO_CACHE_FLAG_CONFLICT, NarinfoCacheChoice, NarinfoDiskCache, NarinfoLayer,
    PassThroughReason, SystemClock, build_narinfo_layer, resolve_narinfo_cache_dir,
};
pub use observ::{
    METRICS_PATH, NullStatusFacts, Observability, RuntimeMetrics, STATUS_PATH, StatusFactSnapshot,
    StatusFacts, serve_admin,
};
pub use operator::{
    ContractError, ContractRequest, DIAGNOSTICS_WARNING, DhtRole, LookupOutcome, Mechanism,
    MechanismState, MetricLabel, OperatorContract, PeerPath, PrivacyPolicy, ResourceCaps,
    SharingProfile, StatusInputs,
};
pub use profile_budget::{
    BudgetError, ENVELOPE_MAX_INFLIGHT_NAR_BYTES, ENVELOPE_MAX_SERVE_DURATION_NS,
    ENVELOPE_MAX_SINGLE_NAR_BYTES, EXPECTED_PROFILE_BUDGET_HASH, PROFILE_BUDGET_ARTIFACT_MISSING,
    PROFILE_BUDGET_ARTIFACT_PATH, ProfileBudget, ProfileBudgetArtifact,
    check_serve_ms_within_envelope, check_serve_within_envelope,
};
// The peer-fabric DeriveBudget POLICY type (mirrors ServeBudget); re-exported so the
// binaries construct a PeerDeriveLedger from their ResourceCaps (TASK-229).
pub use peer_fabric::DeriveBudget;
pub use peer_source::{PeerFabricNarSource, PeerFabricRawServe};
pub use post_fetch::PostFetchAnnounce;
pub use public_allowlist::{
    AllowlistPersistError, AllowlistStatus, LearnOutcome, PublicNarAllowlist, PublicNarClaim,
    PublicProofReject, PublicationRejected, TrustedKeyError, TrustedNarKeys, VerifiedPublicNar,
    derive_allowlist_mac_key, prove_public,
};
pub use rewrite::{
    AllowlistRawServe, AnyRawServe, NoRawServe, RawRewrite, RawServeDecision, RewriteError, to_raw,
};
pub use run::{RunConfig, run};
pub use server::{App, serve};
pub use source::{
    NarBody, NarHash, NarKey, NarPathToken, NarSource, NarinfoSource, RawUpstream, SourceError,
    StoreHash, UpstreamResponse,
};
pub use supply_catalog::{NarProductionSource, SupplyCatalogHandle, SupplyCatalogRecord};
pub use transport::{BitTorrentInfoHash, NODE_ID_LEN, NodeId, NodeIdParseError};
pub use upstream::{CONNECT_TIMEOUT_MS, HEADER_TIMEOUT_MS, UpstreamHttp};

// TransportTag is a peer-fabric value type; re-exported for consumers that had it via the
// daemon's former `transport_fetch` re-export. The daemon's own `Transport`/registry fetch
// path (the legacy iroh fetch layer) lives in the `daemon` composite crate, not here (it is
// pulled only by the iroh path; the libp2p path resolves through `PeerFabricNarSource`).
pub use peer_fabric::TransportTag;

// The generic task/subprocess supervisor lives in `proc-supervisor`; re-exported so the
// per-backend binaries can construct one (`TaskSupervisor::new`) and hand its handle to
// [`server::serve`] / [`run`] without naming the leaf crate directly.
pub use proc_supervisor::{SupervisedProcessOutput, TaskSupervisor, TaskSupervisorHandle};
