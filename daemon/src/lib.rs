//! nix-p2p product daemon (monolith / interim dual-stack build).
//!
//! TASK-146 split the stack-neutral serving FRONTEND into the `daemon-core` crate (serving
//! core, correlation, policy, budgets, rewrite, source/discovery orchestration + the generic
//! `PeerFabricNarSource`), which depends on `peer-fabric` + `proc-supervisor` ONLY. This
//! `daemon` crate is now the INTERIM composite that links BOTH backends (`fabric-iroh` +
//! `fabric-libp2p`) so the existing e2e harness (s6-p2p iroh + s7-libp2p) and every
//! integration test keep driving one binary during the transition. The clean per-backend
//! thin binaries are `daemon-libp2p` (daemon-core + fabric-libp2p, no iroh) and the deferred
//! `daemon-iroh` (TASK-145); see docs/peer-fabric-seam.md "Crate topology".
//!
//! It re-exports `daemon-core` wholesale (so `daemon::App`, `daemon::claim::…`, etc. resolve
//! unchanged), plus the iroh backend modules/types (`fabric-iroh`), the libp2p construction
//! (from the `daemon-libp2p` crate's lib), and two LOCAL orphan-rule bridges:
//! `transport_iroh_bridge` (`IrohTransport` -> daemon-core `Transport`) and
//! [`iroh_catalog_probe`] (`SupplyCatalogHandle` -> iroh `CatalogProbe`).

// The stack-neutral serving frontend. `daemon::App`, `daemon::serve`, `daemon::claim::…`,
// `daemon::TaskSupervisor` (re-exported by daemon-core from proc-supervisor), etc. all
// resolve through this one glob, matching the monolith's former public surface.
pub use daemon_core::*;

// The iroh BACKEND crate (TASK-144): the node-discovery / runtime / publication cluster and
// the iroh-blobs transfer/serve. Re-exported as crate-root modules so every existing
// `crate::iroh_runtime::…` / `crate::transport_iroh::…` path inside this binary and the flat
// `daemon::Foo` re-exports below keep resolving. The only cross edge is daemon -> fabric-iroh.
pub use fabric_iroh::{
    iroh_node_lookup, iroh_node_record, iroh_publication, iroh_publication_authority, iroh_relay,
    iroh_runtime, pinned_http, transport_iroh,
};

// The daemon's OWN `Transport`/`Discovery` fetch registry - the LEGACY iroh fetch path
// (`TransportNarSource`, `fetch_via_offers`, `TransportRegistry`). It stays in this composite
// (not `daemon-core`) because only the iroh path uses it: the libp2p path resolves through
// `daemon_core::PeerFabricNarSource`. Keeping the `Transport` trait local here also lets
// `transport_iroh_bridge` implement it for the foreign `IrohTransport` (orphan rule). It
// moves into `daemon-iroh` with the bridge when the iroh binary is split out (TASK-145).
pub mod transport_fetch;
// The iroh provider's `CatalogProbe` over the daemon-core supply catalog (LOCAL newtype:
// `CatalogProbe` and `SupplyCatalogHandle` are both foreign here, so the orphan rule needs a
// local wrapper, TASK-146).
pub mod iroh_catalog_probe;
// The daemon-side `Transport` impl for the iroh `IrohTransport` (a direct impl: `Transport`
// is local to this crate, `IrohTransport` foreign - orphan rule satisfied). Exports nothing.
mod transport_iroh_bridge;

// The frozen iroh-blobs ALPN is an iroh-specific value that lives in `fabric-iroh`; the
// stack-neutral `daemon-core::transport` no longer names it. Re-export it here so
// `daemon::IROH_BLOBS_ALPN` is unchanged for the iroh composition.
pub use fabric_iroh::IROH_BLOBS_ALPN;

pub use iroh_catalog_probe::IrohCatalogProbe;
// The legacy iroh fetch-registry surface (TransportTag comes via `daemon_core::*`).
pub use transport_fetch::{
    FakeTransport, FetchError, Transport, TransportError, TransportNarSource, TransportRegistry,
    fetch_via_offers, verify_blake3,
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
// NOTE: TaskSupervisor / TaskSupervisorHandle are re-exported via `daemon_core::*` (from
// proc-supervisor), NOT from iroh_runtime, so this block omits them to avoid a name clash.
pub use iroh_runtime::{
    AddressLookupCapability, EndpointCapabilityState, EndpointProfile, EndpointScope,
    IROH_IDENTITY_FILENAME, IROH_SHUTDOWN_DEADLINE, IdentitySource, IrohEndpointHandle,
    IrohNodeRuntime, IrohRuntimeBuilder, IrohRuntimeError, RelayCapability, ShutdownOutcome,
};
// The libp2p CONSTRUCTION now lives in the `daemon-libp2p` crate's lib (the SSOT shared with
// the primary thin binary); re-exported here so `daemon::Libp2pSourceConfig`,
// `daemon::build_libp2p_nar_source`, etc. and the integration tests are unchanged.
pub use daemon_libp2p::{
    AllowlistEligibility, AnnounceAfterFetchDoor, ApprovedPublicProvision, ApprovedPublicSeed,
    IDENTITY_SEED_FILENAME, InitialAnnounceConfig, LAN_SHARE_SCOPE_HINT, LanReachability, LanShare,
    Libp2pAnnounceAfterFetch, Libp2pCatalogProbe, Libp2pNarSource, Libp2pRawServe,
    Libp2pSourceConfig, PublicationPlan, SeedNarHashMismatch, StoreProvision,
    announce_provider_seeds, announce_public_provisions, announce_public_seeds,
    announce_store_provisions, approve_provisions_for_public, approve_seeds_for_public,
    build_libp2p_nar_source, build_libp2p_provider_source, disclose_then_activate_serve,
    effective_network_scope, lan_isolation_or_refuse, lan_serving_disclosures,
    listen_addr_is_private_lan, open_public_allowlist, provider_content_key,
    resolve_durable_identity_seed, should_hint_lan_share_scope, sign_libp2p_provider_record,
    sign_libp2p_store_record, verify_provider_seeds, verify_store_provisions,
};
pub use transport_iroh::{
    BODY_IDLE_TIMEOUT, DEFAULT_MAX_INFLIGHT_NAR_BYTES, DEFAULT_MAX_SERVE_DURATION,
    DEFAULT_MAX_SERVE_NAR_BYTES, DIAL_TIMEOUT, FETCH_TIMEOUT, FileNarSupplier, IndexNarSupplier,
    IrohClientNode, IrohError, IrohNode, IrohNodeBuilder, IrohPeerAddr, IrohProvider,
    IrohProviderConfig, IrohProviderNode, IrohTransport, MemoryNarSupplier, NarSupplier,
    SafetyEnvelope, ServeBudget, ServeCounters, ServeDecline, ServeWindow, StoreResidency,
    StoreRetention, SupplyError, copy_regular_raw_nar, iroh_blobs_alpn, raw_nar_helper_authorized,
};
