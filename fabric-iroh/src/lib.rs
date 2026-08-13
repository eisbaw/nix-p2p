//! `fabric-iroh` - the iroh BACKEND behind the `peer-fabric` seam.
//!
//! This crate isolates the daemon's iroh-welded machinery from the stack-neutral
//! serving frontend (`daemon-core`, TASK-145). The serving core holds ZERO iroh
//! types; the node runtime, node/address discovery and publication are welded to
//! iroh with no stack-neutral interface, so they live HERE, behind the seam, and
//! the frontend depends only on `peer-fabric`. See `docs/peer-fabric-seam.md`
//! "Crate topology": the only cross edge is `daemon -> fabric-iroh`; this crate
//! never depends on the daemon.
//!
//! ## What is here (TASK-144 increment 1)
//!
//! The node-discovery / runtime / publication cluster, moved verbatim from the
//! daemon (only `crate::transport::NodeId` re-pointed at `peer_fabric::NodeId`,
//! severing the last daemon-ward edge):
//!   * [`iroh_runtime`] - the daemon-owned iroh Endpoint runtime + task supervisor;
//!   * [`iroh_node_lookup`] - TASK-138 pkarr NodeId -> address lookup;
//!   * [`iroh_node_record`] - the signed node-record wire schema;
//!   * [`iroh_publication`] / [`iroh_publication_authority`] - TASK-137 routed
//!     node-address publication and its signing authority;
//!   * [`iroh_relay`] - relay-capability classification;
//!   * [`pinned_http`] - the pinned-cert HTTP client the publication path uses;
//!   * [`process_group`] - a generic process-group supervisor (NOT iroh-specific;
//!     it rides here for now because `iroh_runtime` needs it and the daemon's
//!     `availability` also uses it, so keeping it below both keeps the cut
//!     acyclic. It should migrate to a shared util / `daemon-core` when the
//!     frontend is split - see TASK-145).
//!
//! ## The iroh-blobs NAR transfer/serve (TASK-148 increment 2)
//!
//! [`transport_iroh`] - the iroh-blobs whole-NAR transfer + provider serve - now
//! lives here too. It was the last iroh module welded to the daemon serving core;
//! TASK-148/150 rewired it onto `peer_fabric::{NarTransfer, NarServer}` (with a real
//! [`ServeHandle`](peer_fabric::ServeHandle) whose drop tears the serve driver down),
//! severed its edges to `claim`/`transport_fetch`/`source`/`discovery`/`supply_catalog`
//! (the last via the CatalogProbe seam), and moved it below the seam. The iroh-specific
//! [`IROH_BLOBS_ALPN`] constant and its compile-time `iroh_blobs::ALPN` equality
//! assertion moved with it. The daemon keeps a thin `Transport`-trait BRIDGE onto this
//! module's native [`NarTransfer`](peer_fabric::NarTransfer) impl
//! (`daemon/src/transport_iroh_bridge.rs`), so the daemon fetch path is unchanged;
//! retiring that bridge for a PeerFabric `IrohNarSource` (as libp2p already does) is
//! TASK-144.
//!
//! ## The concrete `IrohFabric: PeerFabric` (TASK-144)
//!
//! [`fabric::IrohFabric`] wires these axes into an `Option<Arc<dyn Capability>>` struct,
//! symmetric with `fabric_libp2p::Libp2pFabric`: transfer (always), node_locator (iff
//! pkarr lookup runs, via [`locator::IrohNodeLocator`]) and server (iff a provider was
//! built) are `Some`; the content directory / announcer / hold-query / LAN axes are
//! honestly `None` because iroh offers no content-provider routing (that asymmetry is why
//! libp2p is the primary backend). The composition-root REQUIRED-axis assertion is
//! `peer_fabric::require_axes`. Retiring the daemon's `transport_iroh_bridge` for an
//! `IrohNarSource` over this fabric is the remaining daemon-side step (TASK-144 follow-up).

pub mod fabric;
pub mod iroh_node_lookup;
pub mod iroh_node_record;
pub mod iroh_publication;
pub mod iroh_publication_authority;
pub mod iroh_relay;
pub mod iroh_runtime;
pub mod locator;
pub mod pinned_http;
pub mod transport_iroh;

// TASK-146: `process_group` + the generic `TaskSupervisor` moved OUT of this backend
// into the stack-neutral `proc-supervisor` leaf crate, so `daemon-core` can reach them
// without depending on `fabric-iroh`. Re-exported here (and from `iroh_runtime`) so the
// daemon's existing `fabric_iroh::process_group` / `daemon::process_group` paths keep
// resolving unchanged until the daemon-core split repoints them at `proc_supervisor`.
pub use proc_supervisor::process_group;

// The frozen iroh-blobs ALPN + its compile-time `iroh_blobs::ALPN` cross-check live
// in `transport_iroh` (co-located with the iroh-blobs get-protocol that uses them);
// re-exported here so the daemon can name `fabric_iroh::IROH_BLOBS_ALPN` (TASK-148).
pub use transport_iroh::IROH_BLOBS_ALPN;

// The concrete `IrohFabric: PeerFabric` composition (TASK-144) + its pkarr-backed
// node-locator, so the daemon can name `fabric_iroh::{IrohFabric, IrohNodeLocator}`.
pub use fabric::IrohFabric;
pub use locator::IrohNodeLocator;
