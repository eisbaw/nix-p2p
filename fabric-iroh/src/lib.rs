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
//! ## What is NOT here yet (TASK-144 increment 2)
//!
//! The iroh-blobs NAR transfer/serve (`transport_iroh`) and the `IROH_BLOBS_ALPN`
//! constant are still in the daemon: `transport_iroh` is welded to the serving
//! core (`claim`/`transport_fetch`/`source`/`discovery`) and must be rewired onto
//! `peer_fabric::{NarTransfer, NarServer}` before it can move without dragging the
//! serving core along. The concrete `IrohFabric: PeerFabric` composition also
//! lands in increment 2.

pub mod iroh_node_lookup;
pub mod iroh_node_record;
pub mod iroh_publication;
pub mod iroh_publication_authority;
pub mod iroh_relay;
pub mod iroh_runtime;
pub mod pinned_http;
pub mod process_group;
