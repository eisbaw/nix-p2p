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
mod content;
mod exposure;
mod fabric;
mod fake;
mod ids;
mod outcome;

pub use budget::{AnnounceBudget, DiscoveryBudget, SafetyEnvelope, ServeBudget};
pub use capabilities::{
    AnnounceError, AvailabilityAnnouncer, HoldAnswer, HoldMisalignment, LocalPeerDiscovery,
    NarServer, NarSupplier, NarTransfer, NodeLocator, PeerHoldQuery, PeerHoldReply,
    PeerHoldRequest, ProviderDirectory, Receipt, ServeError, ServeHandle, TransferError,
};
pub use content::{
    CONTENT_KEY_LEN, CONTENT_KEY_PREFIX, ContentKey, DialInfo, PROVIDER_SIGNATURE_LEN,
    ProviderRecord, ResolutionPolicy,
};
pub use exposure::{Disclosed, Exposure, ExposureLedger, ExposureSurface, Recipient};
pub use fabric::{PeerFabric, TransferRegistry};
pub use fake::{
    FakeAvailabilityAnnouncer, FakeFabric, FakeLocalPeerDiscovery, FakeNarServer, FakeNarTransfer,
    FakeNodeLocator, FakePeerHoldQuery, FakeProviderDirectory,
};
pub use ids::{
    BLAKE3_DIGEST_LEN, BLAKE3_PREFIX, Blake3Digest, InfoHash, NODE_ID_LEN, NodeId, TransportOffer,
    TransportTag,
};
pub use outcome::{Lookup, Unavailable};
