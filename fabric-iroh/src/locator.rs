//! [`IrohNodeLocator`] - the PRD axis-2 [`NodeLocator`] on iroh's pkarr address lookup
//! (TASK-144). It wraps TASK-138's [`NodeLookupHandle`] - the narrow, signed NodeId ->
//! address resolver owned by the iroh node runtime - behind the stack-neutral seam, so the
//! serving core learns a provider's dial coordinates through public pkarr infrastructure
//! WITHOUT ever seeing an iroh address type: the resolved [`DialInfo`] carries opaque
//! location strings, reparsed inside the fabric when dialing.
//!
//! # `ResolutionPolicy` mapping (and its honest current limit)
//!
//!   * [`ResolutionPolicy::PublicInfrastructure`] - the active pkarr-over-DNS lookup. It
//!     discloses this node's interest to the DNS/pkarr infrastructure it queries (recorded
//!     to the fabric ledger BEFORE the consultation). Returns [`Lookup::Found`] with the
//!     resolved location strings, [`Lookup::Miss`] when the record resolves but names no
//!     usable current address (expired/withdrawn/no-dialable-candidate, or an empty
//!     candidate set), and [`Lookup::Unavailable`] when the mechanism could not be
//!     consulted (disabled/closed runtime, an authority connection failure, a malformed or
//!     untrusted record, or a deadline).
//!   * [`ResolutionPolicy::ExplicitPeersOnly`] - consult ONLY a statically configured peer
//!     address book, disclosing nothing. This backend has no such book, so an
//!     explicit-peers-only resolution has no source to answer from and returns
//!     [`Lookup::Miss`] with zero disclosure (matching `declared_exposure` = none for that
//!     policy). It is NOT a fabricated result - a node given no explicit peers genuinely
//!     knows no address. A real static per-peer address book is TASK-168.

use std::sync::Arc;

use async_trait::async_trait;
use peer_fabric::{
    DialInfo, Disclosed, Exposure, ExposureLedger, ExposureSurface, Lookup, NodeId, NodeLocator,
    Recipient, ResolutionPolicy, Unavailable,
};

use crate::iroh_node_lookup::{NodeLookupHandle, NodeLookupUnavailable, NodeLookupUnavailableKind};
use crate::iroh_node_record::NodeLocation;

/// The pkarr-backed [`NodeLocator`]. Holds the runtime's [`NodeLookupHandle`] to drive the
/// signed lookup and the shared [`ExposureLedger`] every capability appends to.
pub struct IrohNodeLocator {
    lookup: NodeLookupHandle,
    ledger: Arc<ExposureLedger>,
}

impl IrohNodeLocator {
    /// A locator driving `lookup`, recording disclosures to `ledger`.
    pub fn new(lookup: NodeLookupHandle, ledger: Arc<ExposureLedger>) -> Self {
        IrohNodeLocator { lookup, ledger }
    }

    /// The active pkarr resolution (PublicInfrastructure). Kept separate so the ledger
    /// disclosure and the outcome classification live in one place.
    async fn locate_via_pkarr(&self, node: &NodeId) -> Lookup<DialInfo> {
        // We are about to actually consult public pkarr/DNS infrastructure: record the
        // disclosure HERE, before the lookup, so a query that never runs cannot pollute
        // the ledger. A pkarr-over-DNS lookup reveals THIS node's participation to the DNS
        // resolver it contacts. HONEST GAP (identical to the libp2p locator's): it also
        // reveals the QUERIED target NodeId, but the frozen `peer_fabric::Disclosed` enum
        // models OUR disclosures + ContentKey and has no third-party-NodeId variant, so we
        // record the expressible `OurNodeId` disclosure (widening the enum is a frozen-seam
        // change under wire review, TASK-168).
        self.ledger
            .record(Exposure::new(Recipient::DnsResolver, Disclosed::OurNodeId));

        match self.lookup.resolve(*node).await {
            Ok(result) => {
                // The frozen seam treats DialInfo locations as OPAQUE strings; for iroh a
                // Direct candidate is a socket address and a Relay candidate is a relay
                // URL, both reparsed inside the fabric when dialing.
                let locations: Vec<String> = result
                    .candidates()
                    .iter()
                    .map(|candidate| match candidate {
                        NodeLocation::Direct(address) => address.to_string(),
                        NodeLocation::Relay(url) => url.clone(),
                    })
                    .collect();
                if locations.is_empty() {
                    // Resolved, but the record named no usable candidate: no address known
                    // right now (a healthy miss, not a could-not-consult).
                    Lookup::Miss
                } else {
                    Lookup::Found(DialInfo::new(locations))
                }
            }
            Err(unavailable) => map_unavailable(unavailable),
        }
    }
}

/// Classify a [`NodeLookupUnavailable`] into the 3-way [`Lookup`] outcome: an
/// authoritative "no current address" is a [`Lookup::Miss`] (fold to fallback); a deadline
/// or any mechanism/trust failure is a [`Lookup::Unavailable`] (could-not-consult).
fn map_unavailable(unavailable: NodeLookupUnavailable) -> Lookup<DialInfo> {
    match unavailable.kind() {
        // The lookup ran but the node has no usable current address (record expired,
        // withdrawn, or carrying no dialable candidate): a healthy authoritative absence.
        NodeLookupUnavailableKind::Expired
        | NodeLookupUnavailableKind::Withdrawn
        | NodeLookupUnavailableKind::NoDialableCandidate => Lookup::Miss,
        // The consultation timed out.
        NodeLookupUnavailableKind::Deadline => Lookup::Unavailable(Unavailable::DeadlineExceeded),
        // Everything else - the runtime is disabled/closed, an authority could not be
        // reached, a malformed/untrusted/replayed record, a mismatched namespace/recipient
        // /node-id, a bad signature, a clock rollback, a malformed queried id - is a
        // could-not-consult: we learned no trustworthy address, but not because the node
        // authoritatively has none.
        _ => Lookup::Unavailable(Unavailable::Backend(unavailable.message().to_string())),
    }
}

#[async_trait]
impl NodeLocator for IrohNodeLocator {
    async fn locate(&self, node: &NodeId, policy: &ResolutionPolicy) -> Lookup<DialInfo> {
        match policy {
            // No third party is consulted, so nothing is disclosed. This backend has no
            // explicit address book, so it genuinely knows no address (a clean Miss the
            // caller falls back on), never a fabricated hit.
            ResolutionPolicy::ExplicitPeersOnly => Lookup::Miss,
            ResolutionPolicy::PublicInfrastructure => self.locate_via_pkarr(node).await,
        }
    }

    fn declared_exposure(&self) -> ExposureSurface {
        // The a-priori exposure resolution WILL incur when enabled: a pkarr-over-DNS lookup
        // discloses this node's participation to the DNS resolver (the same disclosure the
        // active path records above; ExplicitPeersOnly would disclose nothing, but the
        // declared surface states the worst case the policy admits).
        ExposureSurface::from_exposures([Exposure::new(
            Recipient::DnsResolver,
            Disclosed::OurNodeId,
        )])
    }
}
