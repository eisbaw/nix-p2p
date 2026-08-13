//! [`require_axes`] - the composition-root REQUIRED-axis assertion (TASK-144 AC#4).
//!
//! A [`PeerFabric`](crate::PeerFabric) reports each participation axis as `Some`/`None`
//! (`None` == this profile turned the axis off). Which axes a running node MUST have is a
//! PROFILE decision that lives ABOVE the seam: an iroh CONSUMER needs the fetch transfer
//! and (to dial a resolved provider) the node-locator; a libp2p CONSUMER additionally
//! needs the content [`ProviderDirectory`](crate::ProviderDirectory); a PROVIDER of either
//! backend needs the [`NarServer`](crate::NarServer) + the
//! [`AvailabilityAnnouncer`](crate::AvailabilityAnnouncer) on top.
//!
//! This is the resolution of the "Unsupported-ZST dilemma" the seam ADR names: an axis a
//! backend genuinely does not offer is honestly `None` (never a panicking stub), so the
//! ONLY safe place to turn a missing-but-required axis into a loud failure is the
//! composition root, at construction, BEFORE the first request. [`require_axes`] is that
//! single check: hand it the fabric and the profile's required axes and it fails fast,
//! naming every missing one, instead of letting a `None` surface as a confusing runtime
//! miss (a fetch that always falls back, a provider that announces then cannot serve).
//!
//! It lives in `peer-fabric` (not a backend) so the two per-backend composition roots
//! share ONE assertion and cannot drift on what "required" means.

use crate::fabric::PeerFabric;
use crate::ids::TransportTag;

/// A single participation axis a profile can REQUIRE of a fabric. Mirrors the
/// `Option`-accessor axes of [`PeerFabric`] plus the tag-keyed fetch axis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Axis {
    /// [`PeerFabric::provider_directory`] - global exact-key content discovery.
    ProviderDirectory,
    /// [`PeerFabric::announcer`] - availability publication.
    Announcer,
    /// [`PeerFabric::node_locator`] - node/address resolution.
    NodeLocator,
    /// A [`PeerFabric::transfer`] backend for this specific [`TransportTag`] (the fetch
    /// axis is tag-keyed, so "required" is per-tag: a claim's offer of this tag must have
    /// a registered transport).
    Transfer(TransportTag),
    /// [`PeerFabric::server`] - inbound serving.
    Server,
    /// [`PeerFabric::hold_query`] - direct named-key hold-query.
    HoldQuery,
    /// [`PeerFabric::local_peers`] - LAN peer discovery.
    LocalPeers,
}

impl Axis {
    /// Whether `fabric` currently offers this axis.
    fn present_in(self, fabric: &dyn PeerFabric) -> bool {
        match self {
            Axis::ProviderDirectory => fabric.provider_directory().is_some(),
            Axis::Announcer => fabric.announcer().is_some(),
            Axis::NodeLocator => fabric.node_locator().is_some(),
            Axis::Transfer(tag) => fabric.transfer(tag).is_some(),
            Axis::Server => fabric.server().is_some(),
            Axis::HoldQuery => fabric.hold_query().is_some(),
            Axis::LocalPeers => fabric.local_peers().is_some(),
        }
    }
}

impl std::fmt::Display for Axis {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Axis::ProviderDirectory => f.write_str("provider_directory"),
            Axis::Announcer => f.write_str("announcer"),
            Axis::NodeLocator => f.write_str("node_locator"),
            Axis::Transfer(tag) => write!(f, "transfer({tag})"),
            Axis::Server => f.write_str("server"),
            Axis::HoldQuery => f.write_str("hold_query"),
            Axis::LocalPeers => f.write_str("local_peers"),
        }
    }
}

/// A selected profile required one or more axes the constructed fabric does not offer.
/// Carries EVERY missing axis (not just the first) so one startup error names the whole
/// gap, not a peel-one-fix-one loop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissingAxes {
    /// The required axes the fabric returned `None`/unregistered for, in the order asked.
    pub missing: Vec<Axis>,
}

impl std::fmt::Display for MissingAxes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "fabric is missing required axis/axes: ")?;
        for (i, axis) in self.missing.iter().enumerate() {
            if i > 0 {
                f.write_str(", ")?;
            }
            write!(f, "{axis}")?;
        }
        Ok(())
    }
}

impl std::error::Error for MissingAxes {}

/// Assert `fabric` offers every axis in `required`, or fail fast with a [`MissingAxes`]
/// naming ALL the missing ones. The composition-root gate (AC#4): call it right after a
/// backend fabric is constructed and before it is used, so a profile that needs an axis
/// the backend does not offer is a loud startup error, never a silent runtime degrade.
pub fn require_axes(fabric: &dyn PeerFabric, required: &[Axis]) -> Result<(), MissingAxes> {
    let missing: Vec<Axis> = required
        .iter()
        .copied()
        .filter(|axis| !axis.present_in(fabric))
        .collect();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(MissingAxes { missing })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::fake::{FakeFabric, FakeNarTransfer};
    use crate::ids::NodeId;

    fn node() -> NodeId {
        NodeId::from_bytes([0x11; 32])
    }

    #[test]
    fn missing_axes_are_all_named_in_order() {
        // `upstream_only` offers no P2P axis; requiring several must report ALL of them,
        // in the order asked, not just the first.
        let fabric = FakeFabric::upstream_only(node());
        let err = require_axes(
            &fabric,
            &[
                Axis::ProviderDirectory,
                Axis::Transfer(TransportTag::Iroh),
                Axis::Server,
            ],
        )
        .expect_err("an upstream-only fabric is missing every required P2P axis");
        assert_eq!(
            err.missing,
            vec![
                Axis::ProviderDirectory,
                Axis::Transfer(TransportTag::Iroh),
                Axis::Server,
            ]
        );
        // The Display names each missing axis (so the startup error is actionable).
        let rendered = err.to_string();
        assert!(rendered.contains("provider_directory"), "{rendered}");
        assert!(rendered.contains("transfer(iroh)"), "{rendered}");
        assert!(rendered.contains("server"), "{rendered}");
    }

    #[test]
    fn a_registered_axis_passes_and_only_genuine_gaps_are_reported() {
        // Register just the Iroh transfer; that axis now passes.
        let fabric = FakeFabric::upstream_only(node())
            .with_transfer(Arc::new(FakeNarTransfer::new(TransportTag::Iroh)));
        require_axes(&fabric, &[Axis::Transfer(TransportTag::Iroh)])
            .expect("a registered transfer satisfies its axis");

        // A present axis is not reported; only the genuine gaps (a different transport
        // tag + a disabled Option axis) are, in the order asked.
        let err = require_axes(
            &fabric,
            &[
                Axis::Transfer(TransportTag::Iroh),
                Axis::Transfer(TransportTag::BitTorrent),
                Axis::ProviderDirectory,
            ],
        )
        .expect_err("only the Iroh transfer is registered");
        assert_eq!(
            err.missing,
            vec![
                Axis::Transfer(TransportTag::BitTorrent),
                Axis::ProviderDirectory
            ]
        );
    }
}
