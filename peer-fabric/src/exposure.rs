//! The exposure model (AC#3): one cooperative sink for what the fabric discloses,
//! plus an a-priori surface each capability declares for preflight.
//!
//! ## One sink, written as it happens
//!
//! Every leak-capable capability appends the disclosures it makes to a SINGLE
//! [`ExposureLedger`] as they happen - there is no per-call `Vec<Exposure>` return
//! that a caller must remember to drain and merge. One sink means status/preflight
//! read exactly one place, and a capability cannot leak "off the books" by
//! forgetting to thread a return value up. The ledger uses `std::sync::Mutex` for
//! interior mutability so a `&self` capability can record without an async runtime.
//!
//! ## Cooperative, not adversarial - stated honestly
//!
//! The ledger is SELF-REPORTED: a capability records what it INTENDS to disclose.
//! It is the right instrument for "did an honest, correctly-implemented fabric emit
//! only the exposure its profile permits" (the TASK-120 preflight/status question),
//! and it is NOT a defence against a malicious or buggy backend that lies about its
//! own disclosures. The adversarial oracle is the packet/source-mutation guard
//! (TASK-132/103) that observes the wire, not this ledger. Both exist on purpose;
//! neither substitutes for the other.
//!
//! ## A-priori surface for preflight
//!
//! Before any traffic, TASK-120 preflight needs to know which recipients an ENABLED
//! capability WILL touch, to accept or reject a profile. Each leak-capable trait
//! answers [`declared_exposure`](crate::ProviderDirectory::declared_exposure)
//! returning an [`ExposureSurface`] - the set of [`Recipient`]s and [`Disclosed`]
//! items it may reach, computed from configuration, without doing anything.

use std::sync::Mutex;

/// WHO a disclosure reached. Aligned to the PRD's axis-6 "lookup leakage" recipient
/// list: an IP/NodeId/content key can be disclosed to any of these even when
/// publication and serving are off, which is why leakage is its own participation
/// axis and its own gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Recipient {
    /// A peer on the local network (mDNS/LAN discovery).
    LanPeer,
    /// A public tracker.
    Tracker,
    /// A DNS resolver (e.g. pkarr-over-DNS address resolution).
    DnsResolver,
    /// A relay used for connectivity.
    Relay,
    /// A DHT/Mainline participant.
    DhtNode,
    /// A bootstrap/entry service.
    Bootstrap,
}

/// WHAT was disclosed to a [`Recipient`]. The three things axis-6 is about: our own
/// dialable address, our own node identity, and which content key we asked about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Disclosed {
    /// Our own dialable address (an IP/relay location).
    OurAddress,
    /// Our own [`NodeId`](crate::NodeId).
    OurNodeId,
    /// A content key we looked up or announced.
    ContentKey,
}

/// One recorded disclosure: `disclosed` reached `to`. The unit both the ledger
/// (after the fact) and the [`ExposureSurface`] (a-priori) are built from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Exposure {
    /// Who received it.
    pub to: Recipient,
    /// What they received.
    pub disclosed: Disclosed,
}

impl Exposure {
    /// A disclosure of `disclosed` to `to`.
    pub fn new(to: Recipient, disclosed: Disclosed) -> Self {
        Exposure { to, disclosed }
    }
}

/// The SINGLE sink for actual disclosures (AC#3). Capabilities [`record`]
/// disclosures as they happen; preflight/status [`entries`] read them back. There
/// is exactly one of these per fabric (accessible via
/// [`PeerFabric::exposure_ledger`](crate::PeerFabric::exposure_ledger)), so there is
/// exactly one place to audit what a run disclosed.
///
/// [`record`](ExposureLedger::record) takes `&self` (interior mutability), so a
/// capability holding an `Arc<ExposureLedger>` writes to it without threading a
/// mutable borrow through the async call graph.
#[derive(Debug, Default)]
pub struct ExposureLedger {
    entries: Mutex<Vec<Exposure>>,
}

impl ExposureLedger {
    /// An empty ledger.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one disclosure as it happens. Append-only: the ledger is the history
    /// of what was disclosed, so nothing is ever removed or overwritten.
    pub fn record(&self, exposure: Exposure) {
        self.entries
            .lock()
            .expect("exposure ledger mutex poisoned")
            .push(exposure);
    }

    /// Record a batch of disclosures at once (e.g. every recipient a single lookup
    /// touched). Equivalent to calling [`record`](ExposureLedger::record) per item.
    pub fn record_all(&self, exposures: impl IntoIterator<Item = Exposure>) {
        let mut guard = self.entries.lock().expect("exposure ledger mutex poisoned");
        guard.extend(exposures);
    }

    /// Every disclosure recorded so far, in the order it happened.
    pub fn entries(&self) -> Vec<Exposure> {
        self.entries
            .lock()
            .expect("exposure ledger mutex poisoned")
            .clone()
    }

    /// How many disclosures have been recorded. `0` on a ledger that has disclosed
    /// nothing - the upstream_only invariant (AC#5) reads this.
    pub fn len(&self) -> usize {
        self.entries
            .lock()
            .expect("exposure ledger mutex poisoned")
            .len()
    }

    /// Whether nothing has been disclosed yet.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// The a-priori exposure surface of ONE enabled capability: which disclosures it
/// MAY make, computed from configuration before any traffic (AC#3). TASK-120
/// preflight unions the surfaces of a profile's enabled capabilities and checks the
/// result against what the profile permits, accepting or rejecting BEFORE the first
/// packet. A disabled axis contributes no surface (it is `None` on the fabric, so it
/// is never asked).
///
/// This is the INTENDED surface, the cooperative counterpart to the [`ExposureLedger`]'s
/// after-the-fact record; the same honesty caveat applies (see the module docs).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExposureSurface {
    surface: Vec<Exposure>,
}

impl ExposureSurface {
    /// An empty surface: a capability that discloses nothing (e.g. a
    /// [`NodeLocator`](crate::NodeLocator) restricted to an explicit peer list).
    pub fn none() -> Self {
        Self::default()
    }

    /// A surface built from the disclosures the capability may make.
    pub fn from_exposures(exposures: impl IntoIterator<Item = Exposure>) -> Self {
        ExposureSurface {
            surface: exposures.into_iter().collect(),
        }
    }

    /// The disclosures this capability may make.
    pub fn exposures(&self) -> &[Exposure] {
        &self.surface
    }

    /// Whether this capability declares no disclosure at all.
    pub fn is_empty(&self) -> bool {
        self.surface.is_empty()
    }

    /// The distinct recipients this capability may reach - the set TASK-120 checks a
    /// profile's leakage allowance against.
    pub fn recipients(&self) -> Vec<Recipient> {
        let mut seen = Vec::new();
        for exposure in &self.surface {
            if !seen.contains(&exposure.to) {
                seen.push(exposure.to);
            }
        }
        seen
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ledger_is_a_single_append_only_sink() {
        // AC#3: disclosures are written as they happen, to ONE sink, and read back
        // from that one place.
        let ledger = ExposureLedger::new();
        assert!(ledger.is_empty());

        ledger.record(Exposure::new(Recipient::DhtNode, Disclosed::ContentKey));
        ledger.record_all([
            Exposure::new(Recipient::Relay, Disclosed::OurAddress),
            Exposure::new(Recipient::Bootstrap, Disclosed::OurNodeId),
        ]);

        let entries = ledger.entries();
        assert_eq!(entries.len(), 3);
        assert_eq!(ledger.len(), 3);
        // Order is preserved (it is the disclosure history).
        assert_eq!(
            entries[0],
            Exposure::new(Recipient::DhtNode, Disclosed::ContentKey)
        );
        assert_eq!(
            entries[2],
            Exposure::new(Recipient::Bootstrap, Disclosed::OurNodeId)
        );
    }

    #[test]
    fn surface_declares_recipients_without_disclosing() {
        let surface = ExposureSurface::from_exposures([
            Exposure::new(Recipient::DhtNode, Disclosed::ContentKey),
            Exposure::new(Recipient::DhtNode, Disclosed::OurNodeId),
            Exposure::new(Recipient::Bootstrap, Disclosed::OurNodeId),
        ]);
        // Distinct recipients, de-duplicated, in declaration order.
        assert_eq!(
            surface.recipients(),
            vec![Recipient::DhtNode, Recipient::Bootstrap]
        );
        assert!(!surface.is_empty());
        assert!(ExposureSurface::none().is_empty());
    }
}
