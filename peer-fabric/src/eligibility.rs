//! The mechanism-neutral PUBLICATION-ELIGIBILITY seam (TASK-100 AC#6).
//!
//! WHETHER a piece of content may be published at all is the single TASK-102 decision
//! (the `PublicNarAllowlist`): a public record may name only content established as
//! signed-public upstream. That decision lives ABOVE this seam. The allowlist is keyed
//! by the signed sha256 `NarHash`, which the frozen [`ProviderRecord`] deliberately no
//! longer carries - it carries the derived [`ContentKey`](crate::ContentKey) (a
//! deterministic `derive_key` of that same `NarHash`) and the BLAKE3 content id. A
//! seam-level authority COULD therefore consult a `ContentKey`-keyed view of the
//! decision at `admit(&record)` time; it is not wired that way today only because doing
//! so is a signature change across every publisher and its call sites (the filed
//! residual), so for now the shipped public path keeps enforcing on the pre-record
//! provision (`ApprovedPublicProvision`) where the `NarHash` is still in hand.
//!
//! What THIS seam adds is a mechanism-neutral CONTRACT that a PUBLISH-capable adapter
//! CONSUMES that decision: every [`AvailabilityAnnouncer`](crate::AvailabilityAnnouncer)
//! is CONSTRUCTED WITH a [`PublicationEligibility`] authority and consults it
//! fail-closed before it emits any record, so there is no announcer that does not
//! consume the decision, and a refusing authority makes a publish FAIL rather than
//! silently emit. The authority is an object the daemon supplies: the shipped public
//! path backs it with the `PublicNarAllowlist`; a LAN-isolated / consume-side path uses
//! [`AdmitAllPublication`] (allowlist filtering does not apply there - a distinct,
//! explicitly-named decision, never a silent bypass).
//!
//! This is the cooperative, adapter-level structural hook. It is NOT the wire oracle: a
//! malicious backend that lies is caught by the signed-record / packet oracles
//! (TASK-102/103), not here. Both exist on purpose.

use crate::content::ProviderRecord;

/// Why a publication was refused by the node's publication-eligibility decision. Typed
/// so a rejected publish tells an un-allowlisted record from a named policy refusal
/// (fail verbosely, never a silent drop).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IneligibleReason {
    /// The content is not established publishable by the single TASK-102 decision
    /// (absent from the `PublicNarAllowlist`). Fail-closed: absence rejects.
    NotAllowlisted,
    /// A named policy refusal (a profile forbids publication, a scope mismatch). The
    /// string is for the log; the variant is the actionable distinction.
    Refused(String),
}

impl std::fmt::Display for IneligibleReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IneligibleReason::NotAllowlisted => {
                f.write_str("content is not established publishable (not allowlisted)")
            }
            IneligibleReason::Refused(why) => write!(f, "publication refused: {why}"),
        }
    }
}

impl std::error::Error for IneligibleReason {}

/// The single publication-eligibility decision (TASK-102), as an object a PUBLISH-capable
/// adapter is CONSTRUCTED WITH and consults before emitting a record (AC#6). Implemented
/// ABOVE/AROUND the seam (the daemon's allowlist for the public path); the seam only
/// names the intention - "is this record allowed out?" - never how the decision is made.
///
/// Fail-closed by contract: [`admit`](PublicationEligibility::admit) returns `Err` to
/// REFUSE, and a refusal must stop the publish (the announcer maps it to
/// [`AnnounceError::Ineligible`](crate::AnnounceError::Ineligible) and emits nothing).
pub trait PublicationEligibility: Send + Sync {
    /// May `record` be published? `Ok(())` admits; `Err` REFUSES (fail-closed - the
    /// caller must not publish on an `Err`).
    fn admit(&self, record: &ProviderRecord) -> Result<(), IneligibleReason>;
}

/// An authority that admits EVERY record. For the LAN-isolated / consume-side paths
/// where the public allowlist does not apply, and for tests. EXPLICITLY named so its
/// use is a visible decision in a composition root, never a silent bypass: a reviewer
/// sees `AdmitAllPublication` and knows this adapter is intentionally unfiltered (its
/// records are gated by a different axis - LAN isolation - not the public allowlist).
pub struct AdmitAllPublication;

impl PublicationEligibility for AdmitAllPublication {
    fn admit(&self, _record: &ProviderRecord) -> Result<(), IneligibleReason> {
        Ok(())
    }
}

/// An authority that REFUSES every record (fail-closed). The safe default posture when
/// no eligibility decision is configured (matching TASK-102's disabled-by-default
/// stance: with no allowlist configured, a public publisher must REFUSE, not admit),
/// and the test double that proves a refusing authority stops a publish.
pub struct RefusePublication;

impl PublicationEligibility for RefusePublication {
    fn admit(&self, _record: &ProviderRecord) -> Result<(), IneligibleReason> {
        Err(IneligibleReason::NotAllowlisted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content::{CONTENT_KEY_LEN, ContentKey, PROVIDER_SIGNATURE_LEN};
    use crate::ids::{Blake3Digest, NodeId, TransportOffer};

    fn record() -> ProviderRecord {
        let provider = NodeId::from_bytes([0x33; 32]);
        ProviderRecord {
            key: ContentKey::from_bytes([0x01; CONTENT_KEY_LEN]),
            content: Blake3Digest::from_bytes([0x42; 32]),
            provider,
            offers: vec![TransportOffer::Iroh { node: provider }],
            sequence: 1,
            issued_at: 100,
            expiry: 200,
            signature: [0u8; PROVIDER_SIGNATURE_LEN],
        }
    }

    #[test]
    fn admit_all_admits_and_refuse_refuses() {
        assert!(AdmitAllPublication.admit(&record()).is_ok());
        assert_eq!(
            RefusePublication.admit(&record()),
            Err(IneligibleReason::NotAllowlisted),
            "the fail-closed authority refuses every record"
        );
    }
}
