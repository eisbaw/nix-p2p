//! The 3-way outcome of an exact-key consultation (AC#2).
//!
//! Every exact-key consultation on the seam returns [`Lookup<T>`], NOT
//! `Result<Option<T>, E>`. The distinction is the design point: healthy-absent
//! (`Miss`) and could-not-consult (`Unavailable`) are PEERS, not error-vs-ok. A
//! `Result<Option>` collapses them - `Ok(None)` cannot say whether the mechanism
//! ran to completion and found nothing, or never got a healthy answer at all. That
//! difference is load-bearing above the seam: a `Miss` is authoritative and a
//! consumer can trust "no provider here"; an `Unavailable` is not, so the same
//! consumer must NOT treat it as absence (it should fall back / retry, and it must
//! not cache a negative). Making it three variants makes "MISS only after a healthy
//! completed lookup" legible at the type level, so no caller can accidentally read
//! a transient failure as a definitive no.

use std::fmt;

/// The outcome of an exact-key consultation: a healthy completed lookup that found
/// something ([`Found`](Lookup::Found)), a healthy completed lookup that found
/// nothing ([`Miss`](Lookup::Miss)), or a lookup that could not complete healthily
/// ([`Unavailable`](Lookup::Unavailable)).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lookup<T> {
    /// The mechanism ran to completion and found `T`.
    Found(T),
    /// The mechanism ran to completion and authoritatively found nothing. A caller
    /// may trust this as absence.
    Miss,
    /// The mechanism could not produce a healthy answer. NOT absence - a caller
    /// must not read it as "no provider", and must not cache it as a negative.
    Unavailable(Unavailable),
}

impl<T> Lookup<T> {
    /// `true` only for [`Found`](Lookup::Found).
    pub fn is_found(&self) -> bool {
        matches!(self, Lookup::Found(_))
    }

    /// `true` only for [`Miss`](Lookup::Miss) - a healthy, authoritative absence.
    pub fn is_miss(&self) -> bool {
        matches!(self, Lookup::Miss)
    }

    /// `true` only for [`Unavailable`](Lookup::Unavailable) - a lookup that could
    /// not complete. Deliberately distinct from [`is_miss`](Lookup::is_miss): a
    /// consumer branches on the two differently (trust vs fall-back-and-retry).
    pub fn is_unavailable(&self) -> bool {
        matches!(self, Lookup::Unavailable(_))
    }

    /// The found value, or `None` for BOTH `Miss` and `Unavailable`. Provided as a
    /// convenience for the "I only want the value" call sites, but note it FLATTENS
    /// the very distinction this type exists to keep - use the variant directly
    /// where the miss/unavailable difference matters.
    pub fn found(self) -> Option<T> {
        match self {
            Lookup::Found(value) => Some(value),
            Lookup::Miss | Lookup::Unavailable(_) => None,
        }
    }
}

/// Why an exact-key consultation could not complete healthily. Distinct variants so
/// a log line and a policy decision can tell a transient bootstrap outage from a
/// routing shortfall from a deadline - "unavailable" alone is not actionable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unavailable {
    /// The bootstrap/entry infrastructure was unreachable, so the mechanism never
    /// entered the network. Transient; retrying once bootstrap is back may succeed.
    BootstrapOutage,
    /// A network partition cut this node off from the part of the keyspace that
    /// would answer. The answer may exist; this node cannot currently reach it.
    Partition,
    /// The consultation's budget deadline elapsed before a healthy answer arrived
    /// (see [`DiscoveryBudget`](crate::DiscoveryBudget)). NOT absence - the lookup
    /// was cut short, not completed.
    DeadlineExceeded,
    /// The routing table held too few reachable peers near the key to consider the
    /// lookup authoritative, so a `Miss` would be a lie. Distinct from `Partition`:
    /// the node is on the network, but under-populated for this key.
    InsufficientRouting,
    /// A backend-specific failure that does not map to the above, carried verbatim
    /// for the log. A catch-all, deliberately last so a caller pattern-matching the
    /// specific reasons handles them before falling here.
    Backend(String),
}

impl fmt::Display for Unavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Unavailable::BootstrapOutage => f.write_str("bootstrap infrastructure unreachable"),
            Unavailable::Partition => f.write_str("network partition from the answering keyspace"),
            Unavailable::DeadlineExceeded => f.write_str("consultation deadline exceeded"),
            Unavailable::InsufficientRouting => {
                f.write_str("too few reachable peers near the key to be authoritative")
            }
            Unavailable::Backend(why) => write!(f, "backend failure: {why}"),
        }
    }
}

impl std::error::Error for Unavailable {}

#[cfg(test)]
mod tests {
    use super::*;

    // AC#2: MISS and UNAVAILABLE are REPRESENTABLE as distinct, non-collapsible
    // outcomes - the property `Result<Option>` cannot express.
    #[test]
    fn miss_and_unavailable_are_distinct_representable_outcomes() {
        let found: Lookup<u32> = Lookup::Found(7);
        let miss: Lookup<u32> = Lookup::Miss;
        let unavailable: Lookup<u32> = Lookup::Unavailable(Unavailable::Partition);

        assert!(found.is_found() && !found.is_miss() && !found.is_unavailable());
        assert!(miss.is_miss() && !miss.is_found() && !miss.is_unavailable());
        assert!(unavailable.is_unavailable() && !unavailable.is_miss() && !unavailable.is_found());

        // The three are pairwise distinct values (not two flavours of one).
        assert_ne!(miss, unavailable);
        assert_ne!(Lookup::<u32>::Miss, Lookup::Found(0));

        // `found()` flattens BOTH non-found variants to None - which is exactly why
        // callers that care must branch on the variant, not on the Option.
        assert_eq!(found.clone().found(), Some(7));
        assert_eq!(miss.found(), None);
        assert_eq!(unavailable.found(), None);
    }

    #[test]
    fn unavailable_reasons_cover_the_required_set() {
        // AC#2: bootstrap-outage / partition / deadline / insufficient-routing.
        for reason in [
            Unavailable::BootstrapOutage,
            Unavailable::Partition,
            Unavailable::DeadlineExceeded,
            Unavailable::InsufficientRouting,
            Unavailable::Backend("dht returned an error".to_string()),
        ] {
            // Each renders a distinct, non-empty diagnostic (fail verbosely).
            assert!(!reason.to_string().is_empty());
        }
    }
}
