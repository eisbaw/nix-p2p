//! The mechanism-bound types the seam hands a capability (AC#7: policy stays ABOVE
//! the seam).
//!
//! The daemon decides the NUMBERS (eligibility, profile, TASK-120 budgets); the
//! fabric only enforces the bound it is handed. These types are those bounds. The
//! [`SafetyEnvelope`] and [`ServeBudget`] shapes deliberately mirror the daemon's
//! (`daemon::transport_iroh`), because they are the exact bounds the transfer and
//! serve axes already enforce; TASK-141 reconciles the daemon onto these. This
//! crate does NOT pick production values - a `Default` is a provisional convenience
//! for tests, and the authoritative numbers are TASK-120's.

use std::time::Duration;

/// Bound on an exact-key consultation ([`ProviderDirectory::find_providers`],
/// [`PeerHoldQuery::ask_holds`]). A deadline overrun surfaces as
/// [`Unavailable::DeadlineExceeded`](crate::Unavailable::DeadlineExceeded) - a
/// lookup cut short, never a `Miss`.
///
/// [`max_peers`] caps how many peers a lookup may consult, so a single consultation
/// cannot fan out unboundedly (a routing/exposure bound, not just a latency one).
/// The full total-deadline/concurrency policy is TASK-106; this is the shape it fills.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiscoveryBudget {
    /// The wall-clock deadline for the whole consultation.
    pub deadline: Duration,
    /// The maximum number of peers the consultation may touch.
    pub max_peers: u32,
}

impl DiscoveryBudget {
    /// A budget with an explicit deadline and peer cap.
    pub fn new(deadline: Duration, max_peers: u32) -> Self {
        DiscoveryBudget {
            deadline,
            max_peers,
        }
    }
}

impl Default for DiscoveryBudget {
    /// A provisional test-convenience default (NOT an authoritative policy number;
    /// TASK-120/106 own those).
    fn default() -> Self {
        DiscoveryBudget {
            deadline: Duration::from_secs(5),
            max_peers: 16,
        }
    }
}

/// Bound on an availability announcement ([`AvailabilityAnnouncer::announce`]).
/// Separate from [`DiscoveryBudget`] because publication is a different
/// participation axis (PRD axis 4) with its own budget and its own exposure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnnounceBudget {
    /// The wall-clock deadline for the publish operation.
    pub deadline: Duration,
    /// How many replica nodes the record may be pushed to, bounding the publish
    /// fan-out (and thus its exposure and cost).
    pub max_replicas: u32,
}

impl AnnounceBudget {
    /// A budget with an explicit deadline and replica cap.
    pub fn new(deadline: Duration, max_replicas: u32) -> Self {
        AnnounceBudget {
            deadline,
            max_replicas,
        }
    }
}

impl Default for AnnounceBudget {
    /// A provisional test-convenience default (NOT an authoritative policy number).
    fn default() -> Self {
        AnnounceBudget {
            deadline: Duration::from_secs(10),
            max_replicas: 20,
        }
    }
}

/// The three time bounds of the FETCH safety envelope, handed to
/// [`NarTransfer::fetch`](crate::NarTransfer::fetch) so a dead/stalled holder yields
/// a BOUNDED abort rather than a hang (PRD S2). Mirrors
/// `daemon::transport_iroh::SafetyEnvelope`; TASK-141 reconciles the daemon onto
/// this. The provisional v1 floor (PRD: 10 s dial, 10 s body idle, 60 s total) is
/// the [`Default`]; TASK-44 may only replace it with an at-least-as-safe frozen
/// policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SafetyEnvelope {
    /// Bound on `connect()` (the dead-holder guard).
    pub dial_timeout: Duration,
    /// Bound on the gap between successive body chunks (the stall guard).
    pub body_idle_timeout: Duration,
    /// Coarse backstop over the whole dial+transfer.
    pub total_timeout: Duration,
}

impl Default for SafetyEnvelope {
    fn default() -> Self {
        SafetyEnvelope {
            dial_timeout: Duration::from_secs(10),
            body_idle_timeout: Duration::from_secs(10),
            total_timeout: Duration::from_secs(60),
        }
    }
}

/// The numeric bound on what SERVING may cost, handed to
/// [`NarServer::serve`](crate::NarServer::serve). Both byte fields are in NarSize
/// units - UNCOMPRESSED NAR bytes, the addressed unit - NEVER the compressed
/// FileSize a narinfo carries (the recurring unit trap). Mirrors
/// `daemon::transport_iroh::ServeBudget`; TASK-141 reconciles the daemon onto this.
/// The PRD-inherited v1 ceilings (256 MiB single, 1 GiB in-flight, 120 s) are the
/// [`Default`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServeBudget {
    /// Above this, a single blob is DECLINED rather than allocated.
    pub max_nar_bytes_uncompressed_nar: u64,
    /// Above this total across concurrently-admitted serves, a further request is
    /// DECLINED rather than admitted.
    pub max_inflight_bytes_uncompressed_nar: u64,
    /// How long one serve may hold its reservation before it is reclaimed.
    pub max_serve_duration: Duration,
}

impl Default for ServeBudget {
    fn default() -> Self {
        ServeBudget {
            max_nar_bytes_uncompressed_nar: 256 * 1024 * 1024,
            max_inflight_bytes_uncompressed_nar: 1024 * 1024 * 1024,
            max_serve_duration: Duration::from_secs(120),
        }
    }
}

/// The numeric bound on what RESPONDER DERIVATION may cost - the hashing analog of
/// [`ServeBudget`] (TASK-229). Where [`ServeBudget`] bounds bytes SERVED, this bounds
/// bytes HASHED: answering a peer's hold-query for a COLD path costs one
/// `nix-store --dump` + BLAKE3 of the whole uncompressed NAR, so an unbounded stream
/// of hold-query probes is a responder-side derivation-DoS the serve budget does not
/// touch. This is the RECEIVER-SIDE admission bound a responder applies BEFORE it
/// dumps: a probe whose NarSize would exceed the remaining allowance is refused
/// (answered `Absent`, the safe direction) with NO dump.
///
/// Every field is an INTEGER (owner no-floats rule). The two byte fields are NarSize
/// units - UNCOMPRESSED NAR bytes, the exact hashing-work unit - NEVER the compressed
/// FileSize a narinfo carries (the recurring unit trap). The allowance is a TUMBLING
/// [`window`](DeriveBudget::window): usage accrues within a window and resets WHOLLY at
/// the boundary, so `bytes/window` and `dumps/window` are integer rate bounds of `cap`
/// per window in steady state — with up to 2x cap across a boundary (full cap just
/// before the reset, full cap just after); a true sliding window is deferred to TASK-243.
///
/// KEYED BY THE AUTHENTICATED REMOTE PEER. The per-peer fields bound ONE authenticated
/// peer's aggregate derivation over the window; the fabric hands the responder the
/// cryptographic connection identity (the libp2p `PeerId` / iroh [`NodeId`](crate::NodeId),
/// the same 32-byte ed25519 key) so the bound is on a self-declared field.
///
/// THE GLOBAL CEILING IS THE SYBIL FLOOR. A per-peer bound alone is bypassable by
/// minting many PeerIds, so [`max_bytes_global_uncompressed_nar`](DeriveBudget::max_bytes_global_uncompressed_nar)
/// caps the aggregate across ALL peers within the window as the responder's own last
/// line of defence. It is NOT a full Sybil defence (that is TASK-205's domain, e.g.
/// per-source-subnet accounting); it is the backstop that keeps a many-identity flood
/// bounded regardless.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeriveBudget {
    /// Per-authenticated-peer ceiling on NarSize BYTES hashed within one
    /// [`window`](DeriveBudget::window). A cold probe whose NarSize would push this
    /// peer's window total over the cap is refused BEFORE dumping.
    pub max_bytes_per_peer_uncompressed_nar: u64,
    /// Per-authenticated-peer ceiling on the COUNT of fresh dumps within one window.
    /// Bounds many-small-NAR floods that stay under the byte cap.
    pub max_dumps_per_peer: u32,
    /// GLOBAL ceiling on NarSize BYTES hashed across ALL peers within one window - the
    /// Sybil floor (per-peer alone is bypassable by minting PeerIds).
    pub max_bytes_global_uncompressed_nar: u64,
    /// GLOBAL ceiling on the COUNT of fresh dumps across ALL peers within one window - the
    /// dump-count Sybil floor. Without it, a flood of freshly-minted PeerIds each serving TINY
    /// NARs defeats the per-peer [`max_dumps_per_peer`](DeriveBudget::max_dumps_per_peer) cap while
    /// staying under the global BYTE ceiling (many small dumps ~= few global bytes). Bounds the
    /// aggregate dump EXECUTIONS regardless of how many identities are minted (TASK-297 MED-7a).
    pub max_dumps_global: u32,
    /// The accounting window. A typed carrier of an INTEGER millisecond value (owner
    /// no-floats rule); never fractional. The enforcer clamps a zero/sub-millisecond
    /// value UP to a sane floor (fail-closed, so a degenerate window cannot disable
    /// aggregation). HONEST BOUND: the enforcer uses a TUMBLING window (it resets wholly
    /// at the boundary), so the effective ceiling is `cap` per window in steady state
    /// with up to `2*cap` across a single boundary - a coarse rate limit, NOT a tight
    /// sliding-window cap. A true sliding window is TASK-243.
    pub window: Duration,
}

impl Default for DeriveBudget {
    /// Provisional test-convenience defaults (NOT authoritative policy numbers;
    /// TASK-120's `ResourceCaps` owns those). Conservative placeholders, integer.
    fn default() -> Self {
        DeriveBudget {
            max_bytes_per_peer_uncompressed_nar: 1024 * 1024 * 1024, // 1 GiB / window / peer
            max_dumps_per_peer: 64,
            max_bytes_global_uncompressed_nar: 4 * 1024 * 1024 * 1024, // 4 GiB / window
            max_dumps_global: 256,                                     // 4x the per-peer dump cap
            window: Duration::from_secs(60),
        }
    }
}

/// The numeric bound on this node's SERVE-side NAR-BODY EGRESS (upload) within one tumbling
/// [`window`](UploadBudget::window) — the shaper analog of [`ServeBudget`] on the
/// COMPRESSED-WIRE axis (TASK-299). Where [`ServeBudget`] bounds the UNCOMPRESSED-NAR
/// bytes a single serve may allocate/hold, this bounds the COMPRESSED-WIRE OCTETS this
/// node actually puts on the wire across the NAR-BODY serves in a window, so a node cannot be
/// driven to saturate its uplink by a stream of serve requests. HONEST SCOPE: it bounds the
/// amplifying NAR-BODY egress; tiny request-gated protocol-control responses (a spent window still
/// writes a few-byte decline per inbound request — non-amplifying) are outside the shaped envelope.
///
/// UNIT (the recurring NarSize-vs-FileSize trap, avoided by construction): the field is
/// COMPRESSED-WIRE OCTETS — the exact bytes handed to the transport (zstd-compressed when
/// negotiated, raw otherwise, framing included) — NEVER an uncompressed NarSize. The
/// enforcer charges the ACTUAL octets written, so the two are never compared.
///
/// NODE-WIDE, NOT PER-PEER. Unlike [`DeriveBudget`] (whose per-peer split defends a shared
/// CPU/IO resource a Sybil flood could monopolise), upload-rate bounds THIS node's finite
/// uplink — one aggregate resource with no per-peer subdivision. A single global window is
/// therefore the honest model: every admitted serve's real egress advances the one window,
/// and once it is spent the node DECLINES further serves until the window rolls. There is no
/// Sybil bypass to close: minting PeerIds cannot widen a fixed uplink budget.
///
/// Every field is an INTEGER (owner no-floats rule): octets and a [`window`](UploadBudget::window)
/// carried as a `Duration` of INTEGER milliseconds. The window is TUMBLING (resets wholly at the
/// boundary). Its enforcer's admission check is LEVEL-TRIGGERED and NON-RESERVING (it admits while
/// the window's emitted octets are below the cap). HONEST SCOPE: it bounds the amplifying NAR-BODY
/// serve egress, not the tiny protocol-control responses (a spent window still writes a few-byte
/// decline per inbound request — non-amplifying, request-gated). The transient bound: at an instant
/// when the window reads empty, every concurrently-admitted serve passes and streams, so the window
/// can overshoot `cap` by the compressed-WIRE volume of those serves — a volume bounded by the
/// concurrent in-flight UNCOMPRESSED-NAR cap ([`ServeBudget::max_inflight_bytes_uncompressed_nar`])
/// plus Bao proof/framing overhead. That is a coarse CROSS-UNIT magnitude bound, NOT a clean
/// same-unit `cap + max_inflight`, and this overshoot volume (`T_wire`) can recur each tumbling
/// window. So the enforced long-run rate is AT MOST `(cap + T_wire) / window` (a byte VOLUME over a
/// window) — a hair above the nominal `cap`/window, never below — a coarse egress rate-limit, NOT a
/// hard `cap` and NOT a reserving/sliding cap (both tighter guarantees are deliberate non-goals). It
/// is a SAFETY/amplification bound on this node's uplink, not a per-peer fairness mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UploadBudget {
    /// Compressed-wire OCTETS this node may emit across all serves within one
    /// [`window`](UploadBudget::window). Once a window's emitted octets reach this, further
    /// serves are DECLINED until the window rolls.
    pub max_bytes_per_window: u64,
    /// The accounting window. A carrier of an INTEGER millisecond value (owner no-floats rule);
    /// never fractional. The enforcer clamps a zero/sub-millisecond window UP to a sane floor
    /// (fail-closed, so a degenerate window cannot disable aggregation).
    pub window: Duration,
}

impl Default for UploadBudget {
    /// A provisional test-convenience default (NOT an authoritative policy number; the frozen
    /// per-profile `profile-budget-v1.json` owns those). Conservative placeholder, integer.
    fn default() -> Self {
        UploadBudget {
            max_bytes_per_window: 128 * 1024 * 1024, // 128 MiB / window (matches the serving profiles)
            window: Duration::from_secs(1),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provisional_defaults_match_the_prd_v1_floors() {
        // These are provisional convenience values, but they should not silently
        // drift from the PRD S2 fetch floor / TASK-72 serve ceilings the daemon
        // already enforces (a mismatch here would be a foot-gun at reconciliation).
        let env = SafetyEnvelope::default();
        assert_eq!(env.dial_timeout, Duration::from_secs(10));
        assert_eq!(env.body_idle_timeout, Duration::from_secs(10));
        assert_eq!(env.total_timeout, Duration::from_secs(60));

        let serve = ServeBudget::default();
        assert_eq!(serve.max_nar_bytes_uncompressed_nar, 256 * 1024 * 1024);
        assert_eq!(
            serve.max_inflight_bytes_uncompressed_nar,
            1024 * 1024 * 1024
        );
        assert_eq!(serve.max_serve_duration, Duration::from_secs(120));
    }

    #[test]
    fn derive_budget_defaults_are_integer_and_global_exceeds_per_peer() {
        let d = DeriveBudget::default();
        assert_eq!(d.max_bytes_per_peer_uncompressed_nar, 1024 * 1024 * 1024);
        assert_eq!(d.max_dumps_per_peer, 64);
        assert_eq!(d.max_bytes_global_uncompressed_nar, 4 * 1024 * 1024 * 1024);
        assert_eq!(d.window, Duration::from_secs(60));
        // The global ceiling is the Sybil floor: it must be >= a single peer's cap, or
        // one honest peer would trip the global before its own per-peer bound (which
        // would make the per-peer bound dead) - and it should leave room for a few
        // busy peers before the backstop bites.
        assert!(
            d.max_bytes_global_uncompressed_nar >= d.max_bytes_per_peer_uncompressed_nar,
            "global ceiling must be at least one peer's per-peer cap"
        );
        // Integer window (no fractional milliseconds).
        assert_eq!(d.window.subsec_nanos() % 1_000_000, 0);
    }
}
