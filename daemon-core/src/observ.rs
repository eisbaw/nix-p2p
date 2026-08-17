//! Runtime observability — the LIVE wiring of the TASK-120 operator contract (TASK-240).
//!
//! TASK-120 shipped the operator-contract SAFETY CORE plus the renderers + label vocabulary
//! ([`OperatorContract::status`], [`PrivacyPolicy`], [`MetricLabel`], [`DIAGNOSTICS_WARNING`]) —
//! UNIT-tested but fed only synthetic inputs. This module is that wiring: the ONE runtime
//! collection point the serving path emits into, and the two surfaces (`--status`, `--metrics`) an
//! operator queries from a running node. It REUSES the operator contract types — it never
//! re-encodes the policy.
//!
//! ## Single source of truth (AC#4/#5)
//!
//! * [`RuntimeMetrics`] is the SSOT for EMITTED metrics: bounded-cardinality integer counters
//!   keyed ONLY by the fixed [`MetricLabel`] / [`LookupOutcome`] vocabularies, never by a
//!   StorePath/NarHash/NodeId, so label cardinality can never explode.
//! * The announce budget is NOT mirrored here — it is read LIVE from the announce hook
//!   ([`crate::post_fetch::PostFetchAnnounce::budget_used`]), which locks the SAME ledger the
//!   budget gate CAS'es on, so the reported figure cannot drift from what is enforced.
//! * Bootstrap health + peer path are read LIVE from the swarm via [`StatusFacts`] (implemented by
//!   the binary over its swarm handle), so the reported connectivity matches the wire.
//!
//! ## Recording boundaries (AC#5, double-count discipline)
//!
//! Each counter family has EXACTLY ONE writer boundary, so one logical request cannot double-count:
//! * the typed DISCOVERY outcome (found/miss/unavailable) + holder count is recorded ONLY in
//!   [`crate::peer_source::PeerFabricNarSource`] (the NAR-resolve path) — NOT in the raw-serve
//!   directory probe, which consults the same directory for the narinfo-rewrite decision;
//! * the SERVE source (hit_peer / hit_upstream) is recorded at the fetch boundary: a peer hit in
//!   `PeerFabricNarSource`, an upstream hit ONCE in [`crate::discovery::FallbackNarSource`]'s
//!   `resolve_within` (the single production boundary; `resolve` delegates to it).
//!
//! The two families are ORTHOGONAL: a discovery `found` whose bytes could not be fetched is a
//! `found` lookup AND a `hit_upstream` serve — both true, never reconciled into one label. A size
//! abort ([`crate::source::SourceError::TooLarge`]) is NEITHER a hit nor a miss and is recorded as
//! neither.
//!
//! ## Redaction by default (AC#5)
//!
//! Every identifier on either surface passes through [`PrivacyPolicy`]: a full NodeId is redacted
//! unless `--diagnostics` is opted in, which additionally prints the mandatory
//! [`DIAGNOSTICS_WARNING`]. Metric SERIES carry only the fixed label vocabulary; the node id
//! appears on a `#` comment line, so it is never a series key. The `/metrics` surface carries NO
//! content id at all (a scrapeable exposition must not be a per-content metadata channel).
//!
//! ## No floats (owner rule)
//!
//! Every counter is an integer `u64`; the surfaces render integers only.

use std::convert::Infallible;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use bytes::Bytes;
use http_body_util::Full;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use crate::operator::{
    LookupOutcome, MetricLabel, OperatorContract, PeerPath, PrivacyPolicy, StatusInputs,
};

/// The admin surface routes. Namespaced under `/nix-p2p/` so they can never collide with the
/// root-level Nix cache API (`<hash>.narinfo`, `nar/*`).
pub const STATUS_PATH: &str = "/nix-p2p/status";
/// The metrics exposition route.
pub const METRICS_PATH: &str = "/nix-p2p/metrics";

/// The atomically-updated last-lookup snapshot for the status surface. Held behind ONE mutex so a
/// status read can never splice the holder count of one lookup with the outcome of another (torn
/// read). Distinct from the monotonic counters, which are independent series.
#[derive(Debug, Clone, Copy, Default)]
struct LastLookup {
    outcome: Option<LookupOutcome>,
    holders: Option<u32>,
}

/// The SSOT for the metrics the serving path emits (AC#5). Bounded-cardinality integer counters
/// keyed ONLY by the fixed [`MetricLabel`] / [`LookupOutcome`] vocabularies.
#[derive(Debug, Default)]
pub struct RuntimeMetrics {
    // ---- serve source: where the served NAR bytes came from ----
    hit_peer: AtomicU64,
    hit_upstream: AtomicU64,
    // ---- discovery outcome: the TASK-100 typed miss-vs-unavailable distinction ----
    found: AtomicU64,
    miss: AtomicU64,
    unavailable: AtomicU64,
    // ---- last-lookup snapshot for the status surface (atomic-together, no torn read) ----
    last: Mutex<LastLookup>,
}

impl RuntimeMetrics {
    /// A fresh zeroed registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record the TYPED discovery outcome (AC#4: miss vs unavailable) plus, when known, the
    /// distinct holder count. Called at each p2p-resolution exit in
    /// [`crate::peer_source::PeerFabricNarSource`] — the SINGLE discovery-outcome boundary. A size
    /// abort is not an outcome and never reaches here.
    pub fn record_lookup(&self, outcome: LookupOutcome, holders: Option<u32>) {
        match outcome {
            LookupOutcome::Found => self.found.fetch_add(1, Ordering::Relaxed),
            LookupOutcome::Miss => self.miss.fetch_add(1, Ordering::Relaxed),
            LookupOutcome::Unavailable => self.unavailable.fetch_add(1, Ordering::Relaxed),
        };
        match self.last.lock() {
            Ok(mut slot) => {
                *slot = LastLookup {
                    outcome: Some(outcome),
                    holders,
                };
            }
            // Fail-OPEN on the observability path (never corrupt the serve path), but do NOT fail
            // SILENTLY: a poisoned lock freezes the last-lookup surface, so say so.
            Err(_) => eprintln!(
                "daemon: observability last-lookup mutex poisoned; the status surface's \
                 last_lookup/holders will not update"
            ),
        }
    }

    /// Record that a peer served the NAR bytes (a hit on the decentralized path).
    pub fn record_peer_serve(&self) {
        self.hit_peer.fetch_add(1, Ordering::Relaxed);
    }

    /// Record that the HTTP upstream served the NAR bytes (the S2 fallback path). Called ONCE by
    /// [`crate::discovery::FallbackNarSource`] when the secondary satisfies a p2p miss.
    pub fn record_upstream_serve(&self) {
        self.hit_upstream.fetch_add(1, Ordering::Relaxed);
    }

    /// The current integer count for a serve-source label (bounded-cardinality read).
    fn serve_count(&self, label: MetricLabel) -> u64 {
        match label {
            MetricLabel::OutcomeHitPeer => self.hit_peer.load(Ordering::Relaxed),
            MetricLabel::OutcomeHitUpstream => self.hit_upstream.load(Ordering::Relaxed),
            _ => 0,
        }
    }

    /// The current integer count for a typed discovery outcome (bounded-cardinality read).
    fn lookup_count(&self, outcome: LookupOutcome) -> u64 {
        match outcome {
            LookupOutcome::Found => self.found.load(Ordering::Relaxed),
            LookupOutcome::Miss => self.miss.load(Ordering::Relaxed),
            LookupOutcome::Unavailable => self.unavailable.load(Ordering::Relaxed),
        }
    }

    /// The typed discovery-outcome totals `(found, miss, unavailable)` — the emitted counters, for
    /// tests and drill oracles that read the SSOT directly rather than the HTTP surface.
    pub fn lookup_totals(&self) -> (u64, u64, u64) {
        (
            self.found.load(Ordering::Relaxed),
            self.miss.load(Ordering::Relaxed),
            self.unavailable.load(Ordering::Relaxed),
        )
    }

    /// The serve-source totals `(hit_peer, hit_upstream)`.
    pub fn serve_totals(&self) -> (u64, u64) {
        (
            self.hit_peer.load(Ordering::Relaxed),
            self.hit_upstream.load(Ordering::Relaxed),
        )
    }

    /// The last-lookup snapshot (outcome + holders) read under a SINGLE lock, so a status scrape can
    /// never SPLICE the holders of one lookup with the outcome of another (torn read). This is the
    /// accessor the status surface uses; `last_lookup`/`last_holders` are per-field conveniences.
    pub fn last_snapshot(&self) -> (Option<LookupOutcome>, Option<u32>) {
        self.last
            .lock()
            .map(|s| (s.outcome, s.holders))
            .unwrap_or((None, None))
    }

    /// The most recent lookup outcome for the status surface, or `None` before the first lookup.
    pub fn last_lookup(&self) -> Option<LookupOutcome> {
        self.last_snapshot().0
    }

    /// Distinct holders known for the most recent lookup, or `None` if none observed.
    pub fn last_holders(&self) -> Option<u32> {
        self.last_snapshot().1
    }

    /// Render the Prometheus-style metrics exposition (AC#5). Every metric SERIES carries only a
    /// fixed vocabulary label; the node id appears on a `#` comment line routed through `privacy`,
    /// so it is NEVER a series key and cannot inflate cardinality. `node_id_full` is redacted here
    /// unless diagnostics are opted in. No content id appears on this scrapeable surface.
    pub fn render(&self, privacy: &PrivacyPolicy, node_id_full: &str) -> String {
        let mut out = Vec::new();
        out.push(
            "# nix-p2p runtime metrics (bounded cardinality: fixed label vocabulary only)"
                .to_string(),
        );
        // Redactable identity: a COMMENT line, never a label — redacted by default.
        out.push(format!(
            "# nix_p2p_node_id {}",
            privacy.node_id(node_id_full)
        ));
        out.push("# HELP nix_p2p_serve_total NAR serves by source".to_string());
        out.push("# TYPE nix_p2p_serve_total counter".to_string());
        for label in [MetricLabel::OutcomeHitPeer, MetricLabel::OutcomeHitUpstream] {
            out.push(format!(
                "nix_p2p_serve_total{{source=\"{}\"}} {}",
                label.as_str(),
                self.serve_count(label)
            ));
        }
        out.push("# HELP nix_p2p_lookup_total discovery lookups by typed outcome".to_string());
        out.push("# TYPE nix_p2p_lookup_total counter".to_string());
        for outcome in [
            LookupOutcome::Found,
            LookupOutcome::Miss,
            LookupOutcome::Unavailable,
        ] {
            out.push(format!(
                "nix_p2p_lookup_total{{outcome=\"{}\"}} {}",
                outcome.as_str(),
                self.lookup_count(outcome)
            ));
        }
        out.push(format!(
            "nix_p2p_diagnostics_opt_in {}",
            u8::from(privacy.diagnostics_opt_in)
        ));
        out.join("\n")
    }
}

/// A snapshot of the LIVE swarm connectivity facts the status surface needs but the generic
/// frontend cannot compute itself (they live in the backend's swarm). The binary implements
/// [`StatusFacts`] over its swarm handle; the frontend renders from the snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusFactSnapshot {
    /// Total configured bootstrap/entry peers.
    pub bootstrap_total: u32,
    /// How many of them are currently connected (live bootstrap health).
    pub bootstrap_healthy: u32,
    /// The current peer path (direct / relay / unknown / none). LIVE as of TASK-242: the libp2p
    /// backend classifies it from the swarm's own `ConnectionEstablished`/`ConnectionClosed`
    /// bookkeeping (`ConnectedPoint::is_relayed`) via `SwarmHandle::connection_path`, so a node
    /// reaching a bootstrap over a `/p2p-circuit` reports [`PeerPath::Relay`] and a direct dial
    /// reports [`PeerPath::Direct`]. A running swarm with no classified live bootstrap connection
    /// reports [`PeerPath::Unknown`]; [`PeerPath::None`] is reserved for an upstream-only node with
    /// no swarm at all (this snapshot's [`none`](StatusFactSnapshot::none)). See the backend's
    /// `SwarmStatusFacts` for the honest scope (this classifies the path to the CONFIGURED bootstrap
    /// peers, not a NAT-reachability verdict).
    pub path: PeerPath,
}

impl StatusFactSnapshot {
    /// The upstream-only / no-swarm snapshot: nothing configured, nothing connected, no path.
    pub fn none() -> Self {
        StatusFactSnapshot {
            bootstrap_total: 0,
            bootstrap_healthy: 0,
            path: PeerPath::None,
        }
    }
}

/// The seam the binary implements to feed LIVE swarm connectivity into the status surface. Async
/// because a swarm query round-trips through the swarm worker. A node with no participating swarm
/// (upstream-only) wires [`NullStatusFacts`].
#[async_trait]
pub trait StatusFacts: Send + Sync {
    /// Query the running swarm for the current connectivity snapshot.
    async fn snapshot(&self) -> StatusFactSnapshot;
}

/// The no-swarm facts provider (upstream-only): always the empty snapshot.
#[derive(Debug, Clone, Copy, Default)]
pub struct NullStatusFacts;

#[async_trait]
impl StatusFacts for NullStatusFacts {
    async fn snapshot(&self) -> StatusFactSnapshot {
        StatusFactSnapshot::none()
    }
}

/// The runtime observability bundle wired into the serving frontend: the authoritative contract,
/// the node's raw identity (redacted at render), the metrics registry, the live-facts provider,
/// and the optional announce hook (for the live budget figure). It renders the two operator
/// surfaces through the contract's [`PrivacyPolicy`]. Served on a DEDICATED loopback admin
/// listener (see [`serve_admin`]), never on the peer-facing cache listener, so the trust boundary
/// is structural rather than resting on redaction alone.
#[derive(Clone)]
pub struct Observability {
    /// The authoritative operator contract (profile, caps, privacy, dht_role).
    pub contract: OperatorContract,
    /// The node's RAW NodeId; redacted through [`PrivacyPolicy`] on every surface.
    pub node_id_full: String,
    /// The emitted-metrics registry (SSOT).
    pub metrics: Arc<RuntimeMetrics>,
    /// The live swarm-facts provider.
    pub facts: Arc<dyn StatusFacts>,
    /// The announce-after-fetch hook, for the LIVE announce budget figure (`None` = consume-only).
    pub announce: Option<Arc<dyn crate::post_fetch::PostFetchAnnounce>>,
    /// The RESPONDER derivation ledger, for the LIVE global derive-budget figure
    /// (TASK-229). Read LIVE (not mirrored) so the reported used/CAP cannot drift from
    /// what the hold-query answer path actually enforces - the same discipline as the
    /// announce budget. `None` for a node that answers no hold-queries (no responder).
    pub derive_ledger: Option<Arc<crate::derive_ledger::PeerDeriveLedger>>,
}

impl Observability {
    /// Render the LIVE `--status` surface (AC#4): the authoritative contract joined with runtime
    /// state (bootstrap health, holders, path, miss-vs-unavailable, announce budget, fallback
    /// reason), routed through the contract's [`PrivacyPolicy`]. Queries the swarm for the live
    /// facts, so it is async.
    pub async fn render_status(&self) -> String {
        let facts = self.facts.snapshot().await;
        let announce_budget_used = self
            .announce
            .as_ref()
            .and_then(|h| h.budget_used())
            .unwrap_or(0);
        // LIVE global derive-budget usage (TASK-229): read straight from the ledger the
        // answer path charges, so the figure cannot drift from what is enforced.
        let derive_budget_global_used = self
            .derive_ledger
            .as_ref()
            .map(|l| l.global_bytes_used())
            .unwrap_or(0);
        // ONE lock acquisition for both fields (no torn read: the holders and outcome a scrape
        // reports are always from the SAME lookup).
        let (last_lookup, holder_count) = self.metrics.last_snapshot();
        let inputs = StatusInputs {
            node_id: self.contract.privacy.node_id(&self.node_id_full),
            bootstrap_total: facts.bootstrap_total,
            bootstrap_healthy: facts.bootstrap_healthy,
            holder_count,
            path: facts.path,
            last_lookup,
            announce_budget_used,
            derive_budget_global_used,
            fallback_reason: fallback_reason(last_lookup, &facts).to_string(),
        };
        self.contract.status(&inputs)
    }

    /// Render the LIVE `--metrics` surface (AC#5) through the contract's [`PrivacyPolicy`].
    pub fn render_metrics(&self) -> String {
        self.metrics
            .render(&self.contract.privacy, &self.node_id_full)
    }
}

/// Serve the operator admin surface (`/nix-p2p/status`, `/nix-p2p/metrics`) on an already-bound
/// listener until it errors. The binary binds this to a LOOPBACK address ONLY (a structural trust
/// boundary — the peer-facing cache listener never carries this surface), and off by default: no
/// `--status-listen` means no admin surface at all, the fail-safe posture. Every response is
/// already redacted by the active [`PrivacyPolicy`]; a non-admin path is a 404, a non-GET a 405.
pub async fn serve_admin(listener: TcpListener, observ: Arc<Observability>) -> std::io::Result<()> {
    loop {
        let (stream, _peer) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let observ = Arc::clone(&observ);
        tokio::spawn(async move {
            let service = service_fn(move |req| {
                let observ = Arc::clone(&observ);
                async move { Ok::<_, Infallible>(admin_respond(req, observ).await) }
            });
            if let Err(err) = http1::Builder::new().serve_connection(io, service).await
                && !err.is_incomplete_message()
            {
                eprintln!("daemon: admin connection error: {err}");
            }
        });
    }
}

/// Build the response for one admin request: route, method-check, render through the privacy
/// policy. Extracted so it is unit-testable without a socket.
async fn admin_respond(
    req: Request<hyper::body::Incoming>,
    observ: Arc<Observability>,
) -> Response<Full<Bytes>> {
    if req.method() != Method::GET {
        return text(StatusCode::METHOD_NOT_ALLOWED, "only GET".to_string());
    }
    match req.uri().path() {
        STATUS_PATH => text(StatusCode::OK, observ.render_status().await),
        METRICS_PATH => text(StatusCode::OK, observ.render_metrics()),
        _ => text(StatusCode::NOT_FOUND, "not found".to_string()),
    }
}

/// A plain-text response with a trailing newline (so `curl` output is line-clean).
fn text(status: StatusCode, mut body: String) -> Response<Full<Bytes>> {
    body.push('\n');
    Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .body(Full::new(Bytes::from(body)))
        .expect("static response builds")
}

/// Derive the operator-facing fallback reason from the last lookup outcome and live connectivity.
/// A pure function of observable state — one place, greppable tokens matching the status vocab.
fn fallback_reason(last_lookup: Option<LookupOutcome>, facts: &StatusFactSnapshot) -> &'static str {
    // A configured-but-unreachable bootstrap set is the dominant, most actionable reason: without
    // it discovery cannot even start, so it is reported ahead of a downstream lookup symptom.
    if facts.bootstrap_total > 0 && facts.bootstrap_healthy == 0 {
        return "bootstrap-outage";
    }
    match last_lookup {
        Some(LookupOutcome::Unavailable) => "discovery-unavailable",
        Some(LookupOutcome::Miss) => "no-provider",
        // Found, or no lookup yet: nothing to explain.
        Some(LookupOutcome::Found) | None => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operator::{DhtRole, SharingProfile};
    use std::sync::Arc;

    // ---- AC#5: emitted metrics use the fixed vocabulary + integers --------------

    /// A fresh registry emits every fixed-label series at zero; the counters increment on record.
    #[test]
    fn counters_increment_and_render_integers() {
        let m = RuntimeMetrics::new();
        let privacy = PrivacyPolicy::default();
        m.record_peer_serve();
        m.record_peer_serve();
        m.record_upstream_serve();
        m.record_lookup(LookupOutcome::Found, Some(3));
        m.record_lookup(LookupOutcome::Miss, None);
        let text = m.render(&privacy, "12D3KooWFULLnodeid");
        assert!(text.contains("nix_p2p_serve_total{source=\"hit_peer\"} 2"));
        assert!(text.contains("nix_p2p_serve_total{source=\"hit_upstream\"} 1"));
        assert!(text.contains("nix_p2p_lookup_total{outcome=\"found\"} 1"));
        assert!(text.contains("nix_p2p_lookup_total{outcome=\"miss\"} 1"));
        assert!(text.contains("nix_p2p_lookup_total{outcome=\"unavailable\"} 0"));
        // Every emitted metric value is an integer (no float rendering anywhere).
        for line in text.lines() {
            if line.starts_with("nix_p2p_") {
                let v = line.rsplit(' ').next().expect("value");
                assert!(
                    v.parse::<u64>().is_ok(),
                    "non-integer metric value in {line:?}"
                );
            }
        }
    }

    /// BOUNDED CARDINALITY bite: every `{key="value"}` label value on the metrics surface is drawn
    /// from the fixed vocabulary — never a StorePath/NarHash/NodeId. MUTATION: a series keyed by a
    /// served content id (an unbounded label) would extract a value not in the vocabulary and
    /// redden this.
    #[test]
    fn metric_labels_are_only_the_fixed_vocabulary() {
        let m = RuntimeMetrics::new();
        m.record_lookup(LookupOutcome::Found, Some(2));
        m.record_peer_serve();
        let text = m.render(&PrivacyPolicy::default(), "12D3KooWFULLnodeid");
        let vocab: std::collections::HashSet<&str> =
            [MetricLabel::OutcomeHitPeer, MetricLabel::OutcomeHitUpstream]
                .into_iter()
                .map(|l| l.as_str())
                .chain(
                    [
                        LookupOutcome::Found,
                        LookupOutcome::Miss,
                        LookupOutcome::Unavailable,
                    ]
                    .into_iter()
                    .map(|o| o.as_str()),
                )
                .collect();
        for line in text.lines() {
            if line.starts_with('#') {
                continue; // comment/info lines are not series
            }
            if let Some(eq) = line.find("=\"") {
                let rest = &line[eq + 2..];
                let value = &rest[..rest.find('"').expect("closing quote")];
                assert!(
                    vocab.contains(value),
                    "metric label value {value:?} is NOT in the bounded vocabulary ({line:?})"
                );
            }
        }
    }

    /// REDACTION-BY-DEFAULT bite (AC#5): the full NodeId is redacted on the metrics surface by
    /// default; the raw identifier NEVER appears. MUTATION: routing the raw node id onto the
    /// surface (dropping `privacy.node_id`) leaks it and reddens the `assert!(!...)`. Diagnostics
    /// opt-in reveals it (and only then).
    #[test]
    fn metrics_redact_node_id_by_default_reveal_under_diagnostics() {
        let full_node = "12D3KooWRAWnodeidentity";
        let off = PrivacyPolicy::default();
        let m = RuntimeMetrics::new();
        let text = m.render(&off, full_node);
        assert!(
            !text.contains(full_node),
            "raw NodeId leaked on the default metrics surface:\n{text}"
        );
        assert!(
            text.contains("12D3KooW…"),
            "expected an 8-char redacted prefix:\n{text}"
        );

        let on = PrivacyPolicy {
            diagnostics_opt_in: true,
        };
        let diag = m.render(&on, full_node);
        assert!(
            diag.contains(full_node),
            "diagnostics must reveal the full NodeId"
        );
    }

    // ---- AC#4: the live status surface joins the contract with runtime state -------

    fn observ(profile: SharingProfile, facts: StatusFactSnapshot) -> Observability {
        struct FixedFacts(StatusFactSnapshot);
        #[async_trait]
        impl StatusFacts for FixedFacts {
            async fn snapshot(&self) -> StatusFactSnapshot {
                self.0
            }
        }
        let mut contract = OperatorContract::for_profile(profile);
        contract.dht_role = DhtRole::Client;
        Observability {
            contract,
            node_id_full: "12D3KooWRAWnodeidentity".to_string(),
            metrics: Arc::new(RuntimeMetrics::new()),
            facts: Arc::new(FixedFacts(facts)),
            announce: None,
            derive_ledger: None,
        }
    }

    /// The live status surface reports REAL runtime state (bootstrap health, holders, typed
    /// miss-vs-unavailable) and REDACTS the node id by default. MUTATION: dropping the
    /// `privacy.node_id` on the status inputs leaks the raw NodeId and reddens the `!contains`.
    #[tokio::test]
    async fn render_status_reports_live_state_redacted() {
        let o = observ(
            SharingProfile::ConsumeOnly,
            StatusFactSnapshot {
                bootstrap_total: 3,
                bootstrap_healthy: 2,
                path: PeerPath::None,
            },
        );
        o.metrics.record_lookup(LookupOutcome::Unavailable, Some(5));
        let s = o.render_status().await;
        assert!(s.contains("profile=consume-only"), "{s}");
        assert!(s.contains("bootstrap_healthy=2/3"), "{s}");
        assert!(s.contains("holders=5"), "{s}");
        assert!(s.contains("last_lookup=unavailable"), "{s}");
        assert!(s.contains("dht_role=client"), "{s}");
        assert!(
            !s.contains("12D3KooWRAWnodeidentity"),
            "raw NodeId leaked on the default status surface:\n{s}"
        );
        assert!(s.contains("node_id=12D3KooW…"), "{s}");
    }

    /// FALLBACK-REASON derivation bites each observable cause. MUTATION: collapsing any arm makes
    /// the corresponding assertion fail — the reasons are distinct, not a constant.
    #[test]
    fn fallback_reason_attributes_each_cause() {
        // A dead bootstrap set dominates (discovery cannot even start).
        assert_eq!(
            fallback_reason(
                Some(LookupOutcome::Miss),
                &StatusFactSnapshot {
                    bootstrap_total: 2,
                    bootstrap_healthy: 0,
                    path: PeerPath::None,
                }
            ),
            "bootstrap-outage"
        );
        let healthy = StatusFactSnapshot {
            bootstrap_total: 2,
            bootstrap_healthy: 2,
            path: PeerPath::None,
        };
        assert_eq!(
            fallback_reason(Some(LookupOutcome::Unavailable), &healthy),
            "discovery-unavailable"
        );
        assert_eq!(
            fallback_reason(Some(LookupOutcome::Miss), &healthy),
            "no-provider"
        );
        assert_eq!(fallback_reason(Some(LookupOutcome::Found), &healthy), "");
        assert_eq!(fallback_reason(None, &healthy), "");
    }
}
