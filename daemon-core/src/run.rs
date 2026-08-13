//! [`run`] - the stack-neutral composition root the per-backend thin binaries call.
//!
//! `fn main() { … daemon_core::run(fabric, cfg) }` (docs/peer-fabric-seam.md): a binary
//! constructs its ONE backend fabric (a `Libp2pFabric`, an `IrohFabric`) plus its
//! connectivity, then hands the running `Arc<dyn PeerFabric>` here. This function is the
//! SHARED serving frontend - it knows nothing about which stack it was handed:
//!
//!   1. asserts the profile's REQUIRED axes are present ([`require_axes`]) and FAILS FAST
//!      otherwise (the composition-root gate; a missing-but-required axis is a loud startup
//!      error, never a silent runtime degrade);
//!   2. wraps the fabric in the generic [`PeerFabricNarSource`] (discover-then-fetch) with an
//!      HTTP-upstream FALLBACK, and pairs it with the dynamic [`PeerFabricRawServe`] decision;
//!   3. builds the [`App`] and serves the tiny Nix binary-cache API on the bound listener,
//!      owning a [`TaskSupervisor`] whose drop tears every HTTP connection task down.
//!
//! Backend-specific PROVIDER setup (installing a serve gate, announcing signed records) is
//! the binary's job, done BEFORE calling `run` and kept alive alongside it - `run` is the
//! consumer-facing HTTP frontend, generic over the fabric.

use std::sync::Arc;

use peer_fabric::{Axis, DiscoveryBudget, PeerFabric, SafetyEnvelope, require_axes};
use tokio::net::TcpListener;

use crate::catalog::{CorrelationStore, NarCatalog};
use crate::discovery::FallbackNarSource;
use crate::peer_source::{PeerFabricNarSource, PeerFabricRawServe};
use crate::rewrite::{AnyRawServe, RawServeDecision};
use crate::server::{App, serve};
use crate::source::{NarSource, NarinfoSource, RawUpstream};
use crate::{CacheInfo, TaskSupervisor};

/// Everything the stack-neutral serving frontend needs, assembled by the binary. The p2p
/// NAR source + raw-serve decision are NOT here - [`run`] derives them from the fabric, so a
/// binary cannot wire a discover/fetch path that disagrees with the fabric it passed.
pub struct RunConfig {
    /// The already-bound listener (the binary binds so a test can grab `127.0.0.1:0`).
    pub listener: TcpListener,
    /// The HTTP upstream: the narinfo source, the base NAR source (fallback behind the p2p
    /// source), and the `log/*`/`*.ls` passthrough. One value behind three seams.
    pub upstream: Arc<dyn NarSource>,
    /// The narinfo source (the upstream, or a disk cache layered over it).
    pub narinfo: Arc<dyn NarinfoSource>,
    /// The `log/*`/`debuginfo/*` passthrough (the upstream).
    pub passthrough: Arc<dyn RawUpstream>,
    /// Persisted correlation (the narinfo disk cache), consulted on an in-memory catalog miss.
    pub correlation: Arc<dyn CorrelationStore>,
    /// The generated `nix-cache-info`.
    pub cache_info: CacheInfo,
    /// The configured upstream string, echoed as `source=` in the per-substitution log.
    pub upstream_label: String,
    /// The bound on each `find_providers` consultation (deadline + peer cap).
    pub discovery_budget: DiscoveryBudget,
    /// The fetch time envelope handed to each transfer.
    pub envelope: SafetyEnvelope,
    /// The REQUIRED axes for this profile - `run` asserts them present and fails fast.
    pub required_axes: Vec<Axis>,
    /// Extra raw-serve decisions OR-ed with the dynamic p2p probe (e.g. a static allowlist).
    /// Empty is the normal single-backend case.
    pub extra_raw_serve: Vec<Arc<dyn RawServeDecision>>,
}

/// Serve the Nix binary-cache frontend over `fabric` until the listener errors (or the
/// returned future is dropped, which tears the serve tasks down via the owned supervisor).
/// Returns `Err` on a fail-fast startup problem (a missing required axis) or a serve error.
pub async fn run(fabric: Arc<dyn PeerFabric>, cfg: RunConfig) -> Result<(), String> {
    // Composition-root REQUIRED-axis gate: a profile that needs an axis the constructed
    // fabric does not offer is a loud startup error here, before the first request.
    require_axes(fabric.as_ref(), &cfg.required_axes)
        .map_err(|missing| format!("fabric does not satisfy the required axes: {missing}"))?;

    // The decentralized fetch path: discover a provider via the fabric's directory, fetch the
    // gate-1-verified raw NAR over its transfer, falling back to HTTP upstream on a clean miss.
    let p2p_source: Arc<dyn NarSource> = Arc::new(PeerFabricNarSource::new(
        fabric.clone(),
        cfg.discovery_budget,
        cfg.envelope,
    ));
    let nar: Arc<dyn NarSource> =
        Arc::new(FallbackNarSource::new(p2p_source, cfg.upstream.clone()));

    // The dynamic raw-serve decision probes the SAME directory the fetch uses, so
    // serves-raw(h) <=> narinfo-rewritten-to-raw(h). OR in any static extras (e.g. a claim
    // allowlist) the binary supplied.
    let dynamic_raw: Arc<dyn RawServeDecision> = Arc::new(PeerFabricRawServe::new(
        fabric.clone(),
        cfg.discovery_budget,
    ));
    let raw_serve: Arc<dyn RawServeDecision> = if cfg.extra_raw_serve.is_empty() {
        dynamic_raw
    } else {
        let mut all = cfg.extra_raw_serve;
        all.push(dynamic_raw);
        Arc::new(AnyRawServe::new(all))
    };

    let app = Arc::new(App {
        narinfo: cfg.narinfo,
        nar,
        passthrough: cfg.passthrough,
        cache_info: cfg.cache_info,
        catalog: Arc::new(NarCatalog::new()),
        upstream_label: cfg.upstream_label,
        correlation: cfg.correlation,
        raw_serve,
    });

    // A standalone supervisor: its drop cancels/aborts every in-flight HTTP connection task,
    // giving the same no-detach shutdown property the iroh path gets from its node runtime.
    let supervisor = TaskSupervisor::new();
    serve(cfg.listener, app, supervisor.handle())
        .await
        .map_err(|error| format!("HTTP serve loop ended with error: {error}"))
}
