//! The HTTP serving layer: routing, header hygiene, and response building.
//!
//! This module depends ONLY on the trait objects in [`crate::source`] - never
//! on an HTTP client. That is the compile-time seam (AC#5): swap the trait impls
//! and the wire behaviour changes with the serving layer untouched.
//!
//! Routing mirrors the tiny Nix binary-cache API:
//!   * `GET/HEAD /nix-cache-info` -> generated locally ([`crate::cacheinfo`]);
//!   * `GET/HEAD /<hash>.narinfo` -> [`NarinfoSource`], body verbatim through the
//!     (empty) rewrite allowlist (AC#3);
//!   * `GET/HEAD /nar/<...>`      -> [`NarSource`], streamed verbatim (AC#6);
//!   * anything else              -> [`RawUpstream`] passthrough (`log/*`,
//!     `*.ls`, `debuginfo/*`) so `nix log` never breaks (AC#4).
//!
//! Status fidelity (AC#4): a non-200 upstream *response* is forwarded with its
//! exact status. Only a transport *failure* ([`SourceError`]) becomes a 502, and
//! it is produced fast so Nix falls back without hanging (S2).

use std::convert::Infallible;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::{Buf, Bytes};
use http::{HeaderMap, HeaderName};
use http_body::{Body, Frame};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use crate::body::{empty, full};
use crate::cacheinfo::CacheInfo;
use crate::catalog::{CorrelationStore, NarCatalog, parse_correlation};
use crate::rewrite;
use crate::source::{
    NarBody, NarCompression, NarHash, NarKey, NarPathToken, NarSource, NarinfoSource,
    NarinfoTransport, RawUpstream, SourceError, StoreHash, UpstreamResponse,
};
use proc_supervisor::TaskSupervisorHandle;

/// Everything a request needs, injected so tests can swap any source for a fake.
pub struct App {
    pub narinfo: Arc<dyn NarinfoSource>,
    pub nar: Arc<dyn NarSource>,
    pub passthrough: Arc<dyn RawUpstream>,
    pub cache_info: CacheInfo,
    /// Correlation state owned by the server (UpstreamHttp holds no catalog):
    /// narinfos populate it, NAR requests read it to carry the signed NarHash
    /// across the seam.
    pub catalog: Arc<NarCatalog>,
    /// The daemon's CONFIGURED upstream, echoed verbatim as `source=` in the
    /// per-substitution log line. Presentation-only (never used to build a
    /// request), so the server layer keeps depending on the trait objects alone
    /// and not on a concrete HTTP client. This is the `--upstream` string as
    /// given; in wave-1 (no redirects) it is also the host actually dialed.
    pub upstream_label: String,
    /// PERSISTED correlation, consulted only on an in-memory catalog MISS. In
    /// production this is the narinfo disk cache, which derives `token -> meta`
    /// from cached narinfos so a warm-on-disk-but-cold-in-memory daemon (post
    /// restart, warm Nix client that skipped the narinfo GET) still dispatches
    /// `SignedNarHash` (task-8; task-4's deferred steady-state). Defaults to
    /// [`crate::catalog::NullCorrelation`] when no cache is wired.
    pub correlation: Arc<dyn CorrelationStore>,
    /// Decides, per NarHash, whether the daemon will serve the RAW nar itself and
    /// therefore rewrite the narinfo's transport fields to raw (task-49). MUST be
    /// coupled with a raw-capable `nar` source: a `true` here without one hands the
    /// client a raw narinfo the daemon cannot back. The wave-1 binary wires
    /// [`crate::rewrite::NoRawServe`] (never rewrite -> verbatim upstream narinfo +
    /// compressed nar, the S2 path); task-41 wires the availability-backed decision
    /// alongside a raw NAR source.
    pub raw_serve: Arc<dyn rewrite::RawServeDecision>,
    /// The public-NAR allowlist (TASK-102): the SINGLE writer of which NAR identities
    /// this node may publicly announce. `respond_narinfo` calls `learn` on the exact
    /// cache.nixos.org response; only a narinfo whose trusted-key Nix signature verifies
    /// appends its `(NarHash, NarSize)`. A daemon with no configured publication
    /// authority uses [`crate::PublicNarAllowlist::disabled`], which learns nothing.
    pub public_allowlist: Arc<crate::public_allowlist::PublicNarAllowlist>,
    /// ANNOUNCE-AFTER-FETCH hook (TASK-77), or `None` for a CONSUME-ONLY (leech) node.
    /// When set, a successful `SignedNarHash` NAR fetch whose narinfo carried a store path
    /// invokes it so this node becomes a discoverable holder (register + verify + announce,
    /// budgeted + eligibility-gated - all in the backend impl). `None` (the default, and the
    /// only posture for a node with no publish authority) means the node fetches without ever
    /// announcing what it fetched - the privacy-preserving consume-only mode (TASK-78).
    pub post_fetch_announce: Option<Arc<dyn crate::post_fetch::PostFetchAnnounce>>,
}

/// Serve on an already-bound listener until it errors. Binding is the caller's
/// job so tests can grab an OS-assigned port (`127.0.0.1:0`) and read it back.
pub async fn serve(
    listener: TcpListener,
    app: Arc<App>,
    supervisor: TaskSupervisorHandle,
) -> std::io::Result<()> {
    loop {
        let (stream, _peer) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let app = Arc::clone(&app);
        let registration = supervisor.spawn("http-connection", async move {
            let service = service_fn(move |req| {
                let app = Arc::clone(&app);
                async move { Ok::<_, Infallible>(handle(req, app).await) }
            });
            if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
                // A client hanging up mid-response is normal traffic, not a
                // fault; surface only unexpected server errors.
                if !err.is_incomplete_message() {
                    eprintln!("daemon: connection error: {err}");
                }
            }
        });
        if let Err(error) = registration {
            if error.is_capacity_exhausted() {
                // The accepted stream is owned by the rejected future and is
                // dropped here, giving this connection an immediate EOF while
                // keeping the listener available for recovery.
                eprintln!("HTTP-CONNECTION-DECLINED reason=busy error={error}");
                continue;
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                format!("HTTP task supervisor is unavailable: {error}"),
            ));
        }
    }
}

/// How a request target maps onto the cache API.
enum Route {
    CacheInfo,
    Narinfo(StoreHash),
    /// The `nar/`-relative URL token; correlation to a signed NarHash happens in
    /// `handle`, not here.
    Nar(NarPathToken),
    /// `log/*`, `*.ls`, `debuginfo/*`, and anything else - passthrough.
    Other,
}

/// Classify the request path. The daemon parses its OWN inbound path here (an
/// HTTP server must); it never constructs an *upstream* URL - that lives in
/// `UpstreamHttp`.
///
/// The `/nar/` prefix is checked before the `.narinfo` suffix so a pathological
/// `/nar/foo.narinfo` routes as a NAR, not a narinfo (no such cache-API path
/// exists, but the order removes the ambiguity rather than relying on it).
fn classify(path: &str) -> Route {
    if path == "/nix-cache-info" {
        Route::CacheInfo
    } else if let Some(token) = path.strip_prefix("/nar/") {
        Route::Nar(NarPathToken::new(token))
    } else if let Some(rest) = path.strip_suffix(".narinfo") {
        Route::Narinfo(StoreHash::new(rest.trim_start_matches('/')))
    } else {
        Route::Other
    }
}

async fn handle(req: Request<Incoming>, app: Arc<App>) -> Response<NarBody> {
    let method = req.method().clone();
    if method != Method::GET && method != Method::HEAD {
        return text_status(StatusCode::METHOD_NOT_ALLOWED, "only GET/HEAD");
    }
    let is_head = method == Method::HEAD;
    let path = req.uri().path().to_string();
    // TASK-33: the remaining end-to-end header-wait budget propagated by a
    // DOWNSTREAM daemon in a chain, or `None` when this hop is the ENTRY (a
    // plain client - e.g. Nix - sends no such header). Passed to the budget-aware
    // source methods so the whole chain shares ONE shrinking deadline instead of
    // each hop re-granting a fresh `header_timeout`.
    let hop_budget = parse_hop_budget(req.headers());

    // Wave-1 choice: HEAD is answered by fetching upstream via GET (the source
    // traits carry no method) and dropping the body. Status/headers are correct,
    // but a HEAD narinfo still buffers the upstream body and a HEAD NAR still
    // opens the stream. Threading the method through the traits is a wave-2
    // refinement; documented here so it is a choice, not an oversight.
    match classify(&path) {
        Route::CacheInfo => respond_cache_info(&app.cache_info, is_head),
        Route::Narinfo(hash) => {
            let fetched = app.narinfo.fetch_within(&hash, hop_budget).await;
            respond_narinfo(
                fetched,
                &hash,
                &app.catalog,
                app.raw_serve.as_ref(),
                app.public_allowlist.as_ref(),
                is_head,
            )
            .await
        }
        Route::Nar(token) => {
            // Correlate: if the daemon saw this NAR's narinfo, carry the SIGNED
            // NarHash (the wave-2 lookup key) across the seam, plus the EXACT
            // requested token as the wave-1 transport hint and the signed NarSize
            // for the wave-2 abort bound (wave-1 UpstreamHttp ignores the size).
            // The hint is the inbound token itself, never derived from the hash,
            // so byte-identity survives a NarHash shared across compressions.
            // On an in-memory miss, consult PERSISTED correlation (task-8): the
            // narinfo disk cache derives token -> (hash, size) from cached
            // narinfos, so a warm-on-disk-but-cold-in-memory daemon still carries
            // the signed hash. Only when BOTH miss do we fall back to the raw URL
            // token - the documented cold-start degenerate (PRD risk 2).
            // In-memory catalog first (cheap, non-blocking); on a miss consult the
            // PERSISTED store, whose disk re-parse is `async` (TASK-28: run
            // off-worker) so it never stalls a Tokio worker on the NAR path.
            let correlated = match app.catalog.meta_for_token(token.as_str()) {
                Some(meta) => Some(meta),
                None => app.correlation.meta_for_token(token.as_str()).await,
            };
            // Capture the inbound token for the log's `path=` before it is moved
            // into the key; it is the exact NAR locator the client asked for.
            let nar_token = token.as_str().to_string();
            // TASK-77 announce-after-fetch: capture (signed NarHash, signed StorePath) BEFORE
            // `meta` is moved into the key, so a successful fetch of a correlated NAR whose
            // narinfo declared a store path can make this node a discoverable holder. Only the
            // SignedNarHash path (a correlated NAR with a store path) is eligible - an
            // UpstreamPath cold-start fetch has no NarHash to announce under, and a narinfo with
            // no unambiguous StorePath yields `None` (fail-safe: no store path, no holder claim).
            let announce_target: Option<(NarHash, String)> = correlated.as_ref().and_then(|meta| {
                meta.store_path
                    .clone()
                    .map(|sp| (meta.nar_hash.clone(), sp))
            });
            let (key, expected_size) = match correlated {
                Some(meta) => (
                    NarKey::SignedNarHash {
                        hash: meta.nar_hash,
                        upstream_hint: token,
                        // The AUTHORITATIVE narinfo transport descriptor (TASK-25): the
                        // HTTP source bounds the on-wire body by NarSize ONLY when this
                        // says Compression: none - never by the URL suffix.
                        transport: meta.transport,
                    },
                    Some(meta.nar_size),
                ),
                None => (NarKey::UpstreamPath(token), None),
            };
            let started = Instant::now();
            let result = app
                .nar
                .resolve_within(&key, expected_size, hop_budget)
                .await;
            // TASK-77: a successful (200) fetch of a correlated NAR triggers announce-after-fetch,
            // so this node becomes a discoverable holder and the swarm GROWS. Fire-and-forget: the
            // hook offloads onto its own task (a bounded wait for the local nix to materialise the
            // path, then a verified announce), so this never blocks or fails the serve. Firing at
            // resolve-success (rather than at stream-drain) is safe because the hook's hard gate is
            // materialisation + `sha256(--dump)==NarHash`: a truncated/aborted body the client never
            // imports leaves the path unmaterialised, so nothing is ever announced (fail-safe). A
            // consume-only (leech) node has `post_fetch_announce == None` and never reaches here.
            if let (Some(hook), Some((nar_hash, store_path)), Ok(resp)) =
                (&app.post_fetch_announce, &announce_target, &result)
                && resp.status == 200
            {
                hook.on_fetched(nar_hash, store_path);
            }
            // The per-substitution log line is emitted on STREAM COMPLETION (not
            // here at header arrival): `forward_nar` wraps the streamed body so the
            // narrated `bytes=` is the ACTUAL drained count and `duration_ms=` covers
            // the whole transfer (TASK-31). A truncated/aborted stream is narrated
            // honestly, never as a completed substitution.
            forward_nar(
                result,
                is_head,
                &app.upstream_label,
                &nar_token,
                started,
                stdout_substitution_sink(),
            )
        }
        Route::Other => forward(app.passthrough.get_within(&path, hop_budget).await, is_head),
    }
}

/// Parse the remaining end-to-end header-wait budget from the inbound request's
/// [`crate::upstream::HOP_BUDGET_HEADER`] (integer milliseconds), propagated by a
/// downstream daemon in a chain (TASK-33).
///
///   * ABSENT / unparsable / non-numeric -> `None`: treat this hop as the chain
///     ENTRY and seed the budget from its own `header_timeout`. Failing OPEN on a
///     garbled header is safe - the worst case is a hop uses its full local
///     timeout, i.e. the wave-1 behaviour.
///   * `0` -> `Some(0)`: the downstream says its deadline is already spent, so
///     this hop must fail fast rather than start a fresh full timeout.
///
/// A hostile/oversized value cannot make this hop wait longer than its own
/// `header_timeout`: [`crate::upstream::composed_header_wait`] takes the MIN, so
/// no clamp is needed here.
fn parse_hop_budget(headers: &HeaderMap) -> Option<Duration> {
    let raw = headers.get(crate::upstream::HOP_BUDGET_HEADER)?;
    let ms: u64 = raw.to_str().ok()?.trim().parse().ok()?;
    Some(Duration::from_millis(ms))
}

/// Serve the locally-generated cache-info body (never proxied).
fn respond_cache_info(info: &CacheInfo, is_head: bool) -> Response<NarBody> {
    let body = info.render().into_bytes();
    let len = body.len();
    let builder = Response::builder()
        .status(StatusCode::OK)
        .header(http::header::CONTENT_TYPE, "text/x-nix-cache-info")
        .header(http::header::CONTENT_LENGTH, len);
    let body = if is_head { empty() } else { full(body.into()) };
    builder
        .body(body)
        .expect("cache-info response is well-formed")
}

/// Narinfo: buffered so the (empty, wave-1) rewrite allowlist runs and
/// byte-fidelity is guaranteed. Non-200 statuses forward verbatim (AC#4).
///
/// This is also where correlation and the task-49 transport rewrite happen: on a
/// 200 we learn the `url-token -> (signed NarHash, NarSize)` mapping from the
/// narinfo body and, if `raw_serve` says the daemon will serve this NarHash's RAW
/// nar, rewrite the UNSIGNED transport fields to describe that raw nar and
/// correlate the REWRITTEN token. Otherwise the upstream narinfo is served
/// verbatim (the S2 path) and the original token is correlated.
async fn respond_narinfo(
    result: Result<UpstreamResponse, SourceError>,
    requested: &StoreHash,
    catalog: &NarCatalog,
    raw_serve: &dyn rewrite::RawServeDecision,
    public_allowlist: &crate::public_allowlist::PublicNarAllowlist,
    is_head: bool,
) -> Response<NarBody> {
    let resp = match result {
        Ok(resp) => resp,
        Err(err) => return gateway_error(&err),
    };
    // A non-200 (404/403/...) forwards verbatim - status fidelity.
    if resp.status != 200 {
        return forward(Ok(resp), is_head);
    }
    // Fail closed on a response we cannot faithfully forward (codex re-gate):
    // an unsupported transfer-coding (buffering + recomputing Content-Length over
    // an undecoded body would emit a Content-Length that disagrees with the coded
    // bytes) or a malformed Connection header we cannot safely parse.
    if must_fail_closed(&resp.headers) {
        eprintln!("daemon: refusing narinfo (unsupported coding / malformed Connection)");
        return text_status(StatusCode::BAD_GATEWAY, "upstream unavailable");
    }

    let UpstreamResponse { headers, body, .. } = resp;
    // Bound the buffered narinfo body (codex re-gate): a narinfo is ~1 KB;
    // anything past MAX_NARINFO_BYTES is a misbehaving upstream, not a narinfo.
    // Fail closed rather than buffer unboundedly. Defence-in-depth: the upstream
    // read is ALSO capped at this value, so no layer pre-buffers more.
    let bytes = match http_body_util::Limited::new(body, crate::source::MAX_NARINFO_BYTES)
        .collect()
        .await
    {
        Ok(collected) => collected.to_bytes(),
        Err(err) => {
            eprintln!(
                "daemon: reading narinfo body (or exceeds {} B): {err}",
                crate::source::MAX_NARINFO_BYTES
            );
            return text_status(StatusCode::BAD_GATEWAY, "upstream unavailable");
        }
    };

    // TASK-102: LEARN whether this exact cache.nixos.org response PROVES the NAR public.
    // `learn` verifies the trusted-key Nix signature over `1;StorePath;NarHash;NarSize;
    // References` and, only on success, appends `(NarHash, NarSize)` to the public-NAR
    // allowlist ONCE (idempotent). This is the SINGLE append site (AC#2): it runs on the
    // ORIGINAL upstream bytes (the signed fields are byte-identical before any rewrite),
    // and only a 200 that survived the framing checks above reaches here - a MISS/outage/
    // timeout returned earlier, so a non-public path appends nothing (AC#3). A daemon with
    // no configured trusted keys uses a disabled allowlist and this is a cheap no-op.
    // `learn` also correlates the signed StorePath to the EXACT `<requested>.narinfo` key,
    // so a response for a DIFFERENT path than the one requested appends nothing.
    match public_allowlist.learn(requested, &bytes) {
        crate::public_allowlist::LearnOutcome::Appended { nar_hash, nar_size } => {
            println!("daemon: public-allowlist appended narhash={nar_hash} nar_size={nar_size}");
        }
        crate::public_allowlist::LearnOutcome::PersistFailed(err) => {
            // Fail-verbose: the entry was NOT admitted (disk and memory agree), so a
            // later request simply re-verifies. Surface it rather than degrade silently.
            eprintln!("daemon: public-allowlist append failed (not admitted): {err}");
        }
        crate::public_allowlist::LearnOutcome::RequestMismatch { requested, signed } => {
            // A response whose signed StorePath does not match the requested key: never
            // learned. Surface it - it is either a misrouted cache or a hostile upstream.
            eprintln!(
                "daemon: public-allowlist ignored a mis-correlated narinfo \
                 (requested {requested}, signed {signed})"
            );
        }
        // AlreadyPresent (idempotent duplicate) and Rejected (not proven public - the
        // common case for a non-cache upstream or an unsigned path) are normal and silent.
        _ => {}
    }

    // Learn the token -> signed-NarHash correlation, and decide whether to rewrite
    // the narinfo's transport fields to describe the RAW nar (task-49). A malformed
    // narinfo yields no correlation, is never rewritten, and its NAR request falls
    // back to UpstreamPath - safe, never a hard failure. The rewrite decision is
    // keyed on the SIGNED NarHash the correlation carries.
    let correlation = parse_correlation(&bytes);
    // The rewrite decision is ASYNC: for a decentralized backend "will I serve this
    // raw?" is a discovery probe (TASK-164), not a static lookup. Await it only when
    // the narinfo actually correlated (a malformed narinfo is never rewritten).
    let rewrite_to_raw = match correlation.as_ref() {
        Some(c) => raw_serve.will_serve_raw(c.nar_hash.as_str()).await,
        None => false,
    };
    // TASK-77: the signed StorePath survives a rewrite unchanged (rewrite only touches the
    // UNSIGNED transport/URL fields, never the signed StorePath/NarHash), so capture it here
    // once for whichever record branch runs below - it is what announce-after-fetch registers.
    let correlated_store_path = correlation.as_ref().and_then(|c| c.store_path.clone());

    let (out_bytes, rewrote) = if rewrite_to_raw {
        match rewrite::to_raw(&bytes) {
            Ok(rw) => {
                // Correlate the REWRITTEN URL token (what the client requests next)
                // back to the signed NarHash, so GET /nar/<token> dispatches
                // SignedNarHash to the raw NAR source rather than 404 on a stale
                // compressed token. FileHash == NarHash and FileSize == NarSize by
                // construction (Compression: none), so the client's transport gate
                // passes against the raw bytes and its NarHash gate passes unchanged.
                catalog.record(
                    NarPathToken::new(rw.url_token),
                    NarHash::new(rw.nar_hash),
                    rw.nar_size,
                    // The rewritten narinfo is `Compression: none`, so the follow-up raw
                    // NAR fetch is bounded by the signed NarSize (like-for-like) - the
                    // authoritative transport for the raw token.
                    NarinfoTransport {
                        compression: NarCompression::Raw,
                    },
                    correlated_store_path.clone(),
                );
                (rw.body, true)
            }
            Err(err) => {
                // Fail SAFE, never half-rewritten: a narinfo will_serve_raw accepted
                // but to_raw could not rewrite is served VERBATIM. Record NO
                // correlation, so the follow-up NAR request takes the UpstreamPath
                // fallback and fetches the actual COMPRESSED bytes this verbatim
                // narinfo describes - never a rewritten token that a raw-only source
                // would mis-serve as raw under a Compression: xz narinfo. Should not
                // occur for a well-formed cache narinfo, so it is logged.
                eprintln!("daemon: narinfo rewrite-to-raw skipped ({err}); serving verbatim");
                (rewrite::apply(&bytes).into_owned(), false)
            }
        }
    } else {
        // Normal (non-peer) path: byte-identical passthrough - unknown fields, odd
        // ordering and multiple Sig lines all survive (AC#3).
        if let Some(c) = correlation {
            catalog.record(c.token, c.nar_hash, c.nar_size, c.transport, c.store_path);
        }
        (rewrite::apply(&bytes).into_owned(), false)
    };
    let len = out_bytes.len();

    let builder = Response::builder().status(StatusCode::OK);
    let mut response = builder
        .body(if is_head {
            empty()
        } else {
            full(out_bytes.into())
        })
        .expect("narinfo response is well-formed");
    forward_headers(response.headers_mut(), &headers);
    if rewrote {
        // The emitted body differs from upstream, so upstream validators no longer
        // describe it. Drop them rather than forward an ETag/Last-Modified for bytes
        // we did not send - byte-fidelity at the fidelity layer. nix verifies via
        // Sig/NarHash, not these, so nothing depends on them.
        let map = response.headers_mut();
        map.remove(http::header::ETAG);
        map.remove(http::header::LAST_MODIFIED);
    }
    // Content-Length must match the bytes we actually emit.
    let map = response.headers_mut();
    map.remove(http::header::CONTENT_LENGTH);
    map.insert(http::header::CONTENT_LENGTH, len.into());
    response
}

/// The outcome the daemon narrates once a NAR body has finished draining (or has
/// failed to). Fired ON STREAM COMPLETION by [`LoggingBody`], so the reported
/// `bytes` is the ACTUAL drained count and `duration` covers the whole transfer
/// (TASK-31) - not the wave-1 `Content-Length` + time-to-headers self-report.
///
/// THE UNIT (the NarSize-vs-FileSize trap - recurred): `bytes` is the count of
/// ON-WIRE body bytes drained, i.e. the COMPRESSED transport representation
/// (FileSize-scaled when the narinfo `Compression` is xz/zstd; equal to NarSize
/// only for `Compression: none`). It is the SAME unit the wave-1 `Content-Length`
/// reported - now COUNTED, not declared - and NEVER the uncompressed signed
/// NarSize, which is a different quantity for any compressed NAR.
#[derive(Debug, Clone, PartialEq, Eq)]
enum SubstitutionOutcome {
    /// The body reached a clean end (`poll_frame` -> `None`): a full, honest
    /// substitution of `bytes` on-wire bytes taking `duration`.
    Complete { bytes: u64, duration: Duration },
    /// The stream aborted before a clean end: an upstream truncation (hyper
    /// surfaces a short `Content-Length`/chunked body as an error), a TASK-25
    /// `BoundedBody` abort (idle-timeout / over-cap - it composes BELOW this
    /// wrapper and surfaces as an `Err` frame), or the client hanging up
    /// mid-stream (the body is dropped before completion). `bytes` were drained
    /// so far. This is NOT a successful substitution - it is deliberately NOT the
    /// `substituted` success line, so a truncated transfer is never mistaken for a
    /// full one (AC#3).
    Aborted {
        bytes: u64,
        duration: Duration,
        reason: String,
    },
}

/// Where a finished [`LoggingBody`] reports its [`SubstitutionOutcome`]. A trait
/// object (not a hard-coded `println!`) so a test can OBSERVE the outcome at the
/// right boundary - the drained byte count and the complete-vs-aborted decision -
/// while production prints the operator-facing lines.
type SubstitutionSink = Arc<dyn Fn(&str, &str, &SubstitutionOutcome) + Send + Sync>;

/// The production sink: prints one comprehensible line per NAR substitution the
/// daemon serves, so an operator tailing the daemon sees WHAT moved, FROM WHERE,
/// HOW MUCH, and HOW LONG.
///
///   * a COMPLETE drain prints the pinned `daemon: substituted ...` success line
///     on stdout (consumed by `scripts/journey.py` + `scripts/measure.py`);
///   * an ABORT prints a DISTINCT `daemon: substitution-aborted ...` line on
///     stderr carrying the PARTIAL drained count - fail-verbose, and never the
///     `substituted` token, so nothing mistakes it for a full substitution.
fn stdout_substitution_sink() -> SubstitutionSink {
    Arc::new(
        |source: &str, nar_token: &str, outcome: &SubstitutionOutcome| match outcome {
            SubstitutionOutcome::Complete { bytes, duration } => {
                println!(
                    "daemon: substituted path=/nar/{nar_token} source={source} \
                     bytes={bytes} duration_ms={}",
                    duration.as_millis()
                );
            }
            SubstitutionOutcome::Aborted {
                bytes,
                duration,
                reason,
            } => {
                eprintln!(
                    "daemon: substitution-aborted path=/nar/{nar_token} source={source} \
                     bytes={bytes} duration_ms={} reason={reason}",
                    duration.as_millis()
                );
            }
        },
    )
}

/// Wraps a streamed NAR body to ACCOUNT the transfer at its real boundary
/// (TASK-31). It counts drained frame-data bytes as they pass through and, ON
/// STREAM COMPLETION, reports a [`SubstitutionOutcome`] to a [`SubstitutionSink`]
/// exactly once.
///
/// Composition with TASK-25 (load-bearing): this wraps the body returned by
/// `upstream::fetch_streaming`, which is ALREADY a `BoundedBody` (the per-read
/// idle timeout + the per-chunk over-cap abort). `LoggingBody` sits ABOVE it, so
/// those aborts arrive here as `Err` frames and are narrated as `Aborted` - never
/// as a completed substitution. The two wrappers compose; this one adds no bound,
/// only honest accounting.
struct LoggingBody<B> {
    inner: B,
    /// Request-dispatch instant; `duration` is `start.elapsed()` AT COMPLETION, so
    /// it spans the whole transfer, not just the header wait (AC#2).
    start: Instant,
    source: String,
    nar_token: String,
    /// Cumulative ON-WIRE body bytes drained so far (the compressed transport unit).
    drained: u64,
    sink: SubstitutionSink,
    /// Fuse: the outcome is reported exactly once (a clean end, an error, or Drop).
    reported: bool,
}

impl<B> LoggingBody<B> {
    fn new(
        inner: B,
        start: Instant,
        source: String,
        nar_token: String,
        sink: SubstitutionSink,
    ) -> Self {
        LoggingBody {
            inner,
            start,
            source,
            nar_token,
            drained: 0,
            sink,
            reported: false,
        }
    }

    /// Report `outcome` to the sink at most once (fuse). Idempotent: a clean end
    /// followed by Drop, or an error followed by Drop, reports only the first.
    fn report(&mut self, outcome: SubstitutionOutcome) {
        if self.reported {
            return;
        }
        self.reported = true;
        (self.sink)(&self.source, &self.nar_token, &outcome);
    }
}

impl<B> Body for LoggingBody<B>
where
    B: Body<Data = Bytes, Error = std::io::Error> + Unpin,
{
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, std::io::Error>>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    this.drained = this.drained.saturating_add(data.remaining() as u64);
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(e))) => {
                // A mid-stream error (upstream truncation, or a TASK-25 BoundedBody
                // abort below us): narrate an honest PARTIAL transfer and forward the
                // error unchanged so hyper/Nix still see the failed download.
                let reason = e.to_string();
                this.report(SubstitutionOutcome::Aborted {
                    bytes: this.drained,
                    duration: this.start.elapsed(),
                    reason,
                });
                Poll::Ready(Some(Err(e)))
            }
            Poll::Ready(None) => {
                this.report(SubstitutionOutcome::Complete {
                    bytes: this.drained,
                    duration: this.start.elapsed(),
                });
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.reported
    }
}

impl<B> Drop for LoggingBody<B> {
    fn drop(&mut self) {
        // The body was dropped before a clean end or an error surfaced: the client
        // hung up (or the handler was cancelled) mid-transfer. Narrate it honestly
        // as an abort with the partial count - never a completed substitution.
        if !self.reported {
            self.report(SubstitutionOutcome::Aborted {
                bytes: self.drained,
                duration: self.start.elapsed(),
                reason: "body dropped before completion (client hung up or handler cancelled)"
                    .to_string(),
            });
        }
    }
}

/// Forward a streamed NAR response, accounting the transfer on completion.
///
/// Only a `200` GET is an actual substitution whose body is drained: its body is
/// wrapped in a [`LoggingBody`] so the log line fires on completion with the real
/// drained byte count and full duration. A HEAD (no body drained) and a non-200
/// (a 404/403 is not a substitution) are forwarded verbatim and NOT narrated - the
/// same events the wave-1 header-time logger skipped.
fn forward_nar(
    result: Result<UpstreamResponse, SourceError>,
    is_head: bool,
    source: &str,
    nar_token: &str,
    started: Instant,
    sink: SubstitutionSink,
) -> Response<NarBody> {
    let resp = match result {
        Ok(resp) => resp,
        Err(err) => return gateway_error(&err),
    };
    if must_fail_closed(&resp.headers) {
        eprintln!("daemon: refusing response (unsupported coding / malformed Connection)");
        return text_status(StatusCode::BAD_GATEWAY, "upstream unavailable");
    }
    let UpstreamResponse {
        status,
        headers,
        body,
    } = resp;
    let status_code = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY);
    let body = if is_head {
        empty()
    } else if status == 200 {
        LoggingBody::new(
            body,
            started,
            source.to_string(),
            nar_token.to_string(),
            sink,
        )
        .boxed()
    } else {
        // A non-200 body forwards verbatim; it is not a substitution to account.
        body
    };
    let mut response = Response::builder()
        .status(status_code)
        .body(body)
        .expect("forwarded NAR response is well-formed");
    forward_headers(response.headers_mut(), &headers);
    response
}

/// Forward a streaming upstream response (NAR / passthrough) verbatim.
fn forward(result: Result<UpstreamResponse, SourceError>, is_head: bool) -> Response<NarBody> {
    let resp = match result {
        Ok(resp) => resp,
        Err(err) => return gateway_error(&err),
    };
    // Fail closed on a response we cannot faithfully forward (codex re-gate):
    // an unsupported transfer-coding (hyper strips only the final `chunked`, so a
    // `gzip, chunked` or `chunked, chunked` body streams out mis-framed) or a
    // malformed Connection header.
    if must_fail_closed(&resp.headers) {
        eprintln!("daemon: refusing response (unsupported coding / malformed Connection)");
        return text_status(StatusCode::BAD_GATEWAY, "upstream unavailable");
    }
    let UpstreamResponse {
        status,
        headers,
        body,
    } = resp;
    let status = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY);
    let mut response = Response::builder()
        .status(status)
        .body(if is_head { empty() } else { body })
        .expect("forwarded response is well-formed");
    // Verbatim transport headers - INCLUDING Content-Encoding and
    // Content-Length - are the crux of AC#6: a gzip NAR is relayed unchanged
    // for the client to decompress and verify.
    forward_headers(response.headers_mut(), &headers);
    response
}

/// The daemon's forwarded/stripped header allowlist, documented so it is a
/// deliberate policy and asserted by `daemon/tests/header_hygiene.rs` (task-13).
/// The daemon is a TRANSPARENT proxy, so the policy is deny-a-fixed-set,
/// forward-everything-else - the inverse of a curated allowlist, because the
/// content-integrity fields the client verifies (`Content-Encoding`,
/// `Content-Length`, `ETag`, and every end-to-end header) must survive verbatim
/// and enumerating them would silently drop any we forgot.
///
/// Three classes:
///   * STRIP (never relayed) - the RFC 7230 §6.1 hop-by-hop headers below, PLUS
///     any field-name listed in a `Connection:` header value. These describe a
///     single TCP hop (this client<->that server) and are meaningless, or
///     actively wrong, one hop further on.
///   * FORWARD verbatim (everything else) - crucially `Content-Encoding` (a gzip
///     NAR relays unchanged for the client to decompress + verify, AC#6),
///     `Content-Type`, `ETag`, `Last-Modified`, `Cache-Control`, `Accept-Ranges`
///     and any `X-*`. The daemon adds NO decoding layer, so these pass byte-exact.
///   * NEVER TOUCH - the narinfo BODY (the signed fingerprint) and the NAR bytes.
///     Header hygiene here concerns the response HEADER MAP only; `Content-Length`
///     is the one header the serving layer RECOMPUTES, and only for the buffered
///     narinfo path where it must equal the bytes actually emitted (see
///     `respond_narinfo`). On the streamed NAR path even `Content-Length` is
///     forwarded verbatim.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Copy every header except hop-by-hop ones (which belong to a single
/// connection and must not be relayed). Honours the `Connection:` header's own
/// token list per RFC 7230 §6.1: `Connection: X-Foo` marks `X-Foo` hop-by-hop
/// for this message, so it is stripped too - a keep-alive/desync hazard the
/// long-chain hardening (task-11/task-13) specifically guards against.
fn forward_headers(dst: &mut HeaderMap, src: &HeaderMap) {
    let connection_tokens = connection_listed_tokens(src);
    for (name, value) in src {
        if is_hop_by_hop(name) || connection_tokens.contains(name.as_str().as_bytes()) {
            continue;
        }
        dst.append(name.clone(), value.clone());
    }
}

/// The lower-cased field-names named in any well-formed `Connection:` header
/// value. A MALFORMED Connection value (obs-text/control token) never reaches
/// here: `connection_header_is_malformed` fails the whole response closed at the
/// serving-layer gate before `forward_headers` runs. For a well-formed value we
/// parse the raw bytes and add EVERY listed token, incl `close`/`keep-alive`:
/// those are connection directives with no legitimate end-to-end header of the
/// same name, so stripping a same-named header is harmless and strictly safer.
fn connection_listed_tokens(src: &HeaderMap) -> std::collections::HashSet<Vec<u8>> {
    let mut tokens = std::collections::HashSet::new();
    for value in src.get_all(http::header::CONNECTION) {
        for token in value.as_bytes().split(|&b| b == b',') {
            let token = crate::source::ascii_lower_trim(token);
            if !token.is_empty() {
                tokens.insert(token);
            }
        }
    }
    tokens
}

fn is_hop_by_hop(name: &HeaderName) -> bool {
    HOP_BY_HOP.contains(&name.as_str())
}

/// The serving-layer fail-closed gate: a response the daemon cannot faithfully
/// forward (an unsupported transfer-coding, or a malformed `Connection` header we
/// cannot safely parse) becomes a clean 502 rather than a mislabeled/leaky
/// forward. Applied before building EVERY forwarded response (codex re-gate).
fn must_fail_closed(headers: &HeaderMap) -> bool {
    crate::source::has_unsupported_transfer_coding(headers)
        || crate::source::connection_header_is_malformed(headers)
        || crate::source::has_ambiguous_framing(headers)
}

/// Map a transport failure to a fast, clean gateway error so Nix falls back.
fn gateway_error(err: &SourceError) -> Response<NarBody> {
    eprintln!("daemon: {err}");
    text_status(StatusCode::BAD_GATEWAY, "upstream unavailable")
}

fn text_status(status: StatusCode, message: &str) -> Response<NarBody> {
    let body = format!("{message}\n").into_bytes();
    let len = body.len();
    Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "text/plain")
        .header(http::header::CONTENT_LENGTH, len)
        .body(full(body.into()))
        .expect("status response is well-formed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_covers_the_cache_api() {
        assert!(matches!(classify("/nix-cache-info"), Route::CacheInfo));
        assert!(matches!(classify("/abc123.narinfo"), Route::Narinfo(_)));
        assert!(matches!(classify("/nar/1xyz.nar.xz"), Route::Nar(_)));
        assert!(matches!(classify("/log/foo"), Route::Other));
        assert!(matches!(classify("/foo.ls"), Route::Other));
    }

    #[test]
    fn narinfo_hash_is_extracted_without_extension() {
        match classify("/0a0lslqb6gbqnj6xqjlaljjqg6kgb3wz.narinfo") {
            Route::Narinfo(h) => assert_eq!(h.as_str(), "0a0lslqb6gbqnj6xqjlaljjqg6kgb3wz"),
            _ => panic!("expected narinfo route"),
        }
    }

    #[test]
    fn nar_locator_keeps_its_suffix() {
        match classify("/nar/1abcd.nar.xz") {
            Route::Nar(h) => assert_eq!(h.as_str(), "1abcd.nar.xz"),
            _ => panic!("expected nar route"),
        }
    }

    #[tokio::test]
    async fn none_narinfo_without_filehash_correlates_and_dispatches_p2p() {
        // TASK-220 biting integration test at the serving layer. A `Compression: none`
        // narinfo that OMITS FileHash arrives on the p2p-discovery HIT path
        // (will_serve_raw = true). The daemon MUST rewrite it to raw AND record the
        // token -> SignedNarHash correlation, so the follow-up GET /nar/<token>
        // dispatches the SignedNarHash (p2p) source - NOT the URL-less UpstreamPath.
        //
        // BITE: before the rewrite fix, to_raw returned MissingField(FileHash), so
        // respond_narinfo took the verbatim else-branch that records NO correlation;
        // meta_for_token would then be None and Route::Nar would fall to UpstreamPath.
        // The assertions below hold only once to_raw stops over-rejecting this class.
        let digest = "06rgb4vfjsg365xwwdjz12qhjnvg3w0agfvyqfp977hp3yk2bczb";
        let body = format!(
            "StorePath: /nix/store/0a0lslqb6gbqnj6xqjlaljjqg6kgb3wz-nix-p2p-fixture-lib\n\
URL: nar/{digest}.nar\n\
Compression: none\n\
NarHash: sha256:{digest}\n\
NarSize: 66048\n\
References: \n\
Sig: nix-p2p-test-1:kvRtCi6KujoW6x7esqgP8QdiaaVX4OL1beI/xmfobVHzM/tSSqmy7jcnI7QDognLkmkwaSgA6vraWOYN0kiICw==\n"
        );
        let mut headers = HeaderMap::new();
        headers.insert(http::header::CONTENT_LENGTH, body.len().into());
        let resp = UpstreamResponse {
            status: 200,
            headers,
            body: full(bytes::Bytes::from(body.into_bytes())),
        };

        let catalog = NarCatalog::new();
        // will_serve_raw = YES for this NarHash: the p2p-discovery HIT that triggers
        // the rewrite-to-raw branch (the exact path where the bug lived).
        let raw_serve = rewrite::AllowlistRawServe::new([format!("sha256:{digest}")]);
        let public = crate::public_allowlist::PublicNarAllowlist::disabled();
        let requested = StoreHash::new("0a0lslqb6gbqnj6xqjlaljjqg6kgb3wz");

        let response =
            respond_narinfo(Ok(resp), &requested, &catalog, &raw_serve, &public, false).await;
        assert_eq!(response.status(), StatusCode::OK);

        // The token the client requests next (the rewritten raw URL token).
        let token = format!("{digest}.nar");
        let meta = catalog.meta_for_token(&token).expect(
            "correlation MUST be recorded for a Compression: none narinfo lacking FileHash - \
             without it the NAR request falls to the URL-less UpstreamPath and p2p is disabled",
        );
        // Route::Nar dispatches the SignedNarHash (p2p) source IFF meta_for_token is
        // Some; prove the recorded meta carries the SIGNED nar identity and the
        // authoritative raw transport (NarSize, not a compressed unit).
        assert_eq!(meta.nar_hash.as_str(), format!("sha256:{digest}"));
        assert_eq!(meta.nar_size, 66048);
        assert_eq!(meta.transport.compression, NarCompression::Raw);
    }

    #[test]
    fn hop_by_hop_headers_are_dropped() {
        let mut src = HeaderMap::new();
        src.insert("content-encoding", "gzip".parse().unwrap());
        src.insert("connection", "close".parse().unwrap());
        src.insert("transfer-encoding", "chunked".parse().unwrap());
        let mut dst = HeaderMap::new();
        forward_headers(&mut dst, &src);
        assert_eq!(dst.get("content-encoding").unwrap(), "gzip");
        assert!(dst.get("connection").is_none());
        assert!(dst.get("transfer-encoding").is_none());
    }

    // ----- TASK-31: full-drain byte + duration accounting (LoggingBody) -----

    use std::collections::VecDeque;
    use std::future::Future;
    use std::sync::Mutex;
    use tokio::time::Sleep;

    /// A scripted body that yields a fixed sequence of frames, optionally pacing a
    /// `gap` of real time BEFORE each frame (to exercise duration accounting). A
    /// `Fail` step terminates the stream with an `io::Error` (an upstream
    /// truncation / reset), mirroring how hyper surfaces a short body.
    enum Step {
        Data(Vec<u8>),
        Fail(String),
    }

    struct StepBody {
        steps: VecDeque<Step>,
        gap: Duration,
        delay: Option<Pin<Box<Sleep>>>,
    }

    impl StepBody {
        fn new(steps: Vec<Step>, gap: Duration) -> Self {
            StepBody {
                steps: steps.into(),
                gap,
                delay: None,
            }
        }
    }

    impl Body for StepBody {
        type Data = Bytes;
        type Error = std::io::Error;

        fn poll_frame(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, std::io::Error>>> {
            let this = self.get_mut();
            // Pace: wait `gap` of real time before delivering the next frame, so the
            // drain takes measurable wall-clock time (the AC#2 slow-body oracle).
            if this.gap > Duration::ZERO && !this.steps.is_empty() {
                if this.delay.is_none() {
                    this.delay = Some(Box::pin(tokio::time::sleep(this.gap)));
                }
                if let Some(d) = this.delay.as_mut() {
                    match d.as_mut().poll(cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(()) => this.delay = None,
                    }
                }
            }
            match this.steps.pop_front() {
                Some(Step::Data(d)) => Poll::Ready(Some(Ok(Frame::data(Bytes::from(d))))),
                Some(Step::Fail(msg)) => Poll::Ready(Some(Err(std::io::Error::other(msg)))),
                None => Poll::Ready(None),
            }
        }
    }

    type Records = Arc<Mutex<Vec<(String, String, SubstitutionOutcome)>>>;

    /// A sink that CAPTURES every reported outcome, so a test observes the drained
    /// count and the complete-vs-aborted decision at the real boundary.
    fn capturing_sink() -> (SubstitutionSink, Records) {
        let records: Records = Arc::new(Mutex::new(Vec::new()));
        let sink_records = Arc::clone(&records);
        let sink: SubstitutionSink = Arc::new(
            move |source: &str, token: &str, outcome: &SubstitutionOutcome| {
                sink_records.lock().unwrap().push((
                    source.to_string(),
                    token.to_string(),
                    outcome.clone(),
                ));
            },
        );
        (sink, records)
    }

    /// Drain a body to the end (or first error), returning the total drained bytes
    /// or the propagated error. This is what hyper does while serving to Nix.
    async fn drain<B>(mut body: B) -> Result<u64, std::io::Error>
    where
        B: Body<Data = Bytes, Error = std::io::Error> + Unpin,
    {
        let mut total = 0u64;
        while let Some(frame) = body.frame().await {
            let frame = frame?;
            if let Some(d) = frame.data_ref() {
                total += d.remaining() as u64;
            }
        }
        Ok(total)
    }

    // AC#1 BITE: with NO Content-Length in play, the logged byte count is the
    // ACTUAL drained sum of the frames - not Content-Length (there is none) and not
    // the signed NarSize. The wave-1 logger printed `bytes=unknown` for exactly this
    // chunked, length-less case; full-drain accounting replaces it with an honest
    // COMPRESSED on-wire byte count.
    #[tokio::test]
    async fn ac1_logs_actual_drained_bytes_not_content_length() {
        let (sink, records) = capturing_sink();
        // Chunked-style: three frames, 7 + 5 + 3 = 15 on-wire bytes, no length header.
        let inner = StepBody::new(
            vec![
                Step::Data(vec![0u8; 7]),
                Step::Data(vec![0u8; 5]),
                Step::Data(vec![0u8; 3]),
            ],
            Duration::ZERO,
        );
        let body = LoggingBody::new(
            inner,
            Instant::now(),
            "cache.example".to_string(),
            "deadbeef.nar.xz".to_string(),
            sink,
        );
        let drained = drain(body).await.expect("clean drain");
        assert_eq!(drained, 15, "the drain itself moved 15 bytes");

        let rec = records.lock().unwrap();
        assert_eq!(rec.len(), 1, "exactly one outcome reported on completion");
        let (source, token, outcome) = &rec[0];
        assert_eq!(source, "cache.example");
        assert_eq!(token, "deadbeef.nar.xz");
        match outcome {
            SubstitutionOutcome::Complete { bytes, .. } => {
                assert_eq!(
                    *bytes, 15,
                    "logged bytes MUST be the counted drain (15), never Content-Length/NarSize"
                );
            }
            other => panic!("expected Complete, got {other:?}"),
        }
    }

    // AC#2 BITE: a paced (slow) body makes `duration` reflect the WHOLE transfer,
    // emitted on completion - not the near-zero header latency. Real wall-clock is
    // used (not tokio paused time) because `duration` is a std `Instant::elapsed`.
    #[tokio::test]
    async fn ac2_duration_covers_full_body_transfer() {
        let (sink, records) = capturing_sink();
        let gap = Duration::from_millis(30);
        // Three frames paced 30ms apart => the body takes ~90ms to drain, whereas a
        // header-time logger would have recorded ~0ms.
        let inner = StepBody::new(
            vec![
                Step::Data(vec![0u8; 4]),
                Step::Data(vec![0u8; 4]),
                Step::Data(vec![0u8; 4]),
            ],
            gap,
        );
        let start = Instant::now();
        let body = LoggingBody::new(
            inner,
            start,
            "cache.example".to_string(),
            "paced.nar".to_string(),
            sink,
        );
        drain(body).await.expect("clean drain");

        let rec = records.lock().unwrap();
        assert_eq!(rec.len(), 1);
        match &rec[0].2 {
            SubstitutionOutcome::Complete { bytes, duration } => {
                assert_eq!(*bytes, 12);
                // Loose lower bound (>= 2 gaps) tolerates scheduler jitter while still
                // proving the duration spans the body, not just the header wait.
                assert!(
                    *duration >= gap * 2,
                    "duration {duration:?} must cover the paced body (>= {:?})",
                    gap * 2
                );
            }
            other => panic!("expected Complete, got {other:?}"),
        }
    }

    // AC#3 BITE: a truncated stream (data then a mid-stream error) is narrated as an
    // Aborted PARTIAL transfer - NEVER a Complete substitution. The `substituted`
    // success line is therefore never emitted for a truncated body, and the reported
    // bytes are the honest partial count.
    #[tokio::test]
    async fn ac3_truncated_stream_is_aborted_not_substituted() {
        let (sink, records) = capturing_sink();
        // 4 + 4 = 8 bytes arrive, then the upstream truncates mid-stream.
        let inner = StepBody::new(
            vec![
                Step::Data(vec![0u8; 4]),
                Step::Data(vec![0u8; 4]),
                Step::Fail("connection reset: body truncated mid-stream".to_string()),
            ],
            Duration::ZERO,
        );
        let body = LoggingBody::new(
            inner,
            Instant::now(),
            "cache.example".to_string(),
            "truncated.nar.xz".to_string(),
            sink,
        );
        let err = drain(body)
            .await
            .expect_err("a truncated stream surfaces an error");
        assert!(err.to_string().contains("truncated"));

        let rec = records.lock().unwrap();
        assert_eq!(rec.len(), 1, "exactly one outcome reported");
        match &rec[0].2 {
            SubstitutionOutcome::Aborted { bytes, reason, .. } => {
                assert_eq!(*bytes, 8, "honest partial count, not a full length");
                assert!(reason.contains("truncated"));
            }
            other => panic!("a truncated transfer must be Aborted, never {other:?}"),
        }
        // The load-bearing negative: no Complete/`substituted` outcome exists.
        assert!(
            !rec.iter()
                .any(|(_, _, o)| matches!(o, SubstitutionOutcome::Complete { .. })),
            "a truncated stream must NEVER be logged as a completed substitution"
        );
    }

    // AC#3 (client-hangup variant): a body dropped before a clean end - the client
    // hung up mid-download - is narrated as Aborted with the partial count, never a
    // completed substitution.
    #[tokio::test]
    async fn client_hangup_midstream_is_aborted_not_substituted() {
        let (sink, records) = capturing_sink();
        let inner = StepBody::new(
            vec![Step::Data(vec![0u8; 6]), Step::Data(vec![0u8; 6])],
            Duration::ZERO,
        );
        let mut body = LoggingBody::new(
            inner,
            Instant::now(),
            "cache.example".to_string(),
            "hangup.nar".to_string(),
            sink,
        );
        // Pull exactly one frame, then drop the body (client disconnected).
        let first = body.frame().await.expect("a frame").expect("ok frame");
        assert_eq!(first.data_ref().map(|d| d.remaining()), Some(6));
        drop(body);

        let rec = records.lock().unwrap();
        assert_eq!(rec.len(), 1);
        match &rec[0].2 {
            SubstitutionOutcome::Aborted { bytes, reason, .. } => {
                assert_eq!(*bytes, 6, "only the drained-so-far bytes are honest");
                assert!(reason.contains("dropped before completion"));
            }
            other => panic!("a mid-stream drop must be Aborted, never {other:?}"),
        }
    }
}
