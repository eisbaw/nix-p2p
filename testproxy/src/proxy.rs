//! The caching proxy request handler and its shared state.
//!
//! Flow for a cache request: consult armed faults (which may short-circuit),
//! then serve from the disk cache on a hit or fetch-and-cache on a miss. NARs
//! stream through a fixed buffer so a 110 MiB payload never sits whole in
//! memory; metadata (cache-info, narinfo) is small and handled in one shot.
//!
//! Fault discipline (the load-bearing invariant): the disk cache is always
//! written with upstream-correct bytes. Corrupt/truncate faults mutate only the
//! bytes handed to the *client*, so AC#3 integrity (never a partial/corrupt
//! cache entry, even under concurrency or an active fault) holds by
//! construction.

use crate::cache::DiskCache;
use crate::config::Config;
use crate::fault::{self, FaultConfig, Scope};
use crate::http::{self, Request};
use crate::kind::{Kind, classify};
use crate::record::{Log, Record};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Bytes streamed per read/write iteration for NAR bodies. Fixed so memory use
/// is O(1) in payload size - the "streams large NARs without whole-file
/// buffering" half of AC#3.
const STREAM_BUF: usize = 64 * 1024;

/// Shared, thread-safe proxy state.
pub struct State {
    pub config: Config,
    pub cache: DiskCache,
    pub faults: Mutex<FaultConfig>,
    pub log: Mutex<Log>,
    /// nar-url -> the instant the narinfo pointing at it was served. Feeds the
    /// gap oracle (narinfo -> nar request gap, per path).
    gaps: Mutex<HashMap<String, Instant>>,
    /// Non-admin request handlers that have started but not yet appended their
    /// completion record. Admin observation never contributes to this count.
    in_flight: AtomicU64,
    /// Per-cold-path single-flight coordinator: collapses N concurrent misses
    /// for the SAME NAR path into ONE upstream fetch (task-23). Distinct from
    /// `in_flight` above, which is a request COUNTER, not a coalescer.
    single_flight: Arc<SingleFlight>,
}

impl State {
    pub fn new(config: Config) -> std::io::Result<Arc<State>> {
        let cache = DiskCache::new(config.cache_dir.clone())?;
        Ok(Arc::new(State {
            config,
            cache,
            faults: Mutex::new(FaultConfig::default()),
            log: Mutex::new(Log::default()),
            gaps: Mutex::new(HashMap::new()),
            in_flight: AtomicU64::new(0),
            single_flight: Arc::new(SingleFlight::default()),
        }))
    }

    /// Number of non-admin handlers whose completion record is not yet visible.
    pub fn in_flight(&self) -> u64 {
        self.in_flight.load(Ordering::SeqCst)
    }
}

/// Keeps [`State::in_flight`] correct on every exit path, including panics.
struct InFlightGuard<'a> {
    count: &'a AtomicU64,
}

impl<'a> InFlightGuard<'a> {
    fn enter(count: &'a AtomicU64) -> Self {
        count.fetch_add(1, Ordering::SeqCst);
        Self { count }
    }
}

impl Drop for InFlightGuard<'_> {
    fn drop(&mut self) {
        let previous = self.count.fetch_sub(1, Ordering::SeqCst);
        debug_assert!(previous > 0, "in-flight proxy request count underflow");
    }
}

/// Per-cold-path single-flight coordinator for NAR misses (task-23).
///
/// The FIRST concurrent miss for a given resolved disk path becomes the LEADER
/// and performs the one upstream fetch; every other concurrent miss for the
/// SAME path becomes a WAITER that blocks until the leader has committed, then
/// serves the committed entry as an ordinary cache HIT instead of fetching
/// upstream itself. So N concurrent misses for one cold path cause exactly ONE
/// upstream fetch.
///
/// Keyed by the resolved disk path, so DIFFERENT paths never block each other -
/// this coalesces redundant work WITHOUT serialising unrelated fetches.
///
/// Deliberately narrow: this layer decides only WHO fetches. It does not touch
/// the egress path, so every request (leader and waiter alike) still runs the
/// normal hit/miss serve code that applies fault injection to its OWN client
/// stream. Coalescing therefore cannot let a waiter bypass a
/// truncate/corrupt/throttle fault, and the cache still receives only
/// upstream-correct bytes from the single leader (AC#3 integrity unchanged).
///
/// Known limit (blast radius): same-path waiters block on the SINGLE leader's
/// liveness with no independent deadline, so a slow leader stalls its whole
/// same-path herd for as long as it runs. It is bounded, not unbounded - the
/// leader's own upstream read is capped by the 60 s idle timeout in
/// `http::upstream_get`, after which it abandons and a waiter re-leads - but a
/// slow-drip upstream can keep the leader (and thus the herd) alive past that
/// per-read idle bound. Acceptable for a localhost test fixture; noted so it is
/// a known property, not a surprise.
#[derive(Default)]
struct SingleFlight {
    inflight: Mutex<HashMap<PathBuf, Arc<Flight>>>,
}

/// One in-progress leader fetch that waiters block on. `done` flips true exactly
/// once, when the leader's [`LeaseGuard`] is dropped (after commit OR failure).
struct Flight {
    done: Mutex<bool>,
    ready: Condvar,
}

/// The result of trying to claim a cold path.
enum Lease {
    /// This request is the leader and must perform the upstream fetch. The guard
    /// wakes every waiter (and clears the map entry) when dropped, so it MUST be
    /// held until AFTER the cache commit.
    Lead(LeaseGuard),
    /// Another request led and has now finished; the caller re-checks the cache
    /// (a committed leader makes it a hit; a failed leader leaves it a miss to
    /// retry as a fresh leader).
    Waited,
}

/// Held by the leader across the whole fetch + commit. Dropping it removes the
/// map entry and wakes every waiter - so it must outlive the commit, else a
/// waiter could wake to a not-yet-committed (still-missing) file.
struct LeaseGuard {
    sf: Arc<SingleFlight>,
    path: PathBuf,
    flight: Arc<Flight>,
}

impl SingleFlight {
    /// Claim `path` as leader, or block until the current leader for `path`
    /// finishes and return [`Lease::Waited`].
    fn lease(self: &Arc<Self>, path: &Path) -> Lease {
        let mut map = self.inflight.lock().unwrap();
        if let Some(flight) = map.get(path).cloned() {
            // Someone is already fetching this path: wait for them, holding no
            // map lock so other paths stay unblocked.
            drop(map);
            let mut done = flight.done.lock().unwrap();
            while !*done {
                done = flight.ready.wait(done).unwrap();
            }
            Lease::Waited
        } else {
            let flight = Arc::new(Flight {
                done: Mutex::new(false),
                ready: Condvar::new(),
            });
            map.insert(path.to_path_buf(), Arc::clone(&flight));
            Lease::Lead(LeaseGuard {
                sf: Arc::clone(self),
                path: path.to_path_buf(),
                flight,
            })
        }
    }
}

impl Drop for LeaseGuard {
    fn drop(&mut self) {
        // Remove the entry FIRST, then signal done and wake waiters. A brand-new
        // miss arriving after the commit finds no entry AND a committed file, so
        // it serves the hit without ever leasing; existing waiters re-check the
        // cache on wake.
        self.sf.inflight.lock().unwrap().remove(&self.path);
        *self.flight.done.lock().unwrap() = true;
        self.flight.ready.notify_all();
    }
}

/// What one served request produced, before it becomes a log [`Record`].
struct Outcome {
    status: u16,
    bytes_sent: u64,
    upstream: bool,
    fault: Option<String>,
    gap_ms: Option<f64>,
}

impl Outcome {
    fn served(status: u16, bytes_sent: u64, upstream: bool) -> Self {
        Outcome {
            status,
            bytes_sent,
            upstream,
            fault: None,
            gap_ms: None,
        }
    }
}

/// Entry point: handle one request on `stream`.
pub fn handle(state: &Arc<State>, request: Request, mut stream: TcpStream) {
    let path = request.path().to_string();

    // Admin endpoints are the fixture's control/observability surface; they are
    // deliberately NOT logged as cache traffic (that would pollute the oracle).
    if path.starts_with("/__testproxy/") {
        admin(state, &request, &mut stream);
        return;
    }
    let _in_flight = InFlightGuard::enter(&state.in_flight);

    let kind = classify(&path);
    let seq = state.log.lock().unwrap().next_seq();
    let faults = state.faults.lock().unwrap().clone();
    let started = Instant::now();
    let start_unix_ms = now_unix_ms();

    let outcome = serve(state, &request, kind, &faults, &mut stream);

    let record = Record {
        seq,
        kind,
        path,
        method: request.method.clone(),
        status: outcome.status,
        bytes_sent: outcome.bytes_sent,
        upstream: outcome.upstream,
        fault: outcome.fault,
        start_unix_ms,
        duration_ms: started.elapsed().as_secs_f64() * 1000.0,
        gap_ms: outcome.gap_ms,
    };
    state.log.lock().unwrap().push(record);
}

/// Apply faults then serve. Returns the outcome to log.
fn serve(
    state: &Arc<State>,
    request: &Request,
    kind: Kind,
    faults: &FaultConfig,
    stream: &mut TcpStream,
) -> Outcome {
    // Mode 3: connection reset - abandon the socket with no valid HTTP response.
    if faults.resets(kind) {
        let _ = stream.shutdown(Shutdown::Both);
        return Outcome {
            status: 0,
            bytes_sent: 0,
            upstream: false,
            fault: Some("connection-reset".into()),
            gap_ms: None,
        };
    }

    // Mode 2: HTTP 500/503.
    if let Some(code) = faults.http_error_for(kind) {
        let _ = http::write_response(stream, code, "text/plain", b"fault: http error\n");
        let mut outcome = Outcome::served(code, 0, false);
        outcome.fault = Some(format!("http-error-{code}"));
        return outcome;
    }

    // Mode 7: upstream unreachable - fast, clean gateway failure, no upstream
    // contacted (models "stop the container").
    if faults.unreachable {
        let _ = http::write_response(stream, 502, "text/plain", b"fault: upstream unreachable\n");
        let mut outcome = Outcome::served(502, 0, false);
        outcome.fault = Some("unreachable".into());
        return outcome;
    }

    // Mode 1: added latency, per path-kind. Applied before serving (hit or
    // miss alike) and tagged in the log so the bite has an in-process oracle
    // as well as the wall-clock one.
    let latency_applied = faults.latency_for(kind).inspect(|delay| {
        std::thread::sleep(*delay);
    });

    let mut outcome = match kind {
        Kind::CacheInfo => serve_metadata(state, request, kind, faults, stream),
        Kind::Narinfo => serve_metadata(state, request, kind, faults, stream),
        Kind::Nar => serve_nar(state, request, faults, stream),
        Kind::Other => serve_passthrough(state, request, stream),
    };
    if outcome.fault.is_none() && latency_applied.is_some() {
        outcome.fault = Some(format!("latency-{}", kind.as_str()));
    }
    outcome
}

/// Serve small metadata (cache-info / narinfo): buffered, cached, gap-tracked.
/// The cache-info body is passed through verbatim - Priority/WantMassQuery are
/// never rewritten (substituter-ordering scenarios depend on them).
fn serve_metadata(
    state: &Arc<State>,
    request: &Request,
    kind: Kind,
    faults: &FaultConfig,
    stream: &mut TcpStream,
) -> Outcome {
    let disk = match state.cache.resolve(request.path()) {
        Some(disk) => disk,
        None => {
            let _ = http::write_response(stream, 400, "text/plain", b"bad path\n");
            return Outcome::served(400, 0, false);
        }
    };

    let (body, upstream) = if let Some(bytes) = state.cache.read_small(&disk) {
        (bytes, false)
    } else {
        match http::upstream_get(&state.config.upstream, request.path()) {
            Ok(mut resp) if resp.status == 200 => {
                let mut bytes = Vec::new();
                if resp.body.read_to_end(&mut bytes).is_err() {
                    let _ =
                        http::write_response(stream, 502, "text/plain", b"upstream read error\n");
                    return Outcome::served(502, 0, true);
                }
                if let Err(err) = state.cache.store_small(&disk, &bytes) {
                    let _ = http::write_response(stream, 500, "text/plain", b"cache write error\n");
                    eprintln!(
                        "testproxy: cache write failed for {}: {err}",
                        request.path()
                    );
                    return Outcome::served(500, 0, true);
                }
                (bytes, true)
            }
            Ok(resp) => {
                // Forward a non-200 (e.g. a 404 for an absent path) faithfully.
                return forward_status(stream, resp);
            }
            Err(err) => {
                eprintln!(
                    "testproxy: upstream fetch failed for {}: {err}",
                    request.path()
                );
                let _ = http::write_response(stream, 502, "text/plain", b"upstream error\n");
                return Outcome::served(502, 0, true);
            }
        }
    };

    // Gap oracle: remember when this narinfo (which points at a nar) was served.
    if kind == Kind::Narinfo
        && let Some(nar_url) = nar_url_from_narinfo(&body)
    {
        state.gaps.lock().unwrap().insert(nar_url, Instant::now());
    }

    // Mode 6: wrong/stale narinfo (client-facing only; the cache keeps the
    // correct bytes so a later fault-off request still hits a clean entry).
    let (client_body, fault) = if kind == Kind::Narinfo && faults.wrong_narinfo {
        (
            fault::wrong_narinfo(&body),
            Some("wrong-narinfo".to_string()),
        )
    } else {
        (body, None)
    };

    let content_type = content_type_for(kind);
    let bytes_sent = write_body(stream, request, content_type, &client_body);
    let mut outcome = Outcome::served(200, bytes_sent, upstream);
    outcome.fault = fault;
    outcome
}

/// Serve a NAR: streamed, cached on miss, with truncate/corrupt egress faults.
fn serve_nar(
    state: &Arc<State>,
    request: &Request,
    faults: &FaultConfig,
    stream: &mut TcpStream,
) -> Outcome {
    let disk = match state.cache.resolve(request.path()) {
        Some(disk) => disk,
        None => {
            let _ = http::write_response(stream, 400, "text/plain", b"bad path\n");
            return Outcome::served(400, 0, false);
        }
    };

    // Gap oracle: time since the narinfo that referenced this NAR was served.
    let nar_key = request.path().trim_start_matches('/').to_string();
    let gap_ms = state
        .gaps
        .lock()
        .unwrap()
        .get(&nar_key)
        .map(|since| since.elapsed().as_secs_f64() * 1000.0);

    // Establish the byte source: cache hit (file) or upstream miss (stream + a
    // cache writer that captures the correct bytes). Concurrent misses for the
    // same cold path are COALESCED (task-23): the first miss leads the single
    // upstream fetch, and same-path waiters block until it commits, then serve
    // the committed file as a hit - exactly one upstream fetch for N concurrent
    // same-path misses. `lease_guard`, when set, is the leader's single-flight
    // lease; it is dropped only AFTER the commit below so a woken waiter always
    // finds a committed (not half-written) file.
    let mut lease_guard: Option<LeaseGuard> = None;
    let (mut source, total_len, upstream, mut writer): (
        Box<dyn Read + Send>,
        Option<u64>,
        bool,
        Option<crate::cache::CacheWriter>,
    ) = loop {
        // Fast path: a hit needs neither a fetch nor a lease.
        if let Some((file, len)) = state.cache.open(&disk) {
            break (Box::new(file), Some(len), false, None);
        }
        match state.single_flight.lease(&disk) {
            // A previous leader for this path just finished; re-check the cache.
            // A committed leader turns the next iteration into a hit; a leader
            // that failed to commit leaves the path cold, so this request then
            // tries to lead the retry itself (bounded: each request leads at
            // most once, so a persistently-failing upstream costs at most N
            // sequential attempts, never an unbounded storm).
            Lease::Waited => continue,
            Lease::Lead(guard) => {
                // Double-check under leadership: a prior leader may have
                // committed between our miss above and acquiring this lease.
                if let Some((file, len)) = state.cache.open(&disk) {
                    break (Box::new(file), Some(len), false, None);
                }
                match http::upstream_get(&state.config.upstream, request.path()) {
                    Ok(resp) if resp.status == 200 => {
                        let len = resp.content_length();
                        let writer = match state.cache.begin_write() {
                            Ok(writer) => writer,
                            Err(err) => {
                                eprintln!("testproxy: cache writer failed: {err}");
                                let _ = http::write_response(
                                    stream,
                                    500,
                                    "text/plain",
                                    b"cache error\n",
                                );
                                return Outcome::served(500, 0, true);
                            }
                        };
                        // Hold the lease through streaming + commit; waiters wake
                        // only once the guard drops after the commit below.
                        lease_guard = Some(guard);
                        break (resp.body, len, true, Some(writer));
                    }
                    // A non-200 or a fetch error is NOT cached: drop the lease
                    // (waking waiters to retry) and report the failure to this
                    // client. Waiters thus observe the same failure, never a
                    // false success.
                    Ok(resp) => {
                        drop(guard);
                        return forward_status(stream, resp);
                    }
                    Err(err) => {
                        drop(guard);
                        eprintln!(
                            "testproxy: upstream fetch failed for {}: {err}",
                            request.path()
                        );
                        let _ =
                            http::write_response(stream, 502, "text/plain", b"upstream error\n");
                        return Outcome::served(502, 0, true);
                    }
                }
            }
        }
    };

    // Advertise the FULL length even under truncation, so the client detects a
    // short read (that is the point of the truncate fault).
    let mut headers = vec![("Content-Type", content_type_for(Kind::Nar).to_string())];
    if let Some(len) = total_len {
        headers.push(("Content-Length", len.to_string()));
    }
    if http::write_head(stream, 200, &headers).is_err() {
        return Outcome::served(200, 0, upstream); // client vanished before body
    }

    // Truncation point in client bytes; requires a known length.
    let truncate_at = match (faults.truncate_nar_pct, total_len) {
        (Some(pct), Some(len)) => Some(len * u64::from(pct.min(100)) / 100),
        _ => None,
    };

    let mut client_sent: u64 = 0;
    let mut client_open = !request.is_head();
    let mut truncated = false;
    let mut cache_failed = false;
    // Bytes actually received from upstream, and whether the upstream stream
    // ended abnormally (a read error). A premature EOF is detected by comparing
    // `received` to the declared length after the loop (codex re-gate #2b).
    let mut received: u64 = 0;
    let mut source_error = false;
    let mut buf = [0u8; STREAM_BUF];

    loop {
        let n = match source.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(err) => {
                eprintln!("testproxy: source read error for {}: {err}", request.path());
                source_error = true;
                break;
            }
        };
        received += n as u64;
        let chunk = &buf[..n];

        // Cache always gets the full, correct bytes.
        if let Some(writer) = writer.as_mut()
            && let Err(err) = writer.write_all(chunk)
        {
            eprintln!("testproxy: cache write error: {err}");
            // Abandon the entry rather than commit a short one; the tmp file is
            // cleaned when the writer is dropped uncommitted below.
            cache_failed = true;
            break;
        }

        // Client egress, subject to truncate + corrupt.
        if client_open {
            let allow = match truncate_at {
                Some(limit) if client_sent + n as u64 > limit => (limit - client_sent) as usize,
                _ => n,
            };
            let out_slice = &chunk[..allow];
            let out_bytes = if faults.corrupt_nar {
                fault::corrupt_chunk(out_slice)
            } else {
                out_slice.to_vec()
            };
            if stream.write_all(&out_bytes).is_err() {
                client_open = false; // client gone; keep filling the cache
            } else {
                client_sent += allow as u64;
            }
            if allow < n {
                truncated = true;
                client_open = false;
            }
        }

        // Mode 8: bandwidth throttle - pace the stream so a mid-transfer crash
        // (SIGKILL/SIGSTOP at N% of a NAR) has a WIDE, deterministic window to
        // land in. Without it a 110 MiB loopback transfer completes faster than
        // an out-of-process observer can catch it mid-flight. Paced on `n` (the
        // bytes moved this iteration, cache + client) so the tmp file grows at
        // the throttled rate too, which is what the crash harness observes.
        if let Some(bps) = faults.throttle_nar_bps
            && bps > 0
            && n > 0
        {
            std::thread::sleep(std::time::Duration::from_secs_f64(n as f64 / bps as f64));
        }
    }

    // Publish the cache entry only if the WHOLE upstream body was captured
    // cleanly. A premature EOF (fewer bytes than the declared Content-Length), a
    // source read error, or a cache write error must NOT commit - else a short
    // NAR would be cached and served as a self-consistent "complete" 200 on the
    // next hit (codex re-gate #2b). No declared length -> a clean EOF is complete
    // (close-delimited; the Nix client is still the NarHash arbiter).
    let incomplete = total_len.is_some_and(|len| received != len);
    if let Some(writer) = writer.take() {
        if cache_failed || source_error || incomplete {
            if incomplete {
                eprintln!(
                    "testproxy: premature EOF for {} ({received} of {} bytes); not caching",
                    request.path(),
                    total_len.unwrap_or(0)
                );
            }
            drop(writer);
        } else if let Err(err) = writer.commit(&disk) {
            eprintln!(
                "testproxy: cache commit failed for {}: {err}",
                request.path()
            );
        }
    }

    // Release the single-flight lease now the entry is committed (or abandoned),
    // waking same-path waiters onto the finished result. Dropping it here rather
    // than at function exit means waiters do not also wait out this leader's
    // (possibly throttled) egress to its own client.
    drop(lease_guard.take());

    let fault = if truncated {
        // A deliberately short body: close hard so the client sees a truncated
        // transfer rather than a clean end.
        let _ = stream.shutdown(Shutdown::Both);
        Some("truncated-nar".to_string())
    } else {
        let _ = stream.flush();
        if faults.corrupt_nar {
            Some("corrupt-nar".to_string())
        } else {
            None
        }
    };

    Outcome {
        status: 200,
        bytes_sent: client_sent,
        upstream,
        fault,
        gap_ms,
    }
}

/// Pass an unrecognised path straight through, uncached.
fn serve_passthrough(state: &Arc<State>, request: &Request, stream: &mut TcpStream) -> Outcome {
    match http::upstream_get(&state.config.upstream, request.path()) {
        Ok(mut resp) => {
            let mut body = Vec::new();
            let _ = resp.body.read_to_end(&mut body);
            let bytes = write_body(stream, request, "application/octet-stream", &body);
            Outcome::served(resp.status, bytes, true)
        }
        Err(_) => {
            let _ = http::write_response(stream, 502, "text/plain", b"upstream error\n");
            Outcome::served(502, 0, true)
        }
    }
}

/// Forward a non-200 upstream response (status + small body) faithfully.
fn forward_status(stream: &mut TcpStream, mut resp: http::UpstreamResponse) -> Outcome {
    let mut body = Vec::new();
    let _ = resp.body.read_to_end(&mut body);
    let _ = http::write_response(stream, resp.status, "application/octet-stream", &body);
    Outcome::served(resp.status, body.len() as u64, true)
}

/// Write a small body, honouring HEAD (headers only). Returns bytes sent.
fn write_body(stream: &mut TcpStream, request: &Request, content_type: &str, body: &[u8]) -> u64 {
    if request.is_head() {
        let headers = [
            ("Content-Type", content_type.to_string()),
            ("Content-Length", body.len().to_string()),
        ];
        let _ = http::write_head(stream, 200, &headers);
        0
    } else if http::write_response(stream, 200, content_type, body).is_ok() {
        body.len() as u64
    } else {
        0
    }
}

fn content_type_for(kind: Kind) -> &'static str {
    match kind {
        Kind::CacheInfo => "text/x-nix-cache-info",
        Kind::Narinfo => "text/x-nix-narinfo",
        Kind::Nar => "application/x-nix-nar",
        Kind::Other => "application/octet-stream",
    }
}

/// Extract the `URL:` (nar path) from a narinfo body, for gap tracking.
fn nar_url_from_narinfo(body: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(body);
    for line in text.lines() {
        if let Some(url) = line.strip_prefix("URL:") {
            return Some(url.trim().to_string());
        }
    }
    None
}

fn now_unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

// ---- admin surface (control + observability for the e2e harness, task-5) ----

fn admin(state: &Arc<State>, request: &Request, stream: &mut TcpStream) {
    let path = request.path();
    match (request.method.as_str(), path) {
        ("GET", "/__testproxy/stats") => {
            let json = state.log.lock().unwrap().stats().to_json();
            let _ = http::write_response(stream, 200, "application/json", json.as_bytes());
        }
        ("GET", "/__testproxy/log") => {
            let json = state.log.lock().unwrap().to_json();
            let _ = http::write_response(stream, 200, "application/json", json.as_bytes());
        }
        ("GET", "/__testproxy/in-flight") => {
            let json = format!("{{\"in_flight\":{}}}", state.in_flight());
            let _ = http::write_response(stream, 200, "application/json", json.as_bytes());
        }
        ("POST", "/__testproxy/reset") => {
            state.log.lock().unwrap().clear();
            state.gaps.lock().unwrap().clear();
            let _ = http::write_response(stream, 200, "application/json", b"{\"ok\":true}");
        }
        ("POST", "/__testproxy/faults/clear") => {
            *state.faults.lock().unwrap() = FaultConfig::default();
            let _ = http::write_response(stream, 200, "application/json", b"{\"ok\":true}");
        }
        ("POST", "/__testproxy/faults") => match parse_faults(request.query().unwrap_or("")) {
            Ok(faults) => {
                *state.faults.lock().unwrap() = faults;
                let _ = http::write_response(stream, 200, "application/json", b"{\"ok\":true}");
            }
            Err(msg) => {
                let body = format!("{{\"ok\":false,\"error\":{}}}", crate::json::quote(&msg));
                let _ = http::write_response(stream, 400, "application/json", body.as_bytes());
            }
        },
        _ => {
            let _ = http::write_response(stream, 404, "text/plain", b"unknown admin endpoint\n");
        }
    }
}

/// Parse the fault admin query string into a [`FaultConfig`]. Unknown keys fail
/// fast so a typo in a scenario is a visible 400, not a silently-ignored fault.
fn parse_faults(query: &str) -> Result<FaultConfig, String> {
    let mut faults = FaultConfig::default();
    let mut http_error_code: Option<u16> = None;
    let mut http_error_kind: Option<Kind> = None;
    let mut reset_scope: Option<Scope> = None;

    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        match key {
            "latency_cache_info_ms" => insert_latency(&mut faults, Kind::CacheInfo, value)?,
            "latency_narinfo_ms" => insert_latency(&mut faults, Kind::Narinfo, value)?,
            "latency_nar_ms" => insert_latency(&mut faults, Kind::Nar, value)?,
            "http_error" => {
                http_error_code = Some(
                    value
                        .parse()
                        .map_err(|_| format!("bad http_error {value:?}"))?,
                )
            }
            "http_error_kind" => {
                http_error_kind =
                    Some(Kind::parse(value).ok_or_else(|| format!("bad kind {value:?}"))?)
            }
            "connection_reset" => {
                reset_scope = Some(if value == "all" || value.is_empty() {
                    Scope::All
                } else {
                    Scope::Only(Kind::parse(value).ok_or_else(|| format!("bad kind {value:?}"))?)
                })
            }
            "truncate_pct" => {
                faults.truncate_nar_pct = Some(
                    value
                        .parse()
                        .map_err(|_| format!("bad truncate_pct {value:?}"))?,
                )
            }
            "throttle_nar_bps" => {
                faults.throttle_nar_bps = Some(
                    value
                        .parse()
                        .map_err(|_| format!("bad throttle_nar_bps {value:?}"))?,
                )
            }
            "corrupt_nar" => faults.corrupt_nar = truthy(value),
            "wrong_narinfo" => faults.wrong_narinfo = truthy(value),
            "unreachable" => faults.unreachable = truthy(value),
            other => return Err(format!("unknown fault param {other:?}")),
        }
    }

    if let Some(code) = http_error_code {
        let scope = http_error_kind.map(Scope::Only).unwrap_or(Scope::All);
        faults.http_error = Some((scope, code));
    }
    faults.connection_reset = reset_scope;
    Ok(faults)
}

fn insert_latency(faults: &mut FaultConfig, kind: Kind, value: &str) -> Result<(), String> {
    let ms: u64 = value
        .parse()
        .map_err(|_| format!("bad latency {value:?}"))?;
    faults
        .latency
        .insert(kind, std::time::Duration::from_millis(ms));
    Ok(())
}

fn truthy(value: &str) -> bool {
    matches!(value, "1" | "true" | "yes" | "")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_nar_url() {
        let narinfo = b"StorePath: /nix/store/x\nURL: nar/abc.nar\nNarHash: sha256:0\n";
        assert_eq!(
            nar_url_from_narinfo(narinfo),
            Some("nar/abc.nar".to_string())
        );
    }

    #[test]
    fn parse_faults_roundtrips_and_rejects_unknown() {
        let faults = parse_faults(
            "latency_nar_ms=50&http_error=503&http_error_kind=narinfo&truncate_pct=25",
        )
        .unwrap();
        assert_eq!(
            faults.latency_for(Kind::Nar),
            Some(std::time::Duration::from_millis(50))
        );
        assert_eq!(faults.http_error_for(Kind::Narinfo), Some(503));
        assert_eq!(faults.http_error_for(Kind::Nar), None);
        assert_eq!(faults.truncate_nar_pct, Some(25));
        assert!(parse_faults("bogus=1").is_err());
    }

    #[test]
    fn parse_faults_reads_throttle_and_rejects_garbage() {
        let faults = parse_faults("throttle_nar_bps=8388608").unwrap();
        assert_eq!(faults.throttle_nar_bps, Some(8 * 1024 * 1024));
        assert!(parse_faults("throttle_nar_bps=notanumber").is_err());
    }
}
