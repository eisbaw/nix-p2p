//! nix-p2p product daemon - binary entrypoint.
//!
//! A thin wrapper over the `daemon` library: parse flags, wire the single
//! `UpstreamHttp` behind all three upstream traits, and serve. All behaviour
//! lives in the library so the integration tests drive the exact same stack.
//!
//! The near-identical `banner()` in `testproxy` is deliberate duplication, not
//! an oversight (task-1 note): factoring it into a shared crate is exactly the
//! coupling the PRD forbids until a second consumer genuinely earns it.

use std::net::{Ipv4Addr, SocketAddr};
use std::process::ExitCode;
use std::sync::Arc;

use daemon::cacheinfo::DEFAULT_PRIORITY;
use daemon::{
    App, CacheInfo, CorrelationStore, NarCatalog, NarinfoDiskCache, NarinfoSource, NoRawServe,
    NullCorrelation, SystemClock, UpstreamHttp, serve,
};
use tokio::net::TcpListener;

/// Human- and machine-readable identity of this build.
fn banner() -> String {
    format!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"))
}

/// Startup configuration. Hand-rolled flag parsing, like the fixture - a CLI
/// crate is a dependency a five-flag binary does not need.
#[derive(Debug, Clone)]
struct Config {
    listen: SocketAddr,
    upstream: String,
    store_dir: String,
    priority: u32,
    want_mass_query: bool,
    /// Directory for the persistent narinfo disk cache (task-8). When unset the
    /// daemon runs pure-upstream (pre-task-8 behaviour); when set it layers
    /// disk-cache-over-upstream and persists the NAR correlation across restarts.
    /// Opt-in in wave 1 so enabling it in the container/NixOS paths is a separate,
    /// reviewable change (filed: wire a default cache dir into the module + e2e).
    narinfo_cache_dir: Option<String>,
    /// Per-hop upstream header timeout in milliseconds (default 1000). Exposed so
    /// the fault x depth matrix (task-13) can move the 200->502 latency ceiling
    /// deliberately and so an operator fronting a slow upstream can widen it. It
    /// is a FIXED per-hop deadline that does NOT compose across a daemon chain
    /// (task-33); see `UpstreamHttp::with_header_timeout`.
    header_timeout_ms: u64,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            // 8082: clear of the fixture upstream (8080) and the testproxy (8081).
            listen: SocketAddr::from((Ipv4Addr::LOCALHOST, 8082)),
            upstream: "http://127.0.0.1:8081".to_string(),
            store_dir: "/nix/store".to_string(),
            priority: DEFAULT_PRIORITY,
            want_mass_query: true,
            narinfo_cache_dir: None,
            header_timeout_ms: 1000,
        }
    }
}

impl Config {
    fn from_args<I: IntoIterator<Item = String>>(args: I) -> Result<Config, String> {
        let mut config = Config::default();
        let mut args = args.into_iter();
        while let Some(flag) = args.next() {
            let mut value = || {
                args.next()
                    .ok_or_else(|| format!("flag {flag} needs a value"))
            };
            match flag.as_str() {
                "--listen" => {
                    let raw = value()?;
                    config.listen = raw
                        .parse()
                        .map_err(|e| format!("bad --listen {raw:?}: {e}"))?;
                }
                "--upstream" => config.upstream = value()?,
                "--narinfo-cache-dir" => config.narinfo_cache_dir = Some(value()?),
                "--header-timeout-ms" => {
                    let raw = value()?;
                    let ms: u64 = raw
                        .parse()
                        .map_err(|e| format!("bad --header-timeout-ms {raw:?}: {e}"))?;
                    // Reject 0 (codex, task-13): a 0 ms header timeout fires before
                    // any upstream can answer, so EVERY request 502s - a bricked-
                    // but-superficially-healthy daemon. Require a positive, sane
                    // value; the upper bound catches a units typo (e.g. seconds).
                    if !(1..=600_000).contains(&ms) {
                        return Err(format!(
                            "bad --header-timeout-ms {ms}: must be 1..=600000 (0 bricks the daemon)"
                        ));
                    }
                    config.header_timeout_ms = ms;
                }
                "--store-dir" => config.store_dir = value()?,
                "--priority" => {
                    let raw = value()?;
                    config.priority = raw
                        .parse()
                        .map_err(|e| format!("bad --priority {raw:?}: {e}"))?;
                }
                "--want-mass-query" => {
                    let raw = value()?;
                    config.want_mass_query = match raw.as_str() {
                        "1" | "true" | "yes" => true,
                        "0" | "false" | "no" => false,
                        other => return Err(format!("bad --want-mass-query {other:?}")),
                    };
                }
                other => return Err(format!("unknown flag {other:?}")),
            }
        }
        Ok(config)
    }

    fn cache_info(&self) -> CacheInfo {
        CacheInfo {
            store_dir: self.store_dir.clone(),
            priority: self.priority,
            want_mass_query: self.want_mass_query,
        }
    }
}

/// The `rewrite-narinfo` filter subcommand: read a narinfo on stdin, apply the
/// task-49 transport rewrite (`to_raw`), write the rewritten narinfo on stdout.
/// Exits 0 on success, 3 on a `RewriteError` (an un-rewritable narinfo), 1 on an
/// I/O error. It is the exact serving-layer rewrite as a pure filter, so an
/// operator (and the real-nix e2e in scripts/) can see and verify precisely what
/// the daemon would hand a client for a peer-served path.
fn run_rewrite_narinfo_filter() -> ExitCode {
    use std::io::{Read, Write};
    let mut input = Vec::new();
    if let Err(err) = std::io::stdin().read_to_end(&mut input) {
        eprintln!("daemon rewrite-narinfo: reading stdin: {err}");
        return ExitCode::FAILURE;
    }
    match daemon::to_raw(&input) {
        Ok(rewrite) => {
            if let Err(err) = std::io::stdout().write_all(&rewrite.body) {
                eprintln!("daemon rewrite-narinfo: writing stdout: {err}");
                return ExitCode::FAILURE;
            }
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("daemon rewrite-narinfo: {err}");
            ExitCode::from(3)
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    // A tiny subcommand surface: `rewrite-narinfo` is a synchronous stdin->stdout
    // filter, handled before any flag parsing or the async serve loop.
    let mut raw_args = std::env::args().skip(1).peekable();
    if raw_args.peek().map(String::as_str) == Some("rewrite-narinfo") {
        return run_rewrite_narinfo_filter();
    }

    let config = match Config::from_args(std::env::args().skip(1)) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("daemon: {err}");
            return ExitCode::from(2);
        }
    };

    println!("{}", banner());

    // The correlation catalog lives in the server only: it populates it as
    // narinfos pass through and reads it at NAR-request time. UpstreamHttp needs
    // no catalog - the request carries the exact URL token to fetch.
    let catalog = Arc::new(NarCatalog::new());
    let upstream = match UpstreamHttp::new(&config.upstream) {
        Ok(upstream) => Arc::new(
            upstream
                .with_header_timeout(std::time::Duration::from_millis(config.header_timeout_ms)),
        ),
        Err(err) => {
            eprintln!("daemon: bad --upstream: {err}");
            return ExitCode::from(2);
        }
    };

    // Layer the persistent narinfo cache over the upstream when a cache dir is
    // configured (task-8). The SAME instance is the narinfo source AND the
    // persistent correlation store, so a warm-on-disk daemon dispatches the
    // signed NarHash even after an in-memory-cold restart.
    let (narinfo, correlation): (Arc<dyn NarinfoSource>, Arc<dyn CorrelationStore>) = match &config
        .narinfo_cache_dir
    {
        Some(dir) => match NarinfoDiskCache::new(dir, upstream.clone(), Arc::new(SystemClock)) {
            Ok(cache) => {
                let cache = Arc::new(cache);
                println!("daemon: narinfo disk cache at {dir}");
                (cache.clone(), cache)
            }
            Err(err) => {
                eprintln!("daemon: cannot open narinfo cache dir {dir:?}: {err}");
                return ExitCode::FAILURE;
            }
        },
        None => (upstream.clone(), Arc::new(NullCorrelation)),
    };

    let app = Arc::new(App {
        narinfo,
        nar: upstream.clone(),
        passthrough: upstream.clone(),
        cache_info: config.cache_info(),
        catalog,
        upstream_label: config.upstream.clone(),
        correlation,
        // Wave-1 binary never serves raw itself, so every narinfo is relayed
        // verbatim and the client fetches the compressed upstream nar (S2). task-41
        // wires an availability-backed RawServeDecision alongside a raw NAR source.
        raw_serve: Arc::new(NoRawServe),
    });

    let listener = match TcpListener::bind(config.listen).await {
        Ok(listener) => listener,
        Err(err) => {
            eprintln!("daemon: cannot bind {}: {err}", config.listen);
            return ExitCode::FAILURE;
        }
    };
    let local = listener
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| config.listen.to_string());
    println!(
        "daemon: listening on {local} -> upstream {}",
        config.upstream
    );

    if let Err(err) = serve(listener, app).await {
        eprintln!("daemon: serve error: {err}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn banner_names_this_crate_and_a_version() {
        let text = banner();
        assert!(
            text.starts_with("daemon "),
            "banner must lead with the crate name, got {text:?}"
        );
        let version = text.strip_prefix("daemon ").expect("prefix checked above");
        assert!(
            version.split('.').count() >= 3,
            "expected a semver-ish version, got {version:?}"
        );
    }

    #[test]
    fn parses_all_flags() {
        let config = Config::from_args(
            [
                "--listen",
                "127.0.0.1:9000",
                "--upstream",
                "http://example:80",
                "--store-dir",
                "/nix/store",
                "--priority",
                "25",
                "--want-mass-query",
                "0",
                "--header-timeout-ms",
                "250",
            ]
            .map(String::from),
        )
        .unwrap();
        assert_eq!(config.listen.port(), 9000);
        assert_eq!(config.upstream, "http://example:80");
        assert_eq!(config.priority, 25);
        assert!(!config.want_mass_query);
        assert_eq!(config.header_timeout_ms, 250);
    }

    #[test]
    fn unknown_flag_fails_fast() {
        assert!(Config::from_args(["--nope".to_string()]).is_err());
        assert!(Config::from_args(["--listen".to_string()]).is_err());
        assert!(Config::from_args(["--priority".to_string(), "abc".to_string()]).is_err());
    }

    #[test]
    fn header_timeout_zero_is_rejected() {
        // 0 ms bricks the daemon (every request 502s before any upstream answer);
        // reject at parse rather than start a bricked-but-healthy-looking daemon.
        assert!(
            Config::from_args(["--header-timeout-ms".to_string(), "0".to_string()]).is_err(),
            "0 must be rejected"
        );
        // Absurd (units typo) is rejected too; a sane value is accepted.
        assert!(
            Config::from_args(["--header-timeout-ms".to_string(), "9999999".to_string()]).is_err()
        );
        assert_eq!(
            Config::from_args(["--header-timeout-ms".to_string(), "500".to_string()])
                .unwrap()
                .header_timeout_ms,
            500
        );
    }

    #[test]
    fn default_config_advertises_a_preferred_priority() {
        assert!(Config::default().priority < 40);
    }
}
