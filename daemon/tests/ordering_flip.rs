//! AC#5: the daemon is orderable ahead of a direct cache, proven by a
//! request-count flip using BOTH levers - the daemon's advertised
//! `nix-cache-info` Priority AND the client-side `?priority=N` URL override.
//!
//! No real `nix` here: this models Nix's DOCUMENTED substituter ordering (lower
//! effective priority wins; the `?priority=` URL override beats the advertised
//! value - bmcgee.ie "TIL: how to optimise substitutions in Nix"). The model
//! reads the advertised priority from the daemon's REAL `nix-cache-info`, so the
//! daemon's actual output is under test; real-`nix` ordering is task-5's job.
//!
//! Topology makes the counts unambiguous: the client chooses between the daemon
//! (fronting upstream B) and a direct cache (upstream A). Whichever it picks
//! receives the narinfo request - via the daemon to B, or straight to A - so
//! `B.narinfo == 1, A.narinfo == 0` means "daemon preferred" and the reverse
//! means "direct preferred".

mod common;

use std::net::SocketAddr;

use common::{DaemonHandle, MockResponse, MockUpstream, get, spawn_daemon_with};
use daemon::CacheInfo;

const ROUTE: &str = "/route123.narinfo";
const DIRECT_PRIORITY: u32 = 40;

/// Read a substituter's advertised `Priority` from its `nix-cache-info`.
async fn advertised_priority(addr: SocketAddr) -> u32 {
    let resp = get(addr, "/nix-cache-info").await;
    resp.body_string()
        .lines()
        .find_map(|line| line.strip_prefix("Priority: ").and_then(|v| v.parse().ok()))
        .expect("nix-cache-info advertises a Priority")
}

/// Nix's rule: pick the substituter with the lowest effective priority, where a
/// `?priority=` URL override replaces the advertised value. First wins on a tie.
async fn choose(subs: &[(&'static str, SocketAddr, Option<u32>)]) -> &'static str {
    let mut best: Option<(&'static str, u32)> = None;
    for (name, addr, override_prio) in subs {
        let effective = match override_prio {
            Some(p) => *p,
            None => advertised_priority(*addr).await,
        };
        if best.is_none_or(|(_, b)| effective < b) {
            best = Some((name, effective));
        }
    }
    best.expect("at least one substituter").0
}

struct Scenario {
    direct: MockUpstream,
    behind: MockUpstream,
    daemon: SocketAddr,
    _handle: DaemonHandle,
}

impl Scenario {
    /// Direct cache A (advertises `Priority: 40`) and a daemon (advertising
    /// `daemon_priority`) fronting upstream B. Both caches serve the narinfo.
    async fn build(daemon_priority: u32) -> Scenario {
        let direct = MockUpstream::start(|_m, path| match path {
            "/nix-cache-info" => MockResponse::ok(
                "text/x-nix-cache-info",
                format!("StoreDir: /nix/store\nWantMassQuery: 1\nPriority: {DIRECT_PRIORITY}\n"),
            ),
            p if p.ends_with(".narinfo") => {
                MockResponse::ok("text/x-nix-narinfo", b"StorePath: /nix/store/x\n".to_vec())
            }
            _ => MockResponse::status(404),
        });
        let behind = MockUpstream::start(|_m, path| {
            if path.ends_with(".narinfo") {
                MockResponse::ok("text/x-nix-narinfo", b"StorePath: /nix/store/x\n".to_vec())
            } else {
                MockResponse::status(404)
            }
        });
        let cache_info = CacheInfo {
            priority: daemon_priority,
            ..CacheInfo::default()
        };
        let (daemon, _handle) = spawn_daemon_with(&behind.base_url(), cache_info).await;
        Scenario {
            direct,
            behind,
            daemon,
            _handle,
        }
    }

    /// Run the client model with an optional `?priority=` override on the daemon,
    /// then send the narinfo request to whichever substituter it chose.
    async fn route(&self, daemon_override: Option<u32>) -> &'static str {
        let subs = [
            ("daemon", self.daemon, daemon_override),
            ("direct", self.direct.addr, None),
        ];
        let chosen = choose(&subs).await;
        let target = if chosen == "daemon" {
            self.daemon
        } else {
            self.direct.addr
        };
        assert_eq!(get(target, ROUTE).await.status, Some(200));
        chosen
    }
}

#[tokio::test]
async fn ordering_flips_on_advertised_priority() {
    // Daemon advertises 30 (< 40): the client prefers the daemon, so the narinfo
    // reaches upstream B (via the daemon) and the direct cache A sees none.
    let s = Scenario::build(30).await;
    assert_eq!(s.route(None).await, "daemon");
    assert_eq!(
        s.behind.count_narinfo(),
        1,
        "daemon forwarded the narinfo to B"
    );
    assert_eq!(
        s.direct.count_narinfo(),
        0,
        "direct cache A was not queried"
    );

    // Daemon advertises 50 (> 40): the flip. Now the client prefers the direct
    // cache A, and B (behind the daemon) sees none.
    let s = Scenario::build(50).await;
    assert_eq!(s.route(None).await, "direct");
    assert_eq!(
        s.direct.count_narinfo(),
        1,
        "direct cache A served the narinfo"
    );
    assert_eq!(s.behind.count_narinfo(), 0, "daemon was not preferred");
}

#[tokio::test]
async fn ordering_flips_on_url_priority_override() {
    // The daemon still advertises 30, but the client-side ?priority= override is
    // the second, independent lever (bmcgee TIL). Override 90 (> 40) demotes the
    // daemon below the direct cache regardless of what it advertises.
    let s = Scenario::build(30).await;
    // The override is independent of - and coexists with - the daemon's real
    // advertised value: prove the daemon genuinely still advertises 30, so the
    // flip below is the override winning over it, not a changed advertisement.
    assert_eq!(
        advertised_priority(s.daemon).await,
        30,
        "the daemon still advertises 30; the override is the lever under test"
    );
    assert_eq!(s.route(Some(90)).await, "direct");
    assert_eq!(s.direct.count_narinfo(), 1);
    assert_eq!(s.behind.count_narinfo(), 0);

    // Override 10 (< 40) promotes the daemon - the override wins over both the
    // advertised 30 and the direct 40.
    let s = Scenario::build(30).await;
    assert_eq!(s.route(Some(10)).await, "daemon");
    assert_eq!(s.behind.count_narinfo(), 1);
    assert_eq!(s.direct.count_narinfo(), 0);
}
