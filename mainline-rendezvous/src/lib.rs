//! nix-p2p Mainline (BitTorrent DHT) peer-address RENDEZVOUS — TASK-258 SPIKE.
//!
//! The idea (from the task): use the BitTorrent Mainline DHT as a RENDEZVOUS layer
//! to FIND other nix-p2p NODES, then run our own `/nix-p2p/<scope>/kad` among them.
//! Every node announces under ONE well-known infohash meaning "I speak nix-p2p";
//! `get_peers` on that infohash returns member ADDRESSES which feed the existing
//! libp2p bootstrap/dial path. Content routing stays entirely on our own kad — this
//! module NEVER answers "who holds hash X?" (that would violate the kad-exclusive
//! content-discovery invariant; see `scripts/check-discovery-no-shortcut.py`).
//!
//! SPIKE STATUS: this is a prototype backing a DECISION, not a shipped default. The
//! central deliverables are (a) the structural NAT/circuit finding and (b) the
//! measured node-membership enumeration cost — see the crate tests and the report.
//!
//! # The BEP5 reachability finding (AC#13), stated where the code lives
//! `announce_peer(info_hash, port)` records ONLY the SOURCE IP of the announce UDP
//! packet plus the given port. `get_peers` returns `Vec<SocketAddrV4>` — bare IP:port,
//! **no PeerId, no arbitrary payload, no `/p2p-circuit` multiaddr**. So for a NAT'd
//! announcer whose only reachable libp2p address is a relayed `/p2p-circuit`, BEP5 can
//! carry neither the circuit address nor the PeerId needed to build one. BEP5 therefore
//! lets a peer DISCOVER another's membership/existence, but does NOT by itself let it
//! REACH a NAT'd peer. See `rendezvous_infohash` / `discover` and the report.

use std::collections::BTreeSet;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::{Duration, Instant};

use futures_lite::StreamExt;
use mainline::async_dht::AsyncDht;
use mainline::{Dht, Id};

// Re-export the async node handle so a SHIPPED caller (TASK-284: `daemon-libp2p`) can name the
// type this crate's `build_node` returns without taking its own direct `mainline` dependency —
// keeping the `mainline` supply-chain edge behind this one wrapping crate.
pub use mainline::async_dht::AsyncDht as RendezvousNode;

/// The fixed domain string the ONE well-known rendezvous infohash is derived from.
/// A node announcing under this infohash asserts only "I speak nix-p2p" — it is a
/// MEMBERSHIP key over NODES, never a CONTENT key over HOLDINGS. (The frozen
/// no-enumeration invariant is about content HOLDINGS; this key does not touch it.)
pub const RENDEZVOUS_DOMAIN: &str = "nix-p2p:mainline-rendezvous:v1";

/// Derive the well-known 20-byte infohash deterministically: the first 20 bytes of
/// `BLAKE3(RENDEZVOUS_DOMAIN)`. Documented derivation, not a magic constant, and it
/// reuses the first-party BLAKE3 already in the tree.
pub fn rendezvous_infohash() -> Id {
    let digest = blake3::hash(RENDEZVOUS_DOMAIN.as_bytes());
    let mut twenty = [0u8; 20];
    twenty.copy_from_slice(&digest.as_bytes()[..20]);
    Id::from_bytes(twenty).expect("BLAKE3 digest yields at least 20 bytes")
}

/// How a rendezvous node participates in the Mainline DHT. The spike holds nodes
/// strictly `Client`; `Server` exists ONLY so the hermetic e2e can stand up an
/// in-topology Mainline entry point instead of contacting the real public swarm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DhtRole {
    /// No `server_mode()` AND `no_adaptive()`: stores/queries but NEVER answers inbound
    /// DHT requests and is never promoted to a serving node (AC#1/#5 client-only). The
    /// `no_adaptive()` half is load-bearing — stock mainline v8 would otherwise
    /// ADAPTIVELY promote a non-firewalled node to serving; the vendored patch disables
    /// that (see `build_node` and vendor/mainline/README.md). This is what a real
    /// nix-p2p node would run.
    Client,
    /// `server_mode()`: a full serving DHT node. Used ONLY for the hermetic local
    /// bootstrap node in the e2e topology — never on a shipped nix-p2p node.
    Server,
}

/// Build a Mainline node in `role`, pointed EXCLUSIVELY at `bootstrap` (a LOCAL
/// Mainline node list). There is deliberately NO default bootstrap here, so this
/// never contacts `router.bittorrent.com` / `dht.transmissionbt.com`; a caller that
/// wants the real public swarm must pass those addresses explicitly. `bind`/`port`
/// pin the UDP socket so a packet capture can be scoped to exactly this node.
///
/// `bootstrap` empty + `Server` => a root bootstrap node (`no_bootstrap()`), the
/// hermetic entry point every other node points at.
pub fn build_node(
    role: DhtRole,
    bootstrap: &[SocketAddrV4],
    bind: Ipv4Addr,
    port: u16,
) -> Result<AsyncDht, String> {
    let boot: Vec<String> = bootstrap.iter().map(|a| a.to_string()).collect();
    let mut builder = Dht::builder();
    builder.bind_address(bind);
    if port != 0 {
        builder.port(port);
    }
    if boot.is_empty() {
        builder.no_bootstrap();
    } else {
        builder.bootstrap(&boot);
    }
    match role {
        DhtRole::Server => {
            builder.server_mode();
        }
        DhtRole::Client => {
            // The client-only guarantee has TWO parts, and NOT calling server_mode()
            // is only the first. Stock mainline v8 has no client-only mode: `build()`
            // runs an ADAPTIVE policy that PROMOTES a non-server, non-firewalled node
            // to a SERVING public-DHT node (`Rpc::try_switching_to_server_mode`) once it
            // proves publicly reachable. So merely omitting server_mode() does NOT keep a
            // real (routable) node a client. `no_adaptive()` — added by the vendored
            // `mainline` patch (see vendor/mainline/README.md) — disables that adaptive
            // promotion, so a Client stays strictly client-only forever (AC#5, TASK-258
            // "no adaptive promotion"). The vendored crate's own co-located oracle
            // (`no_adaptive_client_never_promotes_when_not_firewalled`) pins this and is
            // mutation-provable (revert the guard -> RED).
            builder.no_adaptive();
        }
    }
    // A client answers no inbound query (no server_mode) AND is never adaptively promoted
    // (no_adaptive, above). The v8 SYNC surface is deprecated, so we hand back the `AsyncDht`.
    builder
        .build()
        .map(Dht::as_async)
        .map_err(|e| format!("mainline build failed: {e}"))
}

/// The bound applied to one `get_peers` rendezvous lookup. This bounds an
/// eventually-consistent DHT lookup (legitimate) — it does NOT hide a race: an empty
/// result WITHIN the bound is a real negative (the no-injection bite in the tests
/// relies on that). COLD-CACHE-ONLY for the spike: there is no persisted peer cache
/// (AC#9/#10/#11 deferred), so a lookup always actually hits the DHT.
#[derive(Debug, Clone, Copy)]
pub struct LookupBound {
    /// Wall-clock deadline for the whole lookup.
    pub deadline: Duration,
    /// Stop after this many DISTINCT addresses (a work bound on a popular infohash).
    pub max_addrs: usize,
}

impl Default for LookupBound {
    fn default() -> Self {
        Self {
            deadline: Duration::from_secs(10),
            max_addrs: 512,
        }
    }
}

/// Result of one rendezvous lookup: the distinct member addresses recovered and how
/// long it took. `addrs` is exactly what BEP5 yields — bare `SocketAddrV4`, NO
/// PeerId — which is the whole of the AC#13 reachability finding: the caller has an
/// IP:port to DIAL, and nothing with which to build a `/p2p-circuit/p2p/<PeerId>`.
#[derive(Debug, Clone)]
pub struct Discovery {
    pub addrs: Vec<SocketAddrV4>,
    pub elapsed: Duration,
}

/// Announce our own membership: publish `libp2p_port` under the rendezvous infohash.
/// BEP5 records (source-IP-of-this-packet, libp2p_port). Returns the wall time of the
/// announce put-query. NOTE the structural gap this cannot close: on a NAT'd node the
/// source IP is the public NAT IP and `libp2p_port` has no NAT mapping for the libp2p
/// transport socket (the DHT runs on a DIFFERENT UDP socket), so the announced address
/// is undialable from outside — see the module docs and the report.
pub async fn announce(dht: &AsyncDht, libp2p_port: u16) -> Result<Duration, String> {
    let started = Instant::now();
    dht.announce_peer(rendezvous_infohash(), Some(libp2p_port))
        .await
        .map_err(|e| format!("announce_peer failed: {e}"))?;
    Ok(started.elapsed())
}

/// Discover member addresses via ONE bounded `get_peers` on the rendezvous infohash.
/// This is the DISCOVERY half: it recovers who has announced. Whether the recovered
/// addresses are REACHABLE is a separate question the caller (a libp2p dial) answers,
/// and the AC#13 finding is that for NAT'd members they are not.
pub async fn discover(dht: &AsyncDht, bound: LookupBound) -> Discovery {
    let started = Instant::now();
    let mut seen: BTreeSet<SocketAddrV4> = BTreeSet::new();
    let mut stream = dht.get_peers(rendezvous_infohash());
    // The bound is the deadline OR max_addrs, whichever first. A stream END (query complete)
    // within the deadline is a REAL negative — that is what the no-injection bite (AC#4) relies
    // on: no rendezvous => empty within the bound. `Ok(None)` (stream ended) and `Err(_)`
    // (deadline) both stop the lookup.
    while let Some(remaining) = bound.deadline.checked_sub(started.elapsed()) {
        match tokio::time::timeout(remaining, stream.next()).await {
            Ok(Some(batch)) => {
                for addr in batch {
                    seen.insert(addr);
                }
                if seen.len() >= bound.max_addrs {
                    break;
                }
            }
            Ok(None) | Err(_) => break,
        }
    }
    let mut addrs: Vec<SocketAddrV4> = seen.into_iter().collect();
    addrs.truncate(bound.max_addrs);
    Discovery {
        addrs,
        elapsed: started.elapsed(),
    }
}

/// Convenience for the enumeration measurement (AC#7): a THIRD-party observer runs the
/// SAME `get_peers` and recovers the announced membership. This is deliberately the
/// identical primitive `discover` uses — the point of AC#7 is that ANY stranger who
/// knows the (public) infohash enumerates the node population; there is no privileged
/// input. (The authoritative measurement parses the observer's RAW packet capture; see
/// `scripts/mainline_enumeration.py`. This helper is the API-level cross-check.)
pub async fn enumerate_membership(observer: &AsyncDht, bound: LookupBound) -> Discovery {
    discover(observer, bound).await
}
