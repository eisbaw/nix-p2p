//! TASK-284: the Mainline (BEP5) DHT wired as an OPT-IN PUBLIC peer-address RENDEZVOUS bootstrap.
//!
//! This is the missing INTERNET zero-config entry point. mDNS (TASK-257) bootstraps a node into
//! the LAN pool; at HEAD the kad DHT cannot self-bootstrap across the internet and there are no
//! default nodes, so a node outside a single LAN has no way in. Mainline-as-RENDEZVOUS is the one
//! bootstrap that needs no infrastructure we own or fund: every nix-p2p node announces its
//! MEMBERSHIP under ONE hardcoded well-known infohash and `get_peers`-es that same infohash to
//! learn member ADDRESSES, which it hands to the libp2p DIAL path so kad can converge with NO
//! configured `--libp2p-bootstrap`.
//!
//! CONTENT DISCOVERY STAYS KAD-EXCLUSIVE (AC#2). This module learns only peer ADDRESSES and feeds
//! them to `SwarmHandle::dial` (address bootstrap); it NEVER answers "who holds hash X?" and
//! derives NO infohash from any Nix content hash — the one infohash is a fixed domain constant
//! (`mainline_rendezvous::rendezvous_infohash`). `scripts/check-discovery-no-shortcut.py`
//! (`scan_rendezvous_wiring`) enforces this STRUCTURALLY: every `*rendezvous*`/`*mainline*`-named
//! function body here is scanned and BITES if it reaches `find_providers`/`get_providers`.
//!
//! STRICTLY CLIENT (AC#1/#5). The Mainline node is built with [`DhtRole::Client`], which sets BOTH
//! `!server_mode()` (answers no inbound BEP5 query) AND `no_adaptive()` (never adaptively promoted).
//! The second half is load-bearing and NOT free from omitting server_mode: stock mainline v8 has no
//! client-only mode and would ADAPTIVELY promote a non-firewalled node to a SERVING public-DHT node
//! (`Rpc::try_switching_to_server_mode`). nix-p2p vendors `mainline` with a `no_adaptive` flag that
//! disables that promotion (see vendor/mainline/README.md), which `build_node` sets for a Client, so
//! a real routable node stays strictly client-only. Client-only is observable from a third-party
//! capture as ZERO OUTBOUND RESPONSES to inbound queries — NOT zero inbound queries: a strict
//! client still RECEIVES probe queries (peers ping/find_node it during traversal), it just never
//! ANSWERS them, so the distinguishing signal is `outbound_responses == 0` (exactly what the
//! TASK-258 `scripts/mainline_spike_measure.py` `client_only_from_pcap` oracle keys on). The
//! vendored crate's own co-located test pins the no-promotion guarantee and is mutation-provable.
//! The shipped path here NEVER uses `DhtRole::Server`; `scripts/check-mainline-client-only.py`
//! enforces that structurally.
//!
//! PRIVACY COST (AC#4), disclosed at startup in `main`: because the announce publishes membership
//! under a PUBLIC infohash, any stranger who knows it can enumerate node MEMBERSHIP (which IPs
//! speak nix-p2p) via `get_peers`. That is node MEMBERSHIP, NOT content HOLDINGS — it does not
//! touch the frozen no-enumeration (holdings) invariant. Opt-in and refused under `lan-share`
//! (TASK-280 isolation, AC#3) and `upstream-only`.
//!
//! TRAFFIC BOUND (PRD "not abusive to the shared DHT we don't own"). A fresh node re-discovers on a
//! SHORT warmup cadence ([`MAINLINE_RENDEZVOUS_WARMUP_SECS`]) so it converges quickly past the
//! normal race where its first `get_peers` precedes the other members' announces — but the warmup is
//! BOUNDED ([`MAINLINE_RENDEZVOUS_WARMUP_CYCLES`]) and ends the moment it has dialed a peer, after
//! which it backs off to the gentle steady cadence ([`MAINLINE_RENDEZVOUS_CYCLE_SECS`]); never a
//! tight spin. Each `get_peers` is itself bounded ([`LookupBound`]: an integer deadline and a
//! distinct-address cap). There is NO persisted peer cache: the node is COLD every boot, so a
//! discovered address is genuinely re-learned from Mainline and the e2e (AC#6) cannot be vacuously
//! handed a cached address it "should have discovered".

use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use fabric_libp2p::{Multiaddr, Protocol, SwarmHandle};
use mainline_rendezvous::{DhtRole, LookupBound, RendezvousNode, announce, build_node, discover};

/// The fixed INTEGER cadence (seconds) for the periodic re-announce + re-discover. Generous — a
/// Mainline announce lives well beyond this on the serving nodes — so the loop is deliberately
/// gentle on infrastructure we do not own. Never a float.
pub const MAINLINE_RENDEZVOUS_CYCLE_SECS: u64 = 300;

/// Per-`get_peers` wall-clock deadline (seconds, integer). Bounds one lookup; an empty result
/// within the bound is a REAL negative (no members yet), not a hidden race.
pub const MAINLINE_RENDEZVOUS_DISCOVER_DEADLINE_SECS: u64 = 10;

/// Per-cycle DISTINCT-address work bound (integer): stop one lookup after this many addresses even
/// on a popular infohash, so a cycle's dial fan-out is bounded.
pub const MAINLINE_RENDEZVOUS_MAX_ADDRS: usize = 64;

/// COLD-START warmup interval (seconds, integer). A fresh node that has dialed NO peer yet
/// re-discovers on this SHORT cadence, because its very first `get_peers` often races ahead of the
/// other members' announces propagating to the bootstrap (an empty first lookup is normal). Once it
/// has dialed at least one peer — or the bounded warmup window elapses — it backs off to the gentle
/// steady [`MAINLINE_RENDEZVOUS_CYCLE_SECS`].
pub const MAINLINE_RENDEZVOUS_WARMUP_SECS: u64 = 5;

/// Bounded number of warmup (short-interval) cycles before falling back to the steady cadence even
/// if still peerless (integer). Caps cold-start traffic: at most this many quick lookups on a
/// genuinely empty rendezvous, then gentle — never an unbounded fast spin.
pub const MAINLINE_RENDEZVOUS_WARMUP_CYCLES: u32 = 12;

// The traffic bounds are INTEGERS (no floats — the OWNER no-floats rule) and generous enough to be
// gentle on the shared DHT (the PRD "not abusive" constraint). Enforced at COMPILE time so a future
// edit that makes the steady cadence a tight spin, or zeroes a lookup bound, fails to build. The
// warmup is short but BOUNDED (a capped number of cycles), so cold-start traffic stays finite.
const _: () = assert!(MAINLINE_RENDEZVOUS_CYCLE_SECS >= 60);
const _: () = assert!(MAINLINE_RENDEZVOUS_DISCOVER_DEADLINE_SECS >= 1);
const _: () = assert!(MAINLINE_RENDEZVOUS_MAX_ADDRS >= 1);
const _: () = assert!(MAINLINE_RENDEZVOUS_WARMUP_SECS >= 1);
const _: () = assert!(MAINLINE_RENDEZVOUS_WARMUP_CYCLES >= 1);
// The whole warmup window must stay well under the steady cadence (it is a cold-start burst, not a
// second steady rate): a bounded burst then gentle.
const _: () = assert!(
    MAINLINE_RENDEZVOUS_WARMUP_SECS * (MAINLINE_RENDEZVOUS_WARMUP_CYCLES as u64)
        <= MAINLINE_RENDEZVOUS_CYCLE_SECS
);

/// Everything the rendezvous task needs, resolved ONCE in `main` before the loop is spawned.
pub struct MainlineRendezvousConfig {
    /// LOCAL Mainline entry point(s) (`--libp2p-mainline-bootstrap`). There is deliberately NO
    /// default (we never contact `router.bittorrent.com`); an empty list is rejected at parse time,
    /// so this is non-empty by the time the task is spawned.
    pub bootstrap: Vec<SocketAddrV4>,
    /// This node's own libp2p listen TCP port to announce as its membership address, when it has a
    /// reachable listen (a provider/router). `None` for a pure consumer with no `--libp2p-listen`:
    /// it announces no dialable address and only DISCOVERS others.
    pub announce_libp2p_port: Option<u16>,
}

/// Owns the spawned rendezvous loop; dropping it aborts the loop (the node stops touching Mainline
/// the moment the daemon shuts down). Held by `main` for the process lifetime.
pub struct MainlineRendezvousGuard {
    task: tokio::task::JoinHandle<()>,
}

impl Drop for MainlineRendezvousGuard {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Convert a discovered BEP5 `SocketAddrV4` (a bare IP:port — NO PeerId, the AC#13 spike finding)
/// into a libp2p TCP DIAL multiaddr `/ip4/<ip>/tcp/<port>`. Deliberately NO `/p2p/<PeerId>` hop:
/// BEP5 carries no PeerId, so libp2p dials the bare address and learns the PeerId from the Noise
/// handshake, after which identify feeds the peer into kad. This is the permitted address-bootstrap
/// path — the same shape as an explicit `--libp2p-bootstrap` dial — never content discovery.
fn dial_multiaddr(addr: SocketAddrV4) -> Multiaddr {
    Multiaddr::empty()
        .with(Protocol::Ip4(*addr.ip()))
        .with(Protocol::Tcp(addr.port()))
}

/// Spawn the opt-in Mainline rendezvous bootstrap loop (TASK-284, AC#1). Builds the strictly-CLIENT
/// Mainline node ONCE (never `server_mode`), then hands it to [`run_mainline_rendezvous`] which
/// announces membership and feeds discovered addresses to the libp2p dial path. The returned guard
/// MUST be held for the process lifetime; dropping it aborts the loop.
///
/// The FUNCTION NAME carries the `mainline`/`rendezvous` token so the discovery guard scans this
/// whole body and confirms it reaches only the dial path, never a content-discovery sink.
pub fn spawn_mainline_rendezvous(
    handle: SwarmHandle,
    config: MainlineRendezvousConfig,
) -> Result<MainlineRendezvousGuard, String> {
    if config.bootstrap.is_empty() {
        return Err(
            "internal: mainline rendezvous spawned with no local Mainline bootstrap (parse_config \
             should have rejected this)"
                .into(),
        );
    }
    // Build the strictly-CLIENT Mainline node ONCE. `DhtRole::Client` sets both `!server_mode()`
    // (answers no inbound BEP5 query) and `no_adaptive()` (the vendored-patch flag that suppresses
    // stock mainline's adaptive promotion of a non-firewalled node) — together the AC#1/#5
    // client-only guarantee. Bind an ephemeral UDP port on ALL interfaces so the announce packet's
    // SOURCE IP is this node's
    // routable address (what a peer will dial). `router.bittorrent.com` is never contacted: the only
    // bootstrap is the operator-supplied LOCAL entry point.
    let dht = build_node(DhtRole::Client, &config.bootstrap, Ipv4Addr::UNSPECIFIED, 0)?;
    let task = tokio::spawn(async move {
        run_mainline_rendezvous(dht, handle, config).await;
    });
    Ok(MainlineRendezvousGuard { task })
}

/// The rendezvous loop body (AC#1): announce membership (if this node has a dialable libp2p port),
/// then `get_peers` the ONE well-known infohash for member ADDRESSES and DIAL each into the libp2p
/// swarm, on a bounded cadence. The FUNCTION NAME carries the `mainline`/`rendezvous` token so the
/// discovery guard scans this whole body; it reaches only `handle.dial` (the address-bootstrap
/// path), never `find_providers`/`get_providers` — content discovery stays kad-exclusive (AC#2).
async fn run_mainline_rendezvous(
    dht: RendezvousNode,
    handle: SwarmHandle,
    config: MainlineRendezvousConfig,
) {
    // Bound bootstrap so a mis-pointed node fails fast instead of hanging forever before the first
    // cycle. A failure here is non-fatal: the periodic cycle keeps retrying announce/discover.
    let _ = tokio::time::timeout(Duration::from_secs(10), dht.bootstrapped()).await;

    let bound = LookupBound {
        deadline: Duration::from_secs(MAINLINE_RENDEZVOUS_DISCOVER_DEADLINE_SECS),
        max_addrs: MAINLINE_RENDEZVOUS_MAX_ADDRS,
    };
    // COLD-START: a fresh node has dialed no peer yet. While that holds (and within a BOUNDED warmup
    // window) it re-discovers on the short warmup cadence, because the very first `get_peers` often
    // races ahead of the other members' announces propagating. Once it has dialed a peer — or the
    // warmup budget is spent — it backs off to the gentle steady cadence.
    let mut dialed_any = false;
    let mut warmup_cycle: u32 = 0;
    loop {
        // ANNOUNCE our membership so a later joiner discovers us. Only when we have a reachable
        // libp2p listen port to publish (a provider/router); a pure consumer only discovers.
        if let Some(port) = config.announce_libp2p_port {
            match announce(&dht, port).await {
                Ok(elapsed) => println!(
                    "MAINLINE-RENDEZVOUS-ANNOUNCE libp2p_port={port} elapsed_ms={}",
                    elapsed.as_millis()
                ),
                Err(err) => tracing::warn!(
                    %err,
                    "daemon-libp2p: mainline rendezvous announce failed (will retry next cycle)"
                ),
            }
        }

        // DISCOVER member addresses and DIAL each into the libp2p swarm. This is the ADDRESS
        // bootstrap: the bare IP:port is dialed; libp2p learns the PeerId via the handshake and
        // identify seeds kad. We never resolve "who holds hash X?" here.
        let found = discover(&dht, bound).await;
        if found.addrs.is_empty() {
            println!(
                "MAINLINE-RENDEZVOUS-DISCOVER count=0 elapsed_ms={}",
                found.elapsed.as_millis()
            );
        } else {
            println!(
                "MAINLINE-RENDEZVOUS-DISCOVER count={} peerid=none elapsed_ms={}",
                found.addrs.len(),
                found.elapsed.as_millis()
            );
            for addr in found.addrs {
                let ma = dial_multiaddr(addr);
                match handle.dial(ma.clone()).await {
                    Ok(()) => {
                        dialed_any = true;
                        println!("MAINLINE-RENDEZVOUS-DIAL addr={ma}");
                    }
                    Err(err) => tracing::debug!(
                        %addr,
                        %err,
                        "daemon-libp2p: mainline rendezvous dial failed to initiate"
                    ),
                }
            }
        }

        // Short warmup cadence while still peerless within the bounded warmup window; gentle steady
        // cadence once a peer has been dialed or the warmup budget is spent.
        let interval = if !dialed_any && warmup_cycle < MAINLINE_RENDEZVOUS_WARMUP_CYCLES {
            warmup_cycle += 1;
            MAINLINE_RENDEZVOUS_WARMUP_SECS
        } else {
            MAINLINE_RENDEZVOUS_CYCLE_SECS
        };
        tokio::time::sleep(Duration::from_secs(interval)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A discovered bare IP:port becomes a `/ip4/../tcp/..` dial multiaddr with NO PeerId hop — the
    /// AC#13 finding (BEP5 carries no PeerId) made concrete, and the exact shape `SwarmHandle::dial`
    /// accepts for an address-only bootstrap dial.
    #[test]
    fn discovered_addr_maps_to_a_bare_tcp_dial_multiaddr() {
        let addr: SocketAddrV4 = "203.0.113.7:14001".parse().unwrap();
        let ma = dial_multiaddr(addr);
        assert_eq!(ma.to_string(), "/ip4/203.0.113.7/tcp/14001");
        // No /p2p/<PeerId> component: BEP5 gives no PeerId, and libp2p learns it from the handshake.
        assert!(
            !ma.iter().any(|p| matches!(p, Protocol::P2p(_))),
            "the dial multiaddr must carry NO PeerId (BEP5 has none): {ma}"
        );
    }
}
