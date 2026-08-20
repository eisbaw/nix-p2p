//! LAN-confinement primitives shared by the fabric and the daemon composition roots
//! (TASK-280). Two concerns live here, DOWN in the fabric so both the swarm-internal
//! guards and the daemon-layer LISTEN grammar derive from ONE classifier and cannot drift:
//!
//!   1. The IP/multiaddr LAN classifiers ([`ip_is_provably_private`], [`ip_is_lan_literal`],
//!      [`multiaddr_lan_provenance`]).
//!   2. The [`LanDialGuard`] `NetworkBehaviour` — the swarm-level outbound-dial VETO that
//!      confines a no-allowlist `lan-share` node's egress to LAN peer addresses.
//!
//! The versioned [`LAN_SHARE_NETWORK_SCOPE`] constant lives here too: a `lan-share` node's KAD and
//! NAR substreams negotiate SCOPED protocol names (`/nix-p2p/<scope>/kad/1.0.0`,
//! `/nix-p2p/<scope>/nar/4`), so a same-`v1` dual-homed bridge is cross-scope on the two protocols
//! that carry records and content and can never relay a `lan-share` node's records to the public DHT
//! (the TASK-280 wire freeze). IDENTIFY is DIFFERENT: it negotiates the FIXED libp2p name
//! `/ipfs/id/1.0.0` and carries the scope only in its `protocol_version` METADATA
//! (`/nix-p2p/<scope>/id/1.0.0`); it is NOT a scoped substream. So the scope split alone does not
//! stop a cross-scope peer from completing identify — the swarm additionally REJECTS an identify
//! whose advertised `protocol_version` is not this node's scoped id string under confinement (see
//! `crate::swarm`), dropping its addresses before they can seed routing.

use std::net::IpAddr;
use std::task::{Context, Poll};

use libp2p::core::Endpoint;
use libp2p::core::transport::PortUse;
use libp2p::multiaddr::Protocol;
use libp2p::swarm::{
    ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, THandler, THandlerInEvent,
    THandlerOutEvent, ToSwarm, dummy,
};
use libp2p::{Multiaddr, PeerId};

/// The FROZEN (TASK-280 wire freeze) kad/identify/nar protocol scope for a no-allowlist
/// `lan-share` node. VERSIONED so a future incompatible change can mint `lan-share.v2` without
/// stranding deployed nodes: this string is now a COMPATIBILITY SURFACE — a `lan-share` provider
/// and a `lan-share` consumer MUST agree on it or discovery silently breaks, and a node on the
/// public `v1` scope is structurally shut out of a `lan-share` node's DHT (cross-scope on the
/// scoped `/nix-p2p/<scope>/{kad,id,nar}` protocol names). `--libp2p-scope` overrides it for the
/// deliberate advanced case of a shared scope. Picked now, while cross-host `lan-share` serving is
/// unreleased, so there is no deployed `lan-share`-on-`v1` base to strand (PRD.md risk #13).
pub const LAN_SHARE_NETWORK_SCOPE: &str = "lan-share.v1";

/// Whether an IP literal is PROVABLY PRIVATE: IPv4 RFC1918 (`10/8`, `172.16/12`, `192.168/16`) or
/// IPv6 RFC4193 unique-local (`fc00::/7`). This is the shared admission core (moved DOWN from
/// `daemon-libp2p` in TASK-280 so the fabric-internal guards and the daemon LISTEN grammar cannot
/// drift). It EXCLUDES loopback and link-local (classified separately by [`ip_is_lan_literal`]) and
/// returns `false` for anything NOT provably private, so global/routable unicast, the
/// `0.0.0.0`/`::` wildcard (NOT provably private — on a dual-homed host it names public interfaces
/// too), and CGNAT `100.64/10` (RFC6598 shared ISP space — `is_private` already returns `false`)
/// are all REFUSED. `Ipv6Addr::is_unique_local` is unstable, so the ULA prefix is tested directly.
pub fn ip_is_provably_private(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private(),
        IpAddr::V6(v6) => (v6.segments()[0] & 0xfe00) == 0xfc00,
    }
}

/// Whether an IP literal is a LAN-local literal for confinement purposes: loopback, link-local, or
/// provably-private (RFC1918/ULA, [`ip_is_provably_private`]). This is the IP-hop predicate BOTH the
/// dial VETO ([`multiaddr_lan_provenance`]) and the daemon's strict LISTEN grammar
/// (`multiaddr_is_lan_only`) key on, so "is this a LAN address?" is answered in exactly one place.
/// `Ipv6Addr::is_unicast_link_local` is unstable, so the `fe80::/10` prefix is tested directly.
pub fn ip_is_lan_literal(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_link_local() || ip_is_provably_private(ip),
        IpAddr::V6(v6) => {
            let link_local = (v6.segments()[0] & 0xffc0) == 0xfe80;
            v6.is_loopback() || link_local || ip_is_provably_private(ip)
        }
    }
}

/// Whether a DIAL/SERVE multiaddr has provable LAN provenance, under an EXACT positive grammar over
/// the WHOLE protocol sequence (TASK-280 codex CRITICAL #1). It accepts iff the components are
/// EXACTLY:
///
///   1. one LAN IP literal ([`ip_is_lan_literal`]) — `Ip4(<lan>)` or `Ip6(<lan>)`;
///   2. one DIRECT transport — `Tcp(_)`, OR `Udp(_)` IMMEDIATELY followed by `QuicV1`;
///   3. an OPTIONAL single terminal `/p2p/<peerid>`.
///
/// ANYTHING ELSE is REJECTED (fail-CLOSED): a SECOND `Ip4`/`Ip6` hop (the compound-address bypass —
/// see below), a `/p2p-circuit`, any `/dns*` name, `/ws`/`/wss`/`/tls`/`/sni`, plain draft `/quic`
/// (only `quic-v1` is admitted, matching the shipped `.with_quic()` transport), a bare
/// `/dns/...`/`/memory/...` with no IP literal, or ANY unknown/trailing component after the peer id.
///
/// # Why the whole sequence, not just the first hop
///
/// The earlier implementation scanned for the FIRST IP literal and only rejected relay/DNS hops.
/// That was a CRITICAL bypass: libp2p's TCP/QUIC transport dials the LAST address pair in a
/// multiaddr, so `/ip4/<lan>/tcp/1/ip4/<PUBLIC>/tcp/4001/p2p/<id>` classified LAN (its first hop is
/// `<lan>`) yet the transport actually connects to `<PUBLIC>` — defeating BOTH the dial VETO and the
/// serve-provenance ledger this predicate feeds. A structural whitelist over the full sequence
/// admits ONLY a single-hop direct LAN address, so no second (public) address pair can ride along.
///
/// Unlike the strict LISTEN grammar (`daemon_libp2p::multiaddr_is_lan_only`), this tolerates a
/// trailing `/p2p/<peerid>` because a live dial/serve address legitimately carries the peer
/// component (the LISTEN grammar forbids it because a bind address never does). The transport shape
/// is pinned identically to the LISTEN grammar: the shipped swarm speaks only TCP and QUIC-v1.
pub fn multiaddr_lan_provenance(addr: &Multiaddr) -> bool {
    let comps: Vec<Protocol> = addr.iter().collect();
    let mut i = 0;
    // 1. Exactly one LAN IP literal as the first hop.
    let ip = match comps.first() {
        Some(Protocol::Ip4(v4)) => IpAddr::V4(*v4),
        Some(Protocol::Ip6(v6)) => IpAddr::V6(*v6),
        _ => return false,
    };
    if !ip_is_lan_literal(&ip) {
        return false;
    }
    i += 1;
    // 2. Exactly one DIRECT transport: Tcp, or Udp immediately followed by QuicV1. A second IP hop,
    //    a relay/DNS hop, or a draft `/quic` here all fall through to `return false`.
    match comps.get(i) {
        Some(Protocol::Tcp(_)) => i += 1,
        Some(Protocol::Udp(_)) => {
            i += 1;
            match comps.get(i) {
                Some(Protocol::QuicV1) => i += 1,
                _ => return false,
            }
        }
        _ => return false,
    }
    // 3. Optional single terminal /p2p/<peerid>.
    if let Some(Protocol::P2p(_)) = comps.get(i) {
        i += 1;
    }
    // 4. Nothing may follow: any trailing component (a second address pair, /p2p-circuit, a stray
    //    hop after the peer id) means this is not a single-hop direct LAN address.
    i == comps.len()
}

/// The swarm-level outbound-dial VETO (TASK-280 mitigation #1) that confines a no-allowlist
/// `lan-share` node's egress to LAN peer addresses. Installed as a sibling `NetworkBehaviour` field
/// (`Toggle`-wrapped, DEFAULT OFF) so the derived `NetworkBehaviour` runs it on EVERY
/// behaviour-initiated dial UNIFORMLY — including kad's autonomous by-`PeerId` dials of addresses it
/// learned from query responses, which never pass through `add_address`.
///
/// # Why the veto lives in `handle_established_outbound_connection`, not (only) the pending hook
///
/// The brief's stated mechanism — veto in `handle_pending_outbound_connection` — is INSUFFICIENT
/// for kad-internal dials, and this was verified against the shipped libp2p 0.56 sources rather than
/// assumed:
///   * `libp2p-kad` 0.48 dials a discovered peer with `DialOpts::peer_id(peer).build()` — NO
///     addresses in the `DialOpts`. It supplies the peer's addresses from its k-buckets AND its
///     in-flight query responses through its OWN `handle_pending_outbound_connection` RETURN value.
///   * The `#[derive(NetworkBehaviour)]` macro (libp2p-swarm-derive 0.35) passes every field the
///     SAME original `addresses` slice (empty for a by-`PeerId` dial) and merely CONCATENATES their
///     returns; it never re-feeds one field's supplied addresses to another. So a sibling guard's
///     `handle_pending_outbound_connection` sees an EMPTY slice for a kad dial and cannot veto by
///     address there.
///
/// `handle_established_outbound_connection` IS called once per CONCRETE address the swarm actually
/// dials, and the derive chains every field's impl with `?`, so THIS is the one place a sibling
/// behaviour sees kad's chosen address and can deny it. Denying here aborts the connection BEFORE its
/// `ConnectionHandler` is built — before `ConnectionEstablished` is delivered to any behaviour, so no
/// application substream ever opens: kad never exchanges a message over it, identify never runs, and
/// no NAR stream opens. HONEST RESIDUAL (corrected, codex #5): the swarm calls this hook only AFTER
/// the transport is upgraded, so by the time the deny fires a non-LAN dial has already completed a
/// NOISE SESSION — the remote learns our peer-id and observes our source address (and we learn its
/// peer-id). No kad/identify/nar application substream ever opens on it (the handler is never built),
/// so no record, membership, or content byte crosses; the leak is the connection metadata of one
/// dropped session. A pre-connect (pre-Noise) filter would need a transport-level dial predicate,
/// which the pinned libp2p 0.56 phased `SwarmBuilder` (`.with_tcp/.with_quic/.with_relay_client`)
/// exposes no hook for; the guard is ordered FIRST in the `Behaviour` derive so it denies before any
/// sibling can act on the connection. The pending hook below ALSO vetoes when the swarm already holds
/// explicit non-LAN candidate addresses, denying those pre-transport (defense in depth for direct
/// `dial(addr)` calls).
///
/// `pub` (not `pub(crate)`) only to satisfy the `#[derive(NetworkBehaviour)]` field-visibility rule
/// on the crate-internal (never re-exported) [`crate::swarm::Behaviour`]; the `lan` module is
/// private, so this type does not enter the crate's public API.
pub struct LanDialGuard;

impl NetworkBehaviour for LanDialGuard {
    type ConnectionHandler = dummy::ConnectionHandler;
    type ToSwarm = std::convert::Infallible;

    fn handle_established_inbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        _peer: PeerId,
        _local_addr: &Multiaddr,
        _remote_addr: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        // Inbound is not confined here: a LAN-only listener already can only be reached from the
        // LAN, and inbound-serve provenance is enforced separately at the NAR accept loop.
        Ok(dummy::ConnectionHandler)
    }

    fn handle_pending_outbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        _maybe_peer: Option<PeerId>,
        addresses: &[Multiaddr],
        _effective_role: Endpoint,
    ) -> Result<Vec<Multiaddr>, ConnectionDenied> {
        // Pre-transport veto for dials that ALREADY carry explicit candidate addresses (a direct
        // `dial(addr)`): if every candidate is non-LAN, deny before any SYN. A by-`PeerId` kad dial
        // arrives here with an EMPTY slice (see the type doc) — allow it through so it reaches the
        // per-address veto below, never allow-by-default a populated non-LAN set.
        if !addresses.is_empty() && !addresses.iter().any(multiaddr_lan_provenance) {
            return Err(ConnectionDenied::new(format!(
                "lan-share confinement: refusing outbound dial — none of the {} candidate \
                 address(es) has LAN provenance (first non-LAN: {})",
                addresses.len(),
                addresses[0]
            )));
        }
        Ok(vec![])
    }

    fn handle_established_outbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        _peer: PeerId,
        addr: &Multiaddr,
        _role_override: Endpoint,
        _port_use: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        if multiaddr_lan_provenance(addr) {
            Ok(dummy::ConnectionHandler)
        } else {
            Err(ConnectionDenied::new(format!(
                "lan-share confinement: refusing outbound connection to non-LAN address {addr} \
                 (first IP hop is not loopback/link-local/private, or a relay/DNS hop is present)"
            )))
        }
    }

    fn on_swarm_event(&mut self, _event: FromSwarm) {}

    fn on_connection_handler_event(
        &mut self,
        _peer_id: PeerId,
        _connection_id: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        // The dummy handler's `ToBehaviour` is `Infallible`: no event can ever arrive.
        match event {}
    }

    fn poll(
        &mut self,
        _cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ma(s: &str) -> Multiaddr {
        s.parse().expect("valid multiaddr")
    }

    #[test]
    fn ip_provably_private_classifies_rfc1918_and_ula() {
        assert!(ip_is_provably_private(&"10.0.0.1".parse().unwrap()));
        assert!(ip_is_provably_private(&"172.16.5.5".parse().unwrap()));
        assert!(ip_is_provably_private(&"192.168.1.1".parse().unwrap()));
        assert!(ip_is_provably_private(&"fc00::1".parse().unwrap()));
        assert!(ip_is_provably_private(&"fd12:3456::1".parse().unwrap()));
        // NOT provably private:
        assert!(!ip_is_provably_private(&"8.8.8.8".parse().unwrap()));
        assert!(!ip_is_provably_private(&"127.0.0.1".parse().unwrap())); // loopback, classified elsewhere
        assert!(!ip_is_provably_private(&"169.254.1.1".parse().unwrap())); // link-local, elsewhere
        assert!(!ip_is_provably_private(&"100.64.0.1".parse().unwrap())); // CGNAT
        assert!(!ip_is_provably_private(&"0.0.0.0".parse().unwrap())); // wildcard
    }

    #[test]
    fn ip_lan_literal_adds_loopback_and_link_local() {
        assert!(ip_is_lan_literal(&"127.0.0.1".parse().unwrap()));
        assert!(ip_is_lan_literal(&"::1".parse().unwrap()));
        assert!(ip_is_lan_literal(&"169.254.9.9".parse().unwrap()));
        assert!(ip_is_lan_literal(&"fe80::1".parse().unwrap()));
        assert!(ip_is_lan_literal(&"10.1.2.3".parse().unwrap()));
        assert!(!ip_is_lan_literal(&"8.8.8.8".parse().unwrap()));
        assert!(!ip_is_lan_literal(&"1.1.1.1".parse().unwrap()));
    }

    #[test]
    fn provenance_admits_lan_dial_serve_addresses() {
        // Bare LAN literals + transports:
        assert!(multiaddr_lan_provenance(&ma("/ip4/10.211.34.5/tcp/4001")));
        assert!(multiaddr_lan_provenance(&ma(
            "/ip4/192.168.1.9/udp/4001/quic-v1"
        )));
        assert!(multiaddr_lan_provenance(&ma("/ip6/fc00::9/tcp/4001")));
        assert!(multiaddr_lan_provenance(&ma("/ip4/127.0.0.1/tcp/4001")));
        assert!(multiaddr_lan_provenance(&ma("/ip4/169.254.3.3/tcp/4001")));
        // Trailing /p2p/<peerid> is TOLERATED (unlike the strict LISTEN grammar):
        assert!(multiaddr_lan_provenance(&ma(
            "/ip4/10.0.0.7/tcp/4001/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN"
        )));
    }

    #[test]
    fn provenance_refuses_global_relay_and_dns() {
        // Global unicast:
        assert!(!multiaddr_lan_provenance(&ma("/ip4/8.8.8.8/tcp/4001")));
        assert!(!multiaddr_lan_provenance(&ma(
            "/ip4/99.99.1.1/udp/4001/quic-v1"
        )));
        // Wildcard binds public interfaces too:
        assert!(!multiaddr_lan_provenance(&ma("/ip4/0.0.0.0/tcp/4001")));
        // CGNAT shared space:
        assert!(!multiaddr_lan_provenance(&ma("/ip4/100.64.0.1/tcp/4001")));
        // A relay circuit bridges off-LAN even with a LAN relay literal:
        assert!(!multiaddr_lan_provenance(&ma(
            "/ip4/10.0.0.1/tcp/4001/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN/p2p-circuit"
        )));
        // DNS names resolve to who-knows-what:
        assert!(!multiaddr_lan_provenance(&ma("/dns4/example.com/tcp/4001")));
        assert!(!multiaddr_lan_provenance(&ma("/dns/localhost/tcp/4001")));
        // No IP literal at all:
        assert!(!multiaddr_lan_provenance(&ma("/memory/1234")));
    }

    #[test]
    fn provenance_rejects_compound_address_bypass() {
        // codex CRITICAL #1: libp2p's transport dials the TERMINAL address pair, so a multiaddr whose
        // FIRST hop is LAN but which carries a SECOND (public) hop must be REJECTED — the exact
        // grammar rejects the second address pair. MUTATION: revert `multiaddr_lan_provenance` to the
        // old first-hop scan and every assertion in this test flips to accept (RED-on-revert).
        let id = "12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN";
        // LAN first hop, PUBLIC terminal pair (TCP): the dial actually reaches 203.0.113.7.
        assert!(!multiaddr_lan_provenance(&ma(&format!(
            "/ip4/10.211.34.5/tcp/1/ip4/203.0.113.7/tcp/4001/p2p/{id}"
        ))));
        // Same, but the second pair is QUIC.
        assert!(!multiaddr_lan_provenance(&ma(&format!(
            "/ip4/10.211.34.5/tcp/1/ip4/203.0.113.7/udp/4001/quic-v1/p2p/{id}"
        ))));
        // The peer id is NOT terminal — a public pair rides AFTER it.
        assert!(!multiaddr_lan_provenance(&ma(&format!(
            "/ip4/10.0.0.7/tcp/1/p2p/{id}/ip4/203.0.113.7/tcp/4001"
        ))));
        // Two LAN hops are still rejected (single-hop-only; a second pair of ANY provenance rides).
        assert!(!multiaddr_lan_provenance(&ma(
            "/ip4/10.0.0.7/tcp/1/ip4/192.168.1.9/tcp/4001"
        )));
    }

    #[test]
    fn provenance_pins_the_exact_transport_grammar() {
        // The transport shape is pinned to what the shipped swarm speaks (TCP / QUIC-v1). Positive
        // grammar: draft `/quic`, a `/udp` with no `quic-v1`, `/ws`/`/tls`, a stray trailing hop
        // after the peer id, and a bare IP with no transport are all REFUSED.
        let id = "12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN";
        assert!(!multiaddr_lan_provenance(&ma("/ip4/10.0.0.5"))); // no transport
        assert!(!multiaddr_lan_provenance(&ma("/ip4/10.0.0.5/udp/4001"))); // udp without quic-v1
        assert!(!multiaddr_lan_provenance(&ma("/ip4/10.0.0.5/tcp/4001/ws"))); // ws layered on tcp
        assert!(!multiaddr_lan_provenance(&ma(&format!(
            "/ip4/10.0.0.5/tcp/4001/p2p/{id}/p2p-circuit"
        )))); // trailing hop after the peer id
    }

    #[test]
    fn dial_guard_established_hook_vetoes_non_lan_admits_lan() {
        // The REAL chokepoint (covers kad's autonomous by-PeerId dials): the per-address established
        // hook. MUTATION: invert the `multiaddr_lan_provenance` branch in
        // `handle_established_outbound_connection` and both assertions flip.
        let mut guard = LanDialGuard;
        let cid = ConnectionId::new_unchecked(1);
        let peer = PeerId::random();
        // LAN address: admitted (Ok handler).
        assert!(
            guard
                .handle_established_outbound_connection(
                    cid,
                    peer,
                    &ma("/ip4/10.0.0.5/tcp/4001"),
                    Endpoint::Dialer,
                    PortUse::Reuse,
                )
                .is_ok(),
            "the dial guard must ADMIT a LAN outbound connection"
        );
        // Global address: DENIED with an attributable reason. (`handle_established_outbound_connection`'s
        // Ok type is the dummy handler, which is not `Debug`, so extract the Err via `.err()`.)
        let denied = guard.handle_established_outbound_connection(
            cid,
            peer,
            &ma("/ip4/8.8.8.8/tcp/4001"),
            Endpoint::Dialer,
            PortUse::Reuse,
        );
        assert!(
            denied.is_err(),
            "the dial guard must DENY a global outbound connection"
        );
        let err = denied.err().unwrap();
        assert!(
            format!("{err:?}").contains("lan-share confinement"),
            "the denial must attribute to LAN confinement, got: {err:?}"
        );
    }

    #[test]
    fn dial_guard_pending_hook_denies_all_non_lan_but_passes_empty() {
        // The pre-transport hook denies EXPLICIT-address dials whose every candidate is non-LAN, and
        // passes an EMPTY slice through (a by-PeerId kad dial supplies addresses elsewhere; the
        // per-address hook vetoes those). MUTATION: drop the `!addresses.is_empty()` guard clause or
        // the `any(..)` check and the respective assertion flips.
        let mut guard = LanDialGuard;
        let cid = ConnectionId::new_unchecked(2);
        // All-non-LAN explicit candidates -> denied.
        assert!(
            guard
                .handle_pending_outbound_connection(
                    cid,
                    None,
                    &[ma("/ip4/8.8.8.8/tcp/1"), ma("/ip4/1.1.1.1/tcp/1")],
                    Endpoint::Dialer,
                )
                .is_err(),
            "the pending hook must DENY an all-non-LAN explicit dial pre-transport"
        );
        // At least one LAN candidate -> allowed.
        assert!(
            guard
                .handle_pending_outbound_connection(
                    cid,
                    None,
                    &[ma("/ip4/8.8.8.8/tcp/1"), ma("/ip4/192.168.0.9/tcp/1")],
                    Endpoint::Dialer,
                )
                .is_ok(),
            "the pending hook must ALLOW a dial that has a LAN candidate"
        );
        // Empty slice (by-PeerId dial) -> allowed here, vetoed later per-address.
        assert!(
            guard
                .handle_pending_outbound_connection(
                    cid,
                    Some(PeerId::random()),
                    &[],
                    Endpoint::Dialer
                )
                .is_ok(),
            "an empty (by-PeerId) candidate set must pass the pending hook (vetoed per-address later)"
        );
    }

    #[test]
    fn scope_constant_is_versioned_and_frozen() {
        // WIRE FREEZE guard: this string is a compatibility surface. If it changes, a deployed
        // lan-share provider and consumer would silently stop finding each other. Change it ONLY
        // by minting a new version (lan-share.v2) with a migration story (PRD.md risk #13).
        assert_eq!(LAN_SHARE_NETWORK_SCOPE, "lan-share.v1");
    }
}
