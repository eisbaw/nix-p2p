//! TASK-174: the Miss/`InsufficientRouting` boundary is gated on a NEAR-KEY query-stats
//! bar (how many peers actually answered the walk toward the key), not on a TOTAL
//! routing-table count. This test pins the case the old `routing_peers() == 0` bar
//! CONFLATED:
//!
//!   (a) a node whose routing table is NON-EMPTY (`routing_peers() > 0`) but whose only
//!       entry is DEAD - a bogus address that refuses every dial - so a `get_providers`
//!       / `get_closest_peers` walk reaches NOBODY (`num_successes == 0`). This is a
//!       could-not-consult: the honest answer is `Unavailable(InsufficientRouting)`, NOT
//!       a `Miss`. Under the OLD bar this node passed `routing_peers() > 0` and its empty
//!       result collapsed to a (false) `Miss`.
//!
//!   (b) a node genuinely on the network that queries a key nobody provides -> the walk
//!       REACHES responding peers, finds nothing, and that IS an authoritative `Miss`.
//!       Case (b) is already pinned green by `node_locator_discovery.rs` (the
//!       `unknown_node` MISS arm: a joined resolver, routing reaches B/P, `answered > 0`)
//!       and by `decentralized_discovery.rs`; this file adds the (a) half the old bar
//!       could not express.
//!
//! MUTATION BITE: revert `swarm::absence_from_reach` to always `Lookup::Miss` (the old
//! behaviour for a non-empty routing table with an empty result), OR revert the bar to
//! `routing_peers() == 0`, and BOTH assertions below flip from `InsufficientRouting` to
//! `Miss` - the test fails. The oracle observes exactly the boundary the change moves.

use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use fabric_libp2p::{Libp2pFabric, Multiaddr, NodeConfig, PeerId};
use peer_fabric::{
    ContentKey, DiscoveryBudget, Lookup, NodeId, PeerFabric, ResolutionPolicy, Unavailable,
};

/// Start an isolated single node on its own network scope (no bootstrap, no peers).
fn start_node(seed_byte: u8, scope: &str) -> Libp2pFabric {
    Libp2pFabric::start(NodeConfig::new([seed_byte; 32]).with_network_scope(scope))
        .expect("swarm builds")
}

/// An ed25519 identity whose PeerId is NOT in any routing table: a valid point (so
/// `locate` does not reject it as malformed) that nobody on the network knows.
fn unknown_node(seed_byte: u8) -> NodeId {
    let sk = SigningKey::from_bytes(&[seed_byte; 32]);
    NodeId::from_bytes(sk.verifying_key().to_bytes())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dead_routing_entry_is_insufficient_routing_not_miss() {
    let _ = tracing_subscriber::fmt::try_init();
    let node = start_node(0x21, "near-key-dead-entry");

    // Inject ONE dead routing entry: a random PeerId at a loopback port nothing listens
    // on (127.0.0.1:1 -> connection refused on every dial). This makes the routing table
    // NON-EMPTY - the old total-routing bar would treat the node as "on the network" -
    // while no query can actually reach anyone through it.
    let dead_peer = PeerId::random();
    let dead_addr: Multiaddr = "/ip4/127.0.0.1/tcp/1".parse().unwrap();
    node.handle().add_address(dead_peer, dead_addr).await;

    // Precondition for the bite: the routing table IS non-empty (else this would just be
    // the empty-table pre-check, not the near-key bar). If kad ever stopped counting an
    // added address, this fails loudly rather than passing for the wrong reason.
    assert!(
        node.handle().routing_peers().await > 0,
        "the injected dead entry must make routing_peers() > 0, or this test is not \
         exercising the near-key bar (it would be the empty-table pre-check instead)"
    );

    // (a-directory) find_providers over a key nobody provides: the index walk reaches the
    // dead entry only, nobody answers (answered == 0) -> InsufficientRouting, NOT Miss.
    let key = ContentKey::from_bytes([0x55; 32]);
    let budget = DiscoveryBudget::new(Duration::from_secs(8), 32);
    let dir = node.provider_directory().expect("directory present");
    let started = Instant::now();
    let outcome = dir.find_providers(&key, &budget).await;
    assert!(
        matches!(
            outcome,
            Lookup::Unavailable(Unavailable::InsufficientRouting)
        ),
        "a lookup whose only routing entry is DEAD reached nobody near the key: it must be \
         Unavailable(InsufficientRouting), never a (false) Miss. Got {outcome:?} after {:?}",
        started.elapsed()
    );

    // (a-locator) the SAME near-key bar on the peer-routing path: locate a peer nobody
    // knows. The walk reaches the dead entry only -> answered == 0 -> InsufficientRouting.
    let locator = node.node_locator().expect("locator present");
    let located = locator
        .locate(&unknown_node(0x7e), &ResolutionPolicy::PublicInfrastructure)
        .await;
    assert!(
        matches!(
            located,
            Lookup::Unavailable(Unavailable::InsufficientRouting)
        ),
        "peer-routing whose only routing entry is DEAD reached nobody: it must be \
         Unavailable(InsufficientRouting), never a (false) Miss. Got {located:?}"
    );
}
