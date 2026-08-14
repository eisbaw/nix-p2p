//! TASK-210: the kad iterative-query timeout is CONFIGURABLE and the configured value
//! actually reaches `kad::Config::set_query_timeout`.
//!
//! TASK-209's tc-netem RTT sweep showed the OLD hardcoded 10s `query_timeout` covers only
//! up to ~250ms one-way RTT and silently DeadlineExceeds GEO-satellite (~600ms one-way)
//! peers. TASK-210 lifts that literal into [`NodeConfig::kad_query_timeout`] (default
//! [`fabric_libp2p::DEFAULT_KAD_QUERY_TIMEOUT`] = 30s). This test proves the plumbing WITHOUT
//! a shaped link: two consumers join the SAME holder over loopback and issue the SAME
//! `get_providers` query; the one built with an absurdly small timeout gets
//! [`QueryFail::Timeout`] (the timer fires before the round trip completes), while the one
//! built with the generous default REACHES the holder and returns `Ok`. A regression that
//! re-hardcodes the timeout (ignoring config) would let the small-timeout node reach the
//! holder and return `Ok` too — so the `Err(Timeout)` assertion below BITES that mutation.
//!
//! The end-to-end "budget holds at 600ms one-way" claim (AC#1/#2) is validated by the
//! shaped harness `just shaped-kad --sweep` (scripts/shaped_kad.py), whose consumer now
//! threads its `--disc-budget-secs` arg into `kad_query_timeout`; that run is heavier
//! (netns + tc) and lives outside this in-process gate.

use std::time::{Duration, Instant};

use fabric_libp2p::{DEFAULT_KAD_QUERY_TIMEOUT, Multiaddr, Node, NodeConfig, QueryFail};
use libp2p::kad::RecordKey;

/// Bring up a loopback node on `scope`, optionally overriding the kad query timeout, and
/// return it with its concrete bound listen address.
async fn start_node(
    seed_byte: u8,
    scope: &str,
    kad_query_timeout: Option<Duration>,
) -> (Node, Multiaddr) {
    let mut config = NodeConfig::new([seed_byte; 32]).with_network_scope(scope);
    if let Some(t) = kad_query_timeout {
        config = config.with_kad_query_timeout(t);
    }
    let node = Node::start(config).expect("swarm builds");
    node.handle
        .listen("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .await
        .expect("listen bound");

    let deadline = Instant::now() + Duration::from_secs(5);
    let addr = loop {
        if let Some(addr) = node.handle.listen_addrs().await.into_iter().next() {
            break addr;
        }
        assert!(Instant::now() < deadline, "no listen address bound in time");
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    (node, addr)
}

/// Teach `node` the holder's address, dial it, and wait until it sits in the routing table
/// so a subsequent query has a real candidate to contact (and thus a real round trip to
/// race against the query timeout).
async fn join(node: &Node, holder_peer: libp2p::PeerId, holder_addr: Multiaddr) {
    node.handle
        .add_address(holder_peer, holder_addr.clone())
        .await;
    node.handle.dial(holder_addr).await.expect("dial holder");
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if node.handle.routing_peers().await >= 1 {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "holder never entered the routing table"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// The documented default is locked so an accidental edit to the literal is caught (the
/// justification comment in swarm.rs is calibrated to exactly this value).
#[test]
fn default_kad_query_timeout_is_30s() {
    assert_eq!(DEFAULT_KAD_QUERY_TIMEOUT, Duration::from_secs(30));
    // The default flows into a fresh config.
    assert_eq!(
        NodeConfig::new([0u8; 32]).kad_query_timeout,
        Duration::from_secs(30)
    );
    // And the builder overrides it (integer Duration; no float).
    assert_eq!(
        NodeConfig::new([0u8; 32])
            .with_kad_query_timeout(Duration::from_secs(45))
            .kad_query_timeout,
        Duration::from_secs(45)
    );
}

/// A per-node `kad_query_timeout` actually reaches `set_query_timeout`: the tiny-timeout
/// consumer TIMES OUT on a query the generous-timeout consumer completes over the same
/// loopback link to the same holder.
#[tokio::test]
async fn configured_query_timeout_reaches_kad() {
    let scope = "task210-query-timeout";

    // The holder answers queries (kad Server mode) but provides nothing for our key.
    let (holder, holder_addr) = start_node(1, scope, None).await;
    let holder_peer = holder.peer_id;

    // A key nobody provides: the query walks to the holder, which answers with an empty
    // provider set. Reaching that answer is the "did NOT time out" signal.
    let key = RecordKey::new(&b"task210-no-such-provider-key");

    // Consumer with an absurdly small timeout: the timer fires before any round trip can
    // complete, so the query can only end as Timeout.
    let (fast_expire, _fa) = start_node(2, scope, Some(Duration::from_nanos(1))).await;
    join(&fast_expire, holder_peer, holder_addr.clone()).await;
    let tiny = tokio::time::timeout(
        Duration::from_secs(5),
        fast_expire.handle.get_providers(key.clone(), 32),
    )
    .await
    .expect("the 1ns-timeout query must resolve well within 5s");
    assert!(
        matches!(tiny, Err(QueryFail::Timeout)),
        "a 1ns kad_query_timeout must yield QueryFail::Timeout, got {tiny:?} \
         (a re-hardcoded timeout would instead reach the holder and return Ok)"
    );

    // Consumer with the generous default: same topology, same key, but the query has ample
    // time to reach the holder and return an authoritative empty answer.
    let (generous, _ge) = start_node(3, scope, None).await;
    join(&generous, holder_peer, holder_addr.clone()).await;
    let ok = tokio::time::timeout(
        Duration::from_secs(10),
        generous.handle.get_providers(key.clone(), 32),
    )
    .await
    .expect("the default-timeout query must resolve within 10s over loopback");
    let fan_out = ok.expect("the default-timeout query must reach the holder (Ok)");
    assert!(
        fan_out.providers.is_empty(),
        "nobody provides this key; expected an empty provider set, got {:?}",
        fan_out.providers
    );
    assert!(
        !fan_out.truncated,
        "an empty index over a generous budget must not report truncation"
    );
    assert!(
        fan_out.reach.reached_neighborhood(),
        "the query should have reached the responding holder (answered > 0)"
    );
}
