use std::{
    net::{Ipv4Addr, SocketAddrV4},
    time::Duration,
};

use super::{ServerSettings, DEFAULT_REQUEST_TIMEOUT};

#[derive(Debug, Clone)]
/// Dht Configurations
pub struct Config {
    /// Bootstrap nodes
    ///
    /// Defaults to [super::DEFAULT_BOOTSTRAP_NODES]
    pub bootstrap: Option<Vec<SocketAddrV4>>,
    /// Explicit port to listen on.
    ///
    /// Defaults to None
    pub port: Option<u16>,
    /// UDP socket request timeout duration.
    ///
    /// The longer this duration is, the longer queries take until they are deemeed "done".
    /// The shortet this duration is, the more responses from busy nodes we miss out on,
    /// which affects the accuracy of queries trying to find closest nodes to a target.
    ///
    /// Defaults to [DEFAULT_REQUEST_TIMEOUT]
    pub request_timeout: Duration,
    /// Server to respond to incoming Requests
    pub server_settings: ServerSettings,
    /// Whether or not to start in server mode from the get go.
    ///
    /// Defaults to false where it will run in [Adaptive mode](https://github.com/pubky/mainline?tab=readme-ov-file#adaptive-mode).
    pub server_mode: bool,
    /// LOCAL VENDOR PATCH (nix-p2p TASK-284): disable the adaptive server-mode
    /// promotion entirely.
    ///
    /// Stock mainline runs an ADAPTIVE policy: a node that did NOT request
    /// [`server_mode`](Self::server_mode) is still promoted to a SERVING DHT node by
    /// `Rpc::try_switching_to_server_mode` once it proves publicly reachable (not
    /// firewalled). nix-p2p uses this crate purely as a CLIENT-only peer-address
    /// rendezvous and must NEVER serve the public BitTorrent DHT (TASK-258 privacy
    /// requirement, TASK-284 AC#5 "strictly client-only"). When `true`, the adaptive
    /// promotion is a no-op, so a node stays a client forever unless `server_mode`
    /// was explicitly requested.
    ///
    /// Defaults to `false` — stock adaptive behaviour is unchanged for any caller
    /// that does not opt in via [`DhtBuilder::no_adaptive`](crate::DhtBuilder::no_adaptive).
    pub no_adaptive: bool,
    /// A known public IPv4 address for this node to generate
    /// a secure node Id from according to [BEP_0042](https://www.bittorrent.org/beps/bep_0042.html)
    ///
    /// Defaults to None, where we depend on suggestions from responding nodes.
    pub public_ip: Option<Ipv4Addr>,
    /// Address to bind to.
    ///
    /// Defaults to 0.0.0.0 (all interfaces)
    pub bind_address: Option<Ipv4Addr>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bootstrap: None,
            port: None,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            server_settings: Default::default(),
            server_mode: false,
            no_adaptive: false,
            public_ip: None,
            bind_address: None,
        }
    }
}
