//! `/nix-cache-info` served LOCALLY by the daemon (not proxied).
//!
//! Why local, not passthrough: Nix fetches `nix-cache-info` first, and if that
//! request hangs (because the upstream is momentarily down) Nix marks the whole
//! substituter failed. The additive invariant (S2) needs the daemon to keep
//! advertising itself instantly regardless of upstream health, so cache-info is
//! generated from local config and never touches the network.
//!
//! Wave-1 decisions (AC#5), recorded here so the reasoning travels with the
//! code:
//!
//! * **`Priority: 30`** - below cache.nixos.org's 40 so Nix prefers the daemon
//!   (bandwidth offload is the entire point of wave 0). Not 0/1: that would
//!   over-claim absolute preference and leave an operator no room to place an
//!   even-more-preferred local or corporate cache *ahead* of the daemon without
//!   editing our advertised value. 30 says "prefer me over the CDN, but you can
//!   still front me."
//!
//! * **`WantMassQuery: 1`** - the daemon's designed role is to be the operator's
//!   preferred substituter that intercepts ALL binary-cache traffic to carry
//!   measurement (task-9) and, in wave 2, prefetch. `WantMassQuery: 0` tells Nix
//!   to avoid speculative/mass narinfo queries to a cache, which would starve
//!   exactly the traffic the daemon exists to observe and offload. The
//!   mass-query *amplification* worry is real but does not bite wave 1: the
//!   daemon relays narinfo queries 1:1 to upstream (no worse than Nix querying
//!   cache.nixos.org directly), and task-8's disk cache absorbs repeats. True
//!   amplification - fanning one query into many sources - is a wave-2 p2p
//!   concern, guarded there by the peer-probe/announce budget, not by this 1:1
//!   HTTP passthrough.
//!
//! * **`StoreDir: /nix/store`** - configurable, defaulting to the near-universal
//!   store path (and the fixture's). Echoing the upstream's advertised StoreDir
//!   instead would couple cache-info to an upstream fetch and reintroduce the
//!   hang this module avoids; deferred as a refinement (see backlog).

/// The advertised binary-cache identity. Kept as data so `main` owns the policy
/// values and tests can assert the exact bytes.
#[derive(Debug, Clone)]
pub struct CacheInfo {
    pub store_dir: String,
    pub priority: u32,
    pub want_mass_query: bool,
}

/// Wave-1 default priority: distinctly below cache.nixos.org's 40, with headroom
/// above and below (see module docs).
pub const DEFAULT_PRIORITY: u32 = 30;

impl Default for CacheInfo {
    fn default() -> Self {
        CacheInfo {
            store_dir: "/nix/store".to_string(),
            priority: DEFAULT_PRIORITY,
            want_mass_query: true,
        }
    }
}

impl CacheInfo {
    /// Render the `nix-cache-info` body. All three fields are written
    /// explicitly: a consumer that omits `Priority`/`WantMassQuery` silently
    /// inherits Nix's client defaults, which is exactly the ordering ambiguity
    /// AC#5 forbids.
    pub fn render(&self) -> String {
        format!(
            "StoreDir: {}\nWantMassQuery: {}\nPriority: {}\n",
            self.store_dir,
            u8::from(self.want_mass_query),
            self.priority,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_advertises_a_preferred_priority_below_the_cdn() {
        let info = CacheInfo::default();
        assert!(
            info.priority < 40,
            "priority must be below cache.nixos.org's 40 so Nix prefers the daemon"
        );
        assert!(
            info.priority > 1,
            "priority above 1 leaves room to front the daemon with a more-preferred cache"
        );
    }

    #[test]
    fn render_writes_all_three_fields_explicitly() {
        let body = CacheInfo::default().render();
        assert_eq!(
            body,
            "StoreDir: /nix/store\nWantMassQuery: 1\nPriority: 30\n"
        );
        // Guard against a field silently dropping to a client default.
        assert!(body.contains("WantMassQuery: 1"));
        assert!(body.contains("Priority: 30"));
        assert!(body.contains("StoreDir: /nix/store"));
    }

    #[test]
    fn want_mass_query_zero_renders_zero() {
        let info = CacheInfo {
            want_mass_query: false,
            ..CacheInfo::default()
        };
        assert!(info.render().contains("WantMassQuery: 0"));
    }
}
