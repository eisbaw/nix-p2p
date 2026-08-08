//! nix-p2p test cache-proxy: a simple transparent CACHING proxy fronting a
//! configurable upstream binary cache.
//!
//! This is the permanent test fixture (PRD round 4), not the product. It is
//! deliberately simple and hardcoding-friendly, and it owns ALL fault injection
//! so adversarial-upstream logic never lives in the modular daemon. Its whole
//! dependency set is `std`: it shares no HTTP crate with the daemon because it
//! depends on no HTTP crate at all, which is the strongest possible form of the
//! "independent witness of wire behaviour" that PRD round 5 requires. `just
//! independence` still enforces no shared workspace crate, and its HTTP-stack
//! denylist enforces the two never converging on one third-party stack.
//!
//! Responsibilities:
//!   * transparent passthrough of `/nix-cache-info`, `*.narinfo`, `nar/*`;
//!   * an on-disk cache with atomic (tmp+rename) writes and NAR streaming;
//!   * a request log that is the ground-truth oracle for e2e (per-request kind,
//!     bytes, timing; narinfo->nar gap per path);
//!   * the seven TESTING.md fault modes, all client-facing so the cache stays
//!     byte-correct.

pub mod cache;
pub mod config;
pub mod fault;
pub mod http;
pub mod json;
pub mod kind;
pub mod origin;
pub mod proxy;
pub mod record;
pub mod server;

use std::io;
use std::sync::Arc;

pub use config::Config;
pub use proxy::State;
pub use server::Server;

/// Start the proxy on `config.listen`, returning the running server and its
/// shared state. The state handle lets in-process callers (the bite tests)
/// inspect the log and drive faults directly, alongside the HTTP admin surface.
pub fn spawn(config: Config) -> io::Result<(Server, Arc<State>)> {
    let state = State::new(config)?;
    let listen = state.config.listen;
    let handler_state = Arc::clone(&state);
    let server = server::spawn(listen, move |request, stream| {
        proxy::handle(&handler_state, request, stream);
    })?;
    Ok((server, state))
}

/// Run the proxy until the process is killed (used by `main`).
pub fn serve(config: Config) -> io::Result<()> {
    let (server, state) = spawn(config)?;
    eprintln!(
        "testproxy: listening on {} -> upstream {} (cache {})",
        server.addr,
        state.config.upstream,
        state.config.cache_dir.display()
    );
    server.wait();
    Ok(())
}
