//! nix-p2p product daemon: a transparent Nix binary-cache substituter whose
//! only cleverness is STRUCTURE (PRD wave 0).
//!
//! The daemon serves the tiny Nix binary-cache HTTP API - `nix-cache-info`,
//! `*.narinfo`, `nar/*` - passing signed metadata and NAR payloads through from
//! an upstream cache, behind two capability seams:
//!
//!   * [`NarinfoSource`] - narinfo lookup;
//!   * [`NarSource`] - NAR resolution by content identity to a verified stream.
//!
//! Both have a single [`UpstreamHttp`] impl in wave 1. The seam shape (identity
//! in, not a URL) is what lets wave 2 implement an iroh `NarSource` behind the
//! same trait boundary; the boundary is frozen, though the caller gains
//! narinfo-correlation and URL-rewrite wiring (see [`source`] for the precise
//! scope of what survives).
//!
//! This crate is a library + a thin binary so the in-process integration tests
//! can drive the real serving stack over loopback (`tests/`), the same code the
//! container harness (task-5) will drive over a socket.

mod body;
pub mod cacheinfo;
pub mod rewrite;
pub mod server;
pub mod source;
pub mod upstream;

pub use cacheinfo::CacheInfo;
pub use server::{App, serve};
pub use source::{
    NarBody, NarLocator, NarSource, NarinfoSource, RawUpstream, SourceError, StoreHash,
    UpstreamResponse,
};
pub use upstream::UpstreamHttp;
