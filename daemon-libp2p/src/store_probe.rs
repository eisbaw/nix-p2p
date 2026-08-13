//! The libp2p provider's [`CatalogProbe`] over the daemon-core availability supply catalog.
//!
//! The libp2p provider's supply seam is [`fabric_libp2p::CatalogProbe`] (returning
//! [`fabric_libp2p::ProbedSupply`]). The daemon fills it from the availability index's inert
//! read handle [`daemon_core::SupplyCatalogHandle`]. This is the EXACT libp2p analogue of the
//! iroh provider's `daemon/src/iroh_catalog_probe.rs` (TASK-146), for TASK-191's store-supply
//! wiring.
//!
//! ## Why a NEWTYPE (orphan rule)
//!
//! `daemon-core` is stack-neutral and does NOT depend on `fabric-libp2p`, so it cannot
//! implement `CatalogProbe` for `SupplyCatalogHandle` there. The orphan rule also forbids this
//! crate implementing that foreign trait for the foreign `SupplyCatalogHandle`. The fix is a
//! LOCAL newtype [`Libp2pCatalogProbe`] wrapping the handle: implementing a foreign trait for a
//! LOCAL type is permitted. It reads the record through the handle's `pub`
//! [`daemon_core::SupplyCatalogHandle::probe_record`] and maps the stack-neutral
//! [`daemon_core::SupplyCatalogRecord`] into the libp2p `ProbedSupply`.
//!
//! `daemon_core::content_id::Blake3Digest` is the re-exported `peer_fabric::Blake3Digest`, the
//! same type `fabric_libp2p::CatalogProbe::probe` names, so the bridge type-checks with no
//! conversion.
//!
//! ## NO ENUMERATION preserved (PRD privacy invariant)
//!
//! `probe_record` is a single caller-named-digest lookup with no `list` / `iter` / `len`, and
//! this bridge adds none - a peer learns yes/no about a digest it can already name, never what
//! the node holds. The reverse-map is populated only by the availability index's verified
//! first-serve/warm-load (TASK-56/82), so a digest is probeable here ONLY after its
//! `sha256(--dump) == NarHash` verification passed (a quarantined binding never publishes).

use daemon_core::content_id::Blake3Digest;
use daemon_core::{NarProductionSource, SupplyCatalogHandle};
use fabric_libp2p::{CatalogProbe, ProbedSource, ProbedSupply};

/// Local bridge: the availability supply catalog as the libp2p provider's [`CatalogProbe`].
pub struct Libp2pCatalogProbe(SupplyCatalogHandle);

impl Libp2pCatalogProbe {
    /// Bridge `handle` (the availability index's inert read handle) onto the libp2p provider's
    /// supply seam.
    pub fn new(handle: SupplyCatalogHandle) -> Self {
        Libp2pCatalogProbe(handle)
    }
}

impl CatalogProbe for Libp2pCatalogProbe {
    fn probe(&self, content: &Blake3Digest) -> Option<ProbedSupply> {
        self.0.probe_record(content).map(|record| ProbedSupply {
            declared_size: record.declared_size,
            source: match record.source {
                NarProductionSource::Process { program, args } => {
                    ProbedSource::Process { program, args }
                }
                NarProductionSource::RegularFile(path) => ProbedSource::RegularFile(path),
                NarProductionSource::Memory(bytes) => ProbedSource::Memory(bytes),
            },
        })
    }
}
