//! The iroh provider's `CatalogProbe` over the daemon-core availability supply catalog.
//!
//! The iroh provider's supply seam is [`fabric_iroh::transport_iroh::CatalogProbe`]
//! (returning [`fabric_iroh::transport_iroh::ProbedSupply`]). The daemon fills it from the
//! availability index's inert read handle [`daemon_core::SupplyCatalogHandle`].
//!
//! ## Why a NEWTYPE (TASK-146)
//!
//! `daemon-core` is stack-neutral and does NOT depend on `fabric-iroh`, so it cannot
//! implement `CatalogProbe` for `SupplyCatalogHandle` there. The orphan rule also forbids
//! this binary crate implementing that foreign trait for the foreign `SupplyCatalogHandle`.
//! The fix is a LOCAL newtype [`IrohCatalogProbe`] wrapping the handle: implementing a
//! foreign trait for a LOCAL type is permitted. It reads the record through the handle's
//! `pub` [`SupplyCatalogHandle::probe_record`] and maps the stack-neutral
//! [`daemon_core::SupplyCatalogRecord`] into the iroh `ProbedSupply`.

use daemon_core::content_id::Blake3Digest;
use daemon_core::{NarProductionSource, SupplyCatalogHandle};
use fabric_iroh::transport_iroh::{CatalogProbe, ProbedSource, ProbedSupply};

/// Local bridge: the availability supply catalog as the iroh provider's [`CatalogProbe`].
pub struct IrohCatalogProbe(SupplyCatalogHandle);

impl IrohCatalogProbe {
    /// Bridge `handle` (the availability index's inert read handle) onto the iroh provider's
    /// supply seam.
    pub fn new(handle: SupplyCatalogHandle) -> Self {
        IrohCatalogProbe(handle)
    }
}

impl CatalogProbe for IrohCatalogProbe {
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
