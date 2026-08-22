//! Inert provider-facing supply records.
//!
//! The availability index is the writer; providers receive only a read handle.
//! A record contains data, never an index entry, callback, lock guard, or lazy
//! derivation capability. Registrations are scalar identities so retiring one
//! owner cannot accidentally withdraw a sibling that derives the same digest.

use std::collections::{BTreeMap, HashMap};
use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};

use crate::content_id::Blake3Digest;

/// Closed data description of how the provider can reproduce a NAR.
#[derive(Clone)]
pub enum NarProductionSource {
    Process {
        program: PathBuf,
        args: Vec<OsString>,
    },
    RegularFile(PathBuf),
    Memory(Arc<Vec<u8>>),
}

/// Immutable snapshot returned by a single digest probe. `pub` (TASK-146) so a backend
/// binary can bridge it into that backend's provider-supply seam: `daemon-core` is
/// stack-neutral and cannot name `fabric_iroh::CatalogProbe`, so the iroh binary wraps a
/// [`SupplyCatalogHandle`] in a newtype and maps this record into `fabric_iroh::ProbedSupply`
/// (the orphan rule forbids implementing that foreign trait for this type in a third crate).
#[derive(Clone)]
pub struct SupplyCatalogRecord {
    pub declared_size: u64,
    pub source: NarProductionSource,
    pub store_path: PathBuf,
}

#[derive(Default)]
struct CatalogState {
    next_registration: u64,
    owners: HashMap<u64, Option<Blake3Digest>>,
    records: HashMap<Blake3Digest, BTreeMap<u64, SupplyCatalogRecord>>,
}

/// Non-owning provider view. Its only operation is a caller-named digest probe;
/// there is deliberately no listing or mutation API.
#[derive(Clone, Default)]
pub struct SupplyCatalogHandle {
    state: Arc<Mutex<CatalogState>>,
}

impl SupplyCatalogHandle {
    /// The inherent digest probe over the raw catalog record. `pub` (TASK-146) so a backend
    /// binary's provider-supply bridge (e.g. the iroh `CatalogProbe` newtype) can read the
    /// record without `daemon-core` naming any backend type. Named `probe_record`, NOT
    /// `probe`, on purpose: a backend's `CatalogProbe::probe` calls this one, and sharing the
    /// name across the inherent/trait boundary would risk an accidental self-recursion rebind.
    pub fn probe_record(&self, digest: &Blake3Digest) -> Option<SupplyCatalogRecord> {
        let record = {
            self.state
                .lock()
                .expect("supply-catalog mutex")
                .records
                .get(digest)
                // Prefer the oldest live owner. Selection is deterministic, and
                // withdrawing it naturally reveals a same-digest sibling.
                .and_then(|owners| owners.first_key_value())
                .map(|(_, record)| record.clone())
        }?;
        // TASK-297 HIGH-B: a store path Nix GC'd since publication is no longer servable, so a
        // direct provider probe (the libp2p `/nar` admit path, which does NOT go through the
        // responder's `hold_budgeted` materialisation check) must DECLINE it here - BEFORE admission
        // charges the amplification budget - restoring "probeable => the node has it => real work".
        // This mirrors the availability responder's own `store_path.exists()` gate
        // (`hold_budgeted`, availability.rs); the syscall runs after the mutex is released so a stat
        // never blocks the catalog. A read handle cannot retire the stale record (only the
        // availability writer can); the deterministic retirement is the reconcile path (TASK-297
        // HIGH-B second half). A GC in the probe->spawn gap is a bounded, non-peer-timed TOCTOU that
        // the serve path already tolerates (it re-dumps + BLAKE3-verifies before emitting a byte).
        if !record.store_path.exists() {
            return None;
        }
        Some(record)
    }
}

// The provider-facing `CatalogProbe` seam (TASK-150 AC#3) is a BACKEND type
// (`fabric_iroh::transport_iroh::CatalogProbe`). `daemon-core` is stack-neutral and does
// NOT depend on any backend, so it cannot implement that trait here (and the orphan rule
// would forbid a third crate doing it for this type). TASK-146 relocated the bridge into
// the iroh binary: a newtype `IrohCatalogProbe(SupplyCatalogHandle)` there implements
// `CatalogProbe` by calling [`SupplyCatalogHandle::probe_record`] (now `pub`) and mapping
// the returned [`SupplyCatalogRecord`] into `fabric_iroh::ProbedSupply`. The daemon still
// fills the provider's supply seam with the availability index's inert read handle; only
// the impl site moved below the backend boundary.

/// Availability-side writer. This type is crate-private so transport code
/// cannot activate or retire provider records.
#[derive(Default)]
pub(crate) struct SupplyCatalog {
    handle: SupplyCatalogHandle,
}

impl SupplyCatalog {
    pub(crate) fn read_handle(&self) -> SupplyCatalogHandle {
        self.handle.clone()
    }

    pub(crate) fn register(&self) -> SupplyRegistration {
        let mut state = self.handle.state.lock().expect("supply-catalog mutex");
        state.next_registration = state
            .next_registration
            .checked_add(1)
            .expect("supply-catalog registration id exhausted");
        let id = state.next_registration;
        state.owners.insert(id, None);
        SupplyRegistration {
            id,
            owner: Arc::downgrade(&self.handle.state),
            retired: AtomicBool::new(false),
        }
    }

    /// Publish a derived record only while its registration remains active.
    /// Callers perform this under the availability entries lock after a
    /// pointer-identity check; replacement and retirement use the same
    /// entries-then-catalog order.
    pub(crate) fn publish(
        &self,
        registration: &SupplyRegistration,
        digest: Blake3Digest,
        record: SupplyCatalogRecord,
    ) -> bool {
        if !registration.belongs_to(&self.handle.state) {
            return false;
        }
        if registration.retired.load(Ordering::Acquire) {
            return false;
        }
        let mut state = self.handle.state.lock().expect("supply-catalog mutex");
        let Some(previous_digest) = state.owners.get(&registration.id).copied() else {
            return false;
        };
        if registration.retired.load(Ordering::Acquire) {
            return false;
        }
        if let Some(previous_digest) = previous_digest
            && previous_digest != digest
        {
            remove_record(&mut state, previous_digest, registration.id);
        }
        state.owners.insert(registration.id, Some(digest));
        state
            .records
            .entry(digest)
            .or_default()
            .insert(registration.id, record);
        true
    }

    /// Explicit and idempotent withdrawal. A token is intentionally non-Clone:
    /// one availability entry owns one registration identity.
    pub(crate) fn retire(&self, registration: &SupplyRegistration) {
        registration.retired.store(true, Ordering::Release);
        if !registration.belongs_to(&self.handle.state) {
            return;
        }
        let mut state = self.handle.state.lock().expect("supply-catalog mutex");
        // Always inspect/remove under the mutex, including repeated calls. Thus
        // every return from this idempotent operation proves the record absent,
        // even when another retirement was concurrently in flight.
        if let Some(Some(digest)) = state.owners.remove(&registration.id) {
            remove_record(&mut state, digest, registration.id);
        }
    }
}

fn remove_record(state: &mut CatalogState, digest: Blake3Digest, registration: u64) {
    let remove_digest = if let Some(owners) = state.records.get_mut(&digest) {
        owners.remove(&registration);
        owners.is_empty()
    } else {
        false
    };
    if remove_digest {
        state.records.remove(&digest);
    }
}

pub(crate) struct SupplyRegistration {
    id: u64,
    owner: Weak<Mutex<CatalogState>>,
    retired: AtomicBool,
}

impl SupplyRegistration {
    fn belongs_to(&self, state: &Arc<Mutex<CatalogState>>) -> bool {
        self.owner
            .upgrade()
            .is_some_and(|owner| Arc::ptr_eq(&owner, state))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content_id::BLAKE3_DIGEST_LEN;

    /// A record whose `store_path` EXISTS, so the TASK-297 HIGH-B materialisation gate in
    /// [`SupplyCatalogHandle::probe_record`] admits it and these tests exercise the OWNERSHIP
    /// invariant rather than the existence gate. `temp_dir()` is a directory guaranteed to exist on
    /// the test host; the ownership tests never dump, so the path only needs to satisfy `exists()`.
    fn record(size: u64) -> SupplyCatalogRecord {
        record_at(size, std::env::temp_dir())
    }

    fn record_at(size: u64, store_path: impl Into<PathBuf>) -> SupplyCatalogRecord {
        SupplyCatalogRecord {
            declared_size: size,
            source: NarProductionSource::Memory(Arc::new(vec![0u8; size as usize])),
            store_path: store_path.into(),
        }
    }

    /// A store path that does NOT exist on the host: a stand-in for a binding whose `/nix/store`
    /// path was GC'd after the catalog published it. The random suffix keeps it absent.
    fn missing_store_path() -> PathBuf {
        std::env::temp_dir().join(format!(
            "nix-p2p-supply-catalog-gcd-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    /// TASK-297 HIGH-B: a probe of a digest whose store path has been GC'd MUST decline (return
    /// `None`) BEFORE the libp2p admit path can charge the amplification budget, even though the
    /// registration is still live. Mutation proof: delete the `!record.store_path.exists()` guard in
    /// `probe_record` and this asserts `Some` instead - RED.
    #[test]
    fn a_gc_removed_store_path_is_declined_at_probe() {
        let catalog = SupplyCatalog::default();
        let digest = Blake3Digest::from_bytes([0x7c; BLAKE3_DIGEST_LEN]);

        let reg = catalog.register();
        // Publish while the path exists: the registration/record is genuinely live.
        let live = record_at(10, std::env::temp_dir());
        assert!(catalog.publish(&reg, digest, live));
        assert!(
            catalog.read_handle().probe_record(&digest).is_some(),
            "a live registration whose store path exists is servable"
        );

        // Now the SAME live registration points at a GC'd (absent) path: the probe must decline.
        let gone = record_at(10, missing_store_path());
        assert!(catalog.publish(&reg, digest, gone));
        assert!(
            catalog.read_handle().probe_record(&digest).is_none(),
            "a GC'd store path must be declined at probe, before any amplification charge"
        );
    }

    /// The scalar-owner invariant from the module docs, tested at its OWN layer:
    /// two DIFFERENT registrations that publish the SAME digest each own an
    /// independent record, so retiring one MUST NOT withdraw the sibling.
    ///
    /// This lives here rather than at the availability level because, once the
    /// availability index verifies `sha256(--dump) == key` (task-56), two DISTINCT
    /// NarHashKeys can no longer map to identical NAR bytes (hence identical
    /// BLAKE3): key equality and digest equality now coincide. The catalog itself,
    /// keyed by BLAKE3, still must uphold this refcount-like behaviour, so the
    /// invariant is exercised directly here where two same-digest owners ARE
    /// constructible.
    #[test]
    fn retiring_one_same_digest_owner_preserves_its_sibling() {
        let catalog = SupplyCatalog::default();
        let digest = Blake3Digest::from_bytes([0x5a; BLAKE3_DIGEST_LEN]);

        let first = catalog.register();
        let second = catalog.register();
        assert!(catalog.publish(&first, digest, record(10)));
        assert!(catalog.publish(&second, digest, record(20)));

        // Both owners are live: the digest is servable.
        assert!(catalog.read_handle().probe_record(&digest).is_some());

        // Retire one (idempotently); the sibling keeps the digest servable.
        catalog.retire(&second);
        catalog.retire(&second);
        assert!(
            catalog.read_handle().probe_record(&digest).is_some(),
            "a same-digest sibling must survive its peer's retirement"
        );

        // Retire the last owner: only now does the digest disappear.
        catalog.retire(&first);
        assert!(
            catalog.read_handle().probe_record(&digest).is_none(),
            "the digest disappears only after its FINAL owner retires"
        );
    }

    /// A retired registration cannot publish (no zombie records), and belongs-to
    /// is enforced so a token from another catalog is inert.
    #[test]
    fn a_retired_registration_cannot_publish() {
        let catalog = SupplyCatalog::default();
        let digest = Blake3Digest::from_bytes([0x11; BLAKE3_DIGEST_LEN]);
        let reg = catalog.register();
        catalog.retire(&reg);
        assert!(
            !catalog.publish(&reg, digest, record(1)),
            "a retired registration must not resurrect a record"
        );
        assert!(catalog.read_handle().probe_record(&digest).is_none());
    }
}
