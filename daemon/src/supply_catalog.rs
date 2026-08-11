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

/// Immutable snapshot returned by a single digest probe.
#[derive(Clone)]
pub(crate) struct SupplyCatalogRecord {
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
    pub(crate) fn probe(&self, digest: &Blake3Digest) -> Option<SupplyCatalogRecord> {
        self.state
            .lock()
            .expect("supply-catalog mutex")
            .records
            .get(digest)
            // Prefer the oldest live owner. Selection is deterministic, and
            // withdrawing it naturally reveals a same-digest sibling.
            .and_then(|owners| owners.first_key_value())
            .map(|(_, record)| record.clone())
    }
}

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
