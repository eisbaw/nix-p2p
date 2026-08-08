//! The request log - the ground-truth oracle for every e2e scenario.
//!
//! Every served request appends one [`Record`]. Counters (received, upstream
//! hits, cache hits, bytes, faults) are **derived from the log on demand**, not
//! maintained alongside it: the log is the single source of truth, so the stats
//! endpoint and the counts a scenario asserts can never disagree (MPED: compute
//! derived views, do not duplicate state).
//!
//! What the oracle answers, per its TESTING.md definitions:
//!   * request-count oracle: `received` vs `upstream` per kind. The
//!     oracle-pairing rule (a "0 upstream" claim needs a nonzero received
//!     count) is expressible directly because both are in [`Stats`].
//!   * egress oracle: `bytes_sent` summed.
//!   * gap oracle: each NAR record carries `gap_ms` - the wall time from the
//!     narinfo request that pointed at it to this NAR request.

use crate::json;
use crate::kind::Kind;
use std::collections::BTreeMap;

/// One served request.
#[derive(Debug, Clone)]
pub struct Record {
    pub seq: u64,
    pub kind: Kind,
    pub path: String,
    pub method: String,
    /// HTTP status sent, or 0 if the connection was reset with no response.
    pub status: u16,
    /// Body bytes actually written to the client.
    pub bytes_sent: u64,
    /// True if this request caused an upstream fetch (a cache miss).
    pub upstream: bool,
    /// The fault emitted on this request, if any (its name).
    pub fault: Option<String>,
    /// Unix time the request started, milliseconds.
    pub start_unix_ms: u128,
    /// Wall time to serve, milliseconds.
    pub duration_ms: f64,
    /// For NAR requests: ms since the narinfo that referenced this NAR was
    /// served. `None` if no such narinfo was seen (or not a NAR).
    pub gap_ms: Option<f64>,
}

impl Record {
    fn to_json(&self) -> String {
        json::Object::new()
            .raw("seq", self.seq)
            .str("kind", self.kind.as_str())
            .str("path", &self.path)
            .str("method", &self.method)
            .raw("status", self.status)
            .raw("bytes_sent", self.bytes_sent)
            .raw("upstream", self.upstream)
            .raw("fault", json::opt_str(self.fault.as_deref()))
            .raw("start_unix_ms", self.start_unix_ms)
            .raw("duration_ms", format!("{:.3}", self.duration_ms))
            .raw("gap_ms", json::opt_f64(self.gap_ms))
            .finish()
    }
}

/// The append-only request log.
#[derive(Default)]
pub struct Log {
    records: Vec<Record>,
    next_seq: u64,
}

impl Log {
    /// Reserve the next sequence number (assigned when a request starts so log
    /// order matches arrival order even under concurrency).
    pub fn next_seq(&mut self) -> u64 {
        let seq = self.next_seq;
        self.next_seq += 1;
        seq
    }

    pub fn push(&mut self, record: Record) {
        self.records.push(record);
    }

    /// Clear the log (per-scenario reset). Sequence numbering continues so a
    /// stale reference to an old seq is never silently reused.
    pub fn clear(&mut self) {
        self.records.clear();
    }

    pub fn records(&self) -> &[Record] {
        &self.records
    }

    /// Serialise the whole log as a JSON array of records.
    pub fn to_json(&self) -> String {
        json::array(self.records.iter().map(Record::to_json))
    }

    /// Derive counters from the log. This is the only place counts come from.
    pub fn stats(&self) -> Stats {
        let mut stats = Stats::default();
        for record in &self.records {
            *stats.received.entry(record.kind).or_insert(0) += 1;
            if record.upstream {
                *stats.upstream.entry(record.kind).or_insert(0) += 1;
            } else if record.status == 200 {
                *stats.cache_hits.entry(record.kind).or_insert(0) += 1;
            }
            stats.bytes_sent += record.bytes_sent;
            if let Some(fault) = &record.fault {
                *stats.faults.entry(fault.clone()).or_insert(0) += 1;
            }
        }
        stats
    }
}

/// Counters derived from the log. `received`/`upstream` are what the request-
/// count oracle and its pairing rule read.
#[derive(Debug, Default)]
pub struct Stats {
    pub received: BTreeMap<Kind, u64>,
    pub upstream: BTreeMap<Kind, u64>,
    pub cache_hits: BTreeMap<Kind, u64>,
    pub bytes_sent: u64,
    pub faults: BTreeMap<String, u64>,
}

impl Stats {
    pub fn received_total(&self) -> u64 {
        self.received.values().sum()
    }

    pub fn upstream_total(&self) -> u64 {
        self.upstream.values().sum()
    }

    pub fn received_of(&self, kind: Kind) -> u64 {
        self.received.get(&kind).copied().unwrap_or(0)
    }

    pub fn upstream_of(&self, kind: Kind) -> u64 {
        self.upstream.get(&kind).copied().unwrap_or(0)
    }

    pub fn to_json(&self) -> String {
        let by_kind = |map: &BTreeMap<Kind, u64>| {
            let mut obj = json::Object::new();
            for (kind, count) in map {
                obj = obj.raw(kind.as_str(), *count);
            }
            obj.finish()
        };
        let faults = {
            let mut obj = json::Object::new();
            for (name, count) in &self.faults {
                obj = obj.raw(name, *count);
            }
            obj.finish()
        };
        json::Object::new()
            .raw("received", by_kind(&self.received))
            .raw("upstream", by_kind(&self.upstream))
            .raw("cache_hits", by_kind(&self.cache_hits))
            .raw("received_total", self.received_total())
            .raw("upstream_total", self.upstream_total())
            .raw("bytes_sent", self.bytes_sent)
            .raw("faults", faults)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(kind: Kind, upstream: bool, status: u16, bytes: u64) -> Record {
        Record {
            seq: 0,
            kind,
            path: "/x".into(),
            method: "GET".into(),
            status,
            bytes_sent: bytes,
            upstream,
            fault: None,
            start_unix_ms: 0,
            duration_ms: 0.0,
            gap_ms: None,
        }
    }

    #[test]
    fn stats_derive_received_and_upstream_separately() {
        let mut log = Log::default();
        log.push(rec(Kind::Nar, true, 200, 100)); // miss
        log.push(rec(Kind::Nar, false, 200, 100)); // hit
        let stats = log.stats();
        // The oracle-pairing shape: received nonzero, upstream can be read apart.
        assert_eq!(stats.received_of(Kind::Nar), 2);
        assert_eq!(stats.upstream_of(Kind::Nar), 1);
        assert_eq!(stats.cache_hits.get(&Kind::Nar), Some(&1));
        assert_eq!(stats.bytes_sent, 200);
    }

    #[test]
    fn faults_are_counted_by_name() {
        let mut log = Log::default();
        let mut r = rec(Kind::Nar, false, 0, 0);
        r.fault = Some("connection-reset".into());
        log.push(r);
        assert_eq!(log.stats().faults.get("connection-reset"), Some(&1));
    }
}
