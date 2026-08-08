//! Path classification for the Nix binary-cache HTTP surface.
//!
//! The cache API is tiny: one `nix-cache-info`, `<hash>.narinfo` metadata, and
//! `nar/<filehash>.nar[.xz|.zst]` payloads. Every request the fixture logs and
//! every fault it injects is scoped by one of these kinds, so classification is
//! its own small, testable unit rather than scattered string matching.

/// The request kinds the fixture distinguishes. `Copy` so it threads cheaply
/// through fault scoping and log records; `Ord`/`Hash` so it keys the per-kind
/// latency map.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Kind {
    CacheInfo,
    Narinfo,
    Nar,
    Other,
}

impl Kind {
    /// Stable wire name used in the JSON log and stats, and by the fault
    /// admin endpoint. Kept in sync with `parse` below.
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::CacheInfo => "cache-info",
            Kind::Narinfo => "narinfo",
            Kind::Nar => "nar",
            Kind::Other => "other",
        }
    }

    /// Parse a kind name (as used by the fault admin endpoint's `kind=` param).
    /// `None` for an unknown name so callers can fail fast. Named `parse`, not
    /// `from_str`, to avoid shadowing the `FromStr` trait method.
    pub fn parse(name: &str) -> Option<Kind> {
        match name {
            "cache-info" => Some(Kind::CacheInfo),
            "narinfo" => Some(Kind::Narinfo),
            "nar" => Some(Kind::Nar),
            "other" => Some(Kind::Other),
            _ => None,
        }
    }
}

/// Classify a request path against the Nix binary-cache API.
///
/// Deliberately literal: the fixture fronts exactly this API and nothing else,
/// so anything unrecognised is `Other` and passed through without caching.
pub fn classify(path: &str) -> Kind {
    if path == "/nix-cache-info" {
        Kind::CacheInfo
    } else if path.ends_with(".narinfo") {
        Kind::Narinfo
    } else if path.starts_with("/nar/") {
        Kind::Nar
    } else {
        Kind::Other
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_the_three_cache_kinds() {
        assert_eq!(classify("/nix-cache-info"), Kind::CacheInfo);
        assert_eq!(
            classify("/0a0lslqb6gbqnj6xqjlaljjqg6kgb3wz.narinfo"),
            Kind::Narinfo
        );
        assert_eq!(classify("/nar/06rgb4vfjsg365xwwdjz.nar"), Kind::Nar);
        assert_eq!(classify("/nar/06rgb4vfjsg365xwwdjz.nar.xz"), Kind::Nar);
        assert_eq!(classify("/nar/06rgb4vfjsg365xwwdjz.nar.zst"), Kind::Nar);
        assert_eq!(classify("/favicon.ico"), Kind::Other);
    }

    #[test]
    fn as_str_and_from_str_round_trip() {
        for kind in [Kind::CacheInfo, Kind::Narinfo, Kind::Nar, Kind::Other] {
            assert_eq!(Kind::parse(kind.as_str()), Some(kind));
        }
        assert_eq!(Kind::parse("bogus"), None);
    }
}
