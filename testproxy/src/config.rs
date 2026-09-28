//! Startup configuration and argument parsing.
//!
//! Hardcoding is explicitly allowed for the fixture (PRD), so parsing is a
//! deliberately small hand-rolled flag reader rather than a CLI crate - another
//! third-party dependency the dependency-free fixture does not need.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

/// Everything the proxy needs to run.
#[derive(Debug, Clone)]
pub struct Config {
    /// Address to listen on. Defaults to `127.0.0.1:8081`.
    pub listen: SocketAddr,
    /// Upstream binary cache base URL, e.g. `http://127.0.0.1:8080`.
    pub upstream: String,
    /// Directory for the on-disk cache.
    pub cache_dir: PathBuf,
    /// Maximum idle interval of a blocked downstream write, not total transfer time.
    pub downstream_write_idle: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            listen: SocketAddr::from((Ipv4Addr::LOCALHOST, 8081)),
            upstream: "http://127.0.0.1:8080".to_string(),
            cache_dir: PathBuf::from("testproxy-cache"),
            downstream_write_idle: Duration::from_secs(60),
        }
    }
}

impl Config {
    /// Parse fixture flags from an argument iterator (without the program name).
    /// Unknown flags fail fast
    /// with a message rather than being silently ignored.
    pub fn from_args<I: IntoIterator<Item = String>>(args: I) -> Result<Config, String> {
        let mut config = Config::default();
        let mut args = args.into_iter();
        while let Some(flag) = args.next() {
            let mut value = || {
                args.next()
                    .ok_or_else(|| format!("flag {flag} needs a value"))
            };
            match flag.as_str() {
                "--listen" => {
                    let raw = value()?;
                    config.listen = raw
                        .parse()
                        .map_err(|e| format!("bad --listen {raw:?}: {e}"))?;
                }
                "--upstream" => config.upstream = value()?,
                "--cache-dir" => config.cache_dir = PathBuf::from(value()?),
                "--downstream-write-idle-ms" => {
                    let milliseconds = value()?
                        .parse::<u64>()
                        .map_err(|_| "--downstream-write-idle-ms requires a positive integer")?;
                    if milliseconds == 0 {
                        return Err("--downstream-write-idle-ms must be nonzero".into());
                    }
                    config.downstream_write_idle = Duration::from_millis(milliseconds);
                }
                other => return Err(format!("unknown flag {other:?}")),
            }
        }
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_all_flags() {
        let config = Config::from_args(
            [
                "--listen",
                "127.0.0.1:9000",
                "--upstream",
                "http://example:80",
                "--cache-dir",
                "/tmp/c",
                "--downstream-write-idle-ms",
                "2000",
            ]
            .map(String::from),
        )
        .unwrap();
        assert_eq!(config.listen.port(), 9000);
        assert_eq!(config.upstream, "http://example:80");
        assert_eq!(config.cache_dir, PathBuf::from("/tmp/c"));
        assert_eq!(config.downstream_write_idle, Duration::from_secs(2));
    }

    #[test]
    fn unknown_flag_fails_fast() {
        assert!(Config::from_args(["--nope".to_string()]).is_err());
        assert!(Config::from_args(["--listen".to_string()]).is_err());
    }

    #[test]
    fn invalid_write_idle_bound_fails_fast() {
        for value in ["0", "-1", "unbounded"] {
            assert!(
                Config::from_args(["--downstream-write-idle-ms", value].map(String::from)).is_err()
            );
        }
        let error = crate::State::new(Config {
            downstream_write_idle: Duration::ZERO,
            ..Config::default()
        })
        .err()
        .expect("programmatic zero also fails before opening the cache");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    }
}
