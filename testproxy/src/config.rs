//! Startup configuration and argument parsing.
//!
//! Hardcoding is explicitly allowed for the fixture (PRD), so parsing is a
//! deliberately small hand-rolled flag reader rather than a CLI crate - another
//! third-party dependency the dependency-free fixture does not need.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;

/// Everything the proxy needs to run.
#[derive(Debug, Clone)]
pub struct Config {
    /// Address to listen on. Defaults to `127.0.0.1:8081`.
    pub listen: SocketAddr,
    /// Upstream binary cache base URL, e.g. `http://127.0.0.1:8080`.
    pub upstream: String,
    /// Directory for the on-disk cache.
    pub cache_dir: PathBuf,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            listen: SocketAddr::from((Ipv4Addr::LOCALHOST, 8081)),
            upstream: "http://127.0.0.1:8080".to_string(),
            cache_dir: PathBuf::from("testproxy-cache"),
        }
    }
}

impl Config {
    /// Parse `--listen ADDR`, `--upstream URL`, `--cache-dir PATH` from an
    /// argument iterator (without the program name). Unknown flags fail fast
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
            ]
            .map(String::from),
        )
        .unwrap();
        assert_eq!(config.listen.port(), 9000);
        assert_eq!(config.upstream, "http://example:80");
        assert_eq!(config.cache_dir, PathBuf::from("/tmp/c"));
    }

    #[test]
    fn unknown_flag_fails_fast() {
        assert!(Config::from_args(["--nope".to_string()]).is_err());
        assert!(Config::from_args(["--listen".to_string()]).is_err());
    }
}
