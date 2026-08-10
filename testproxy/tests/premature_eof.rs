//! AC#3 (codex re-gate #2b): the testproxy NAR cache must NEVER commit a
//! premature-EOF body (fewer bytes than the declared Content-Length) - else a
//! short NAR would be cached and served as a self-consistent "complete" 200 on
//! the next hit, poisoning the cache. Only a fully-received body is committed.

mod common;

use common::get;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use testproxy::Config;

/// A raw origin that answers EVERY request with `Content-Length: 10` but only 2
/// body bytes, then closes - a premature EOF under the declared length.
fn short_origin() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("origin binds");
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for incoming in listener.incoming() {
            let Ok(mut stream) = incoming else { continue };
            std::thread::spawn(move || {
                // Drain the request head TO ITS TERMINATOR, not "whatever one
                // read() happened to return" (task-109). One read() is not a
                // request head: it returns what has arrived so far. Responding and
                // then dropping the stream while the peer is still writing its
                // request hands that peer EPIPE, and the peer here is the code
                // under test. Measured: 3 of the 10 failing instances in the
                // task-109 baseline (45% gate failure rate at N=20) were this
                // origin breaking the proxy's pipe - the proxy then correctly
                // returned 502, which the test below misread as cache poisoning.
                //
                // Byte-at-a-time is deliberate: it is obviously correct and this is
                // a 2-line-per-request test origin, not a hot path.
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    match stream.read(&mut byte) {
                        Ok(0) | Err(_) => break, // peer gave up; nothing to answer
                        Ok(_) => head.push(byte[0]),
                    }
                }
                // Declares 10 bytes, sends 2, then closes: premature EOF.
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\nhe",
                );
                let _ = stream.flush();
            });
        }
    });
    addr
}

fn scratch_cache() -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "testproxy-premature-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn premature_eof_nar_is_not_committed_or_served_complete() {
    let origin = short_origin();
    let cache_dir = scratch_cache();
    let config = Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        upstream: format!("http://{origin}"),
        cache_dir: cache_dir.clone(),
    };
    let (proxy, _state) = testproxy::spawn(config).expect("proxy binds");

    // First request: the upstream body is short of its Content-Length. The client
    // sees an incomplete transfer (body shorter than the advertised length).
    let first = get(proxy.addr, "/nar/x.nar").unwrap();
    assert_eq!(first.content_length, Some(10));
    assert!(
        !first.complete(),
        "a premature-EOF body must reach the client as INCOMPLETE, not a clean 200"
    );

    // The core bite: the short body must NOT have been committed to the cache.
    let cached = cache_dir.join("nar/x.nar");
    assert!(
        std::fs::metadata(&cached).is_err(),
        "a premature-EOF NAR must NOT be committed to the cache ({cached:?} exists)"
    );

    // Second request: because nothing was cached, it is a MISS that refetches
    // upstream (again short) - it is NOT served as a complete cached 200.
    let second = get(proxy.addr, "/nar/x.nar").unwrap();
    // State the property MEANT, not merely "the transfer was not complete"
    // (task-109). `complete()` asks whether the body matched the advertised
    // Content-Length - and a 502 error page matches ITS OWN Content-Length, so it
    // is "complete" too. The bare `!complete()` check therefore could not tell
    // "served a poisoned cache entry" (the defect this test guards) from "the
    // upstream fetch failed" (an unrelated accident), and when the origin above
    // raced it reported the former while the latter had happened. Pinning the
    // status first makes a 502 fail AS a 502, naming the right component.
    assert_eq!(
        second.status,
        Some(200),
        "the second request must reach the origin and receive its (short) 200 - an \
         upstream error here means the ORIGIN or the fetch broke, not the cache"
    );
    assert_eq!(
        second.content_length,
        Some(10),
        "the second response must still advertise the origin's Content-Length"
    );
    assert!(
        !second.complete(),
        "the second request must not be served a complete 200 from a poisoned cache"
    );

    let _ = std::fs::remove_dir_all(&cache_dir);
    let _ = TcpStream::connect(origin); // nudge the accept loop toward exit
}
