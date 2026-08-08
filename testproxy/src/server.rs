//! A minimal thread-per-connection HTTP server loop, generic over a handler.
//!
//! Both the proxy and the test origin (a plain static file server) are just
//! handlers over this loop, which keeps the accept/parse/dispatch plumbing in
//! one place. Thread-per-connection is the simplest model that still lets a
//! handler block on a slow upstream or a latency fault without starving others,
//! and a fixture never needs more.

use crate::http::{self, Request};
use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};

/// A running server. Holds its bound address so callers (tests, `main`) can
/// connect, and a stop flag so it can be shut down cleanly.
pub struct Server {
    pub addr: SocketAddr,
    stop: Arc<AtomicBool>,
    accept: Option<JoinHandle<()>>,
}

impl Server {
    /// Block until the server stops (used by `main`, which runs forever).
    pub fn wait(mut self) {
        if let Some(handle) = self.accept.take() {
            let _ = handle.join();
        }
    }

    /// Stop accepting and join the accept thread. Wakes the blocked `accept`
    /// by dialling the listener once after setting the flag.
    pub fn shutdown(mut self) {
        self.signal_stop();
        if let Some(handle) = self.accept.take() {
            let _ = handle.join();
        }
    }

    fn signal_stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
        // Unblock the accept() that is parked waiting for a connection.
        let _ = TcpStream::connect(self.addr);
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        if self.accept.is_some() {
            self.signal_stop();
            if let Some(handle) = self.accept.take() {
                let _ = handle.join();
            }
        }
    }
}

/// Bind `addr` and serve requests with `handler`, one thread per connection.
///
/// The handler receives the parsed [`Request`] and the raw [`TcpStream`] so it
/// can stream a body or - for the reset/truncate faults - abandon the socket
/// deliberately. Binding `port 0` yields an OS-assigned port, read back from
/// [`Server::addr`]; that is how the tests avoid port collisions.
pub fn spawn<H>(addr: SocketAddr, handler: H) -> io::Result<Server>
where
    H: Fn(Request, TcpStream) + Send + Sync + 'static,
{
    let listener = TcpListener::bind(addr)?;
    let addr = listener.local_addr()?;
    let stop = Arc::new(AtomicBool::new(false));
    let handler = Arc::new(handler);

    let stop_for_loop = Arc::clone(&stop);
    let accept = thread::spawn(move || {
        for incoming in listener.incoming() {
            if stop_for_loop.load(Ordering::SeqCst) {
                break;
            }
            match incoming {
                Ok(stream) => {
                    let handler = Arc::clone(&handler);
                    // Detached: the connection outlives the accept iteration and
                    // is bounded by the request it serves. A fixture does not
                    // need graceful in-flight drain on shutdown.
                    thread::spawn(move || serve_connection(stream, &*handler));
                }
                Err(_) => continue,
            }
        }
    });

    Ok(Server {
        addr,
        stop,
        accept: Some(accept),
    })
}

fn serve_connection<H>(mut stream: TcpStream, handler: &H)
where
    H: Fn(Request, TcpStream),
{
    match http::parse_request(&mut stream) {
        Ok(Some(request)) => handler(request, stream),
        // Cleanly closed / empty connection (e.g. the shutdown dial): ignore.
        Ok(None) => {}
        Err(_) => {
            let _ = http::write_response(&mut stream, 400, "text/plain", b"bad request\n");
        }
    }
}
