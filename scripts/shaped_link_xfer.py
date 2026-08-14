#!/usr/bin/env python3
"""Bulk-TCP sender/receiver for the shaped-link measurement primitive.

Used ONLY by `scripts/shaped_link.py` (test/measurement surface, never linked
into the product daemon). Kept tiny and dependency-free so it can run inside a
bare network namespace via `nsenter`.

The transfer is timed by the SENDER, end-to-end: the sender waits for a 1-byte
ack the receiver sends only after it has drained all N bytes, so the reported
wall time is genuine delivery time across the link, not the time to fill a local
socket buffer. That is what makes the rate an observation OUTSIDE the shaper
(an endpoint clock over delivered bytes) rather than netem's own accounting.
"""

import socket
import sys
import time

CHUNK = 64 * 1024


def recv(port: int, expect: int, ready_file: str | None = None) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(1)
    # Touch a readiness file, if asked, so the orchestrator can wait for the
    # listener without a probe-connect that would consume the single accept().
    if ready_file:
        with open(ready_file, "w") as fh:
            fh.write("ready\n")
    print(f"RECV_READY port={port}", flush=True)
    conn, _ = srv.accept()
    got = 0
    while got < expect:
        b = conn.recv(CHUNK)
        if not b:
            break  # early EOF: sender closed before delivering `expect` bytes
        got += len(b)
    # Ack SUCCESS only when every expected byte arrived. A truncated transfer
    # (early EOF, got < expect) must NOT read as a completed measurement: send a
    # distinct failure byte so the sender's `ack != b"D"` check fails loudly.
    complete = got == expect
    try:
        conn.sendall(b"D" if complete else b"E")
    except OSError:
        pass  # peer already gone; the missing/failed ack is itself the signal
    conn.close()
    srv.close()
    # Machine-parseable contract line consumed by shaped_link.py: it carries BOTH
    # the delivered count and the expectation so the driver can verify got==expect.
    print(
        f"RECV_DONE bytes={got} expect={expect} status={'ok' if complete else 'short'}",
        flush=True,
    )


def send(host: str, port: int, total: int) -> None:
    payload = b"\xa5" * CHUNK
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    t0 = time.monotonic()
    sent = 0
    while sent < total:
        n = min(CHUNK, total - sent)
        s.sendall(payload[:n])
        sent += n
    s.shutdown(socket.SHUT_WR)
    ack = s.recv(1)  # block until the receiver has drained every byte
    t1 = time.monotonic()
    s.close()
    if ack != b"D":
        print("SEND_FAIL no-ack", flush=True)
        sys.exit(1)
    elapsed = t1 - t0
    mbit = (sent * 8) / elapsed / 1e6
    mbps = sent / elapsed / 1e6
    # Machine-parseable contract line consumed by shaped_link.py.
    print(
        f"SEND_DONE bytes={sent} elapsed_s={elapsed:.4f} "
        f"mbit_per_s={mbit:.2f} MB_per_s={mbps:.2f}",
        flush=True,
    )


if __name__ == "__main__":
    mode = sys.argv[1]
    if mode == "recv":
        ready = sys.argv[4] if len(sys.argv) > 4 else None
        recv(int(sys.argv[2]), int(sys.argv[3]), ready)
    elif mode == "send":
        send(sys.argv[2], int(sys.argv[3]), int(sys.argv[4]))
    else:
        sys.stderr.write(f"unknown mode {mode!r}\n")
        sys.exit(2)
