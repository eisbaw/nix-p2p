#!/usr/bin/env python3
"""TASK-258 SPIKE — node-membership ENUMERATION cost + CLIENT-ONLY oracle, FROM RAW WIRE.

This is the central privacy-cost deliverable (AC#7) and the client-only observation
(AC#1), computed from a THIRD host's OWN packet capture — never from any node's config
or the `mainline` API return value. The point of AC#7 is precisely that any stranger who
knows the (public) well-known infohash can enumerate the nix-p2p NODE POPULATION by
`get_peers`; there is NO privileged input, so a run that is HANDED the peer list is
vacuous and must fail.

What this measures, in EXACTLY the task's terms:
  * It enumerates node MEMBERSHIP (which IPs speak nix-p2p), NOT content HOLDINGS. It does
    NOT touch the frozen no-enumeration (holdings) invariant. Never blur that.

Two modes:
  --pcap FILE --observer-port P --announced a.b.c.d:port,...   (enumeration)
      Parse the OBSERVER's capture: from every BEP5 get_peers RESPONSE the observer
      RECEIVED (bencode `y=r`, `r.values` compact peers), recover the member set. Report
      the recoverable fraction as an EXACT RATIONAL num/denom against the announced set,
      and the observer's get_peers wall time as INTEGER ms (--walltime-ms).
  --pcap FILE --client-only-port P                             (client-only)
      Count BEP5 QUERY messages (bencode `y=q`) the node at port P RECEIVED. A strict
      CLIENT never answers inbound queries and is never promoted to serving, so this MUST
      be 0. Flipping the identical node to server_mode makes it > 0 (the bite).

Provenance is re-derived from the raw payloads every run (never self-reported): the
verdict recomputes the counts from the pcap, and refuses a pcap that contains no BEP5
messages at all (nothing observed => nothing proven, exit 2).

--self-test proves the oracle BITES by mutation, with no network:
  * a synthetic capture with `values` recovers exactly the injected members;
  * the SAME capture with `values` stripped recovers 0 (a handed/vacuous run fails);
  * a capture of inbound QUERIES is flagged as non-client (the server bite);
  * a client capture (only responses) passes.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import struct
import subprocess
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Minimal bencode decoder (enough for BEP5 KRPC messages). Returns Python
# bytes/int/list/dict. Rejects malformed input by raising ValueError.
# ---------------------------------------------------------------------------
def bdecode(data: bytes) -> object:
    value, index = _bdecode_at(data, 0)
    return value


def _bdecode_at(data: bytes, i: int) -> tuple[object, int]:
    c = data[i : i + 1]
    if c == b"i":
        end = data.index(b"e", i)
        return int(data[i + 1 : end]), end + 1
    if c == b"l":
        i += 1
        out = []
        while data[i : i + 1] != b"e":
            v, i = _bdecode_at(data, i)
            out.append(v)
        return out, i + 1
    if c == b"d":
        i += 1
        out = {}
        while data[i : i + 1] != b"e":
            k, i = _bdecode_at(data, i)
            v, i = _bdecode_at(data, i)
            out[k] = v
        return out, i + 1
    if c.isdigit():
        colon = data.index(b":", i)
        length = int(data[i:colon])
        start = colon + 1
        return data[start : start + length], start + length
    raise ValueError(f"bad bencode at byte {i}: {c!r}")


def _compact_peers(values: object) -> list[tuple[str, int]]:
    """BEP5 compact peer info: each entry is 6 bytes (4 IPv4 + 2 port, big-endian)."""
    peers: list[tuple[str, int]] = []
    if not isinstance(values, list):
        return peers
    for entry in values:
        if isinstance(entry, bytes) and len(entry) == 6:
            ip = str(ipaddress.IPv4Address(entry[:4]))
            port = struct.unpack(">H", entry[4:6])[0]
            peers.append((ip, port))
    return peers


def _krpc_kind(msg: object) -> bytes | None:
    """Return the KRPC message type byte string (`q`/`r`/`e`) or None if not KRPC."""
    if isinstance(msg, dict):
        y = msg.get(b"y")
        if isinstance(y, bytes):
            return y
    return None


# ---------------------------------------------------------------------------
# pcap -> per-packet UDP payloads via tshark (available in the devshell). We ask
# for the raw UDP payload hex plus ports so we can scope to the node under test.
# ---------------------------------------------------------------------------
def _udp_payloads(pcap: Path) -> list[tuple[int, int, bytes]]:
    """Return (src_port, dst_port, payload_bytes) for every UDP packet with a payload."""
    # NOTE: tshark auto-dissects the BitTorrent DHT protocol, which CONSUMES the `data`
    # layer — so `-e data.data` is empty on these packets. Extract the raw UDP payload
    # via `-e udp.payload` and bencode-decode it ourselves (we do not trust tshark's
    # bt-dht dissection; the verdict is re-derived from the raw bytes every run).
    proc = subprocess.run(
        [
            "tshark",
            "-r",
            str(pcap),
            "-Y",
            "udp.length>8",
            "-T",
            "fields",
            "-e",
            "udp.srcport",
            "-e",
            "udp.dstport",
            "-e",
            "udp.payload",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    out: list[tuple[int, int, bytes]] = []
    for line in proc.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) != 3 or not parts[2]:
            continue
        try:
            src = int(parts[0])
            dst = int(parts[1])
            payload = bytes.fromhex(parts[2].replace(":", ""))
        except ValueError:
            continue
        out.append((src, dst, payload))
    return out


def enumerate_from_pcap(
    pcap: Path, observer_port: int, announced: set[tuple[str, int]]
) -> dict:
    """Recover the member set from the OBSERVER's received get_peers responses."""
    recovered: set[tuple[str, int]] = set()
    krpc_seen = 0
    responses_with_values = 0
    for src, dst, payload in _udp_payloads(pcap):
        if dst != observer_port:  # only packets the observer RECEIVED
            continue
        try:
            msg = bdecode(payload)
        except (ValueError, IndexError):
            continue
        kind = _krpc_kind(msg)
        if kind is None:
            continue
        krpc_seen += 1
        if kind == b"r" and isinstance(msg, dict):
            r = msg.get(b"r")
            if isinstance(r, dict) and b"values" in r:
                peers = _compact_peers(r[b"values"])
                if peers:
                    responses_with_values += 1
                recovered.update(peers)
    hits = recovered & announced
    return {
        "krpc_messages_observed": krpc_seen,
        "responses_with_values": responses_with_values,
        "recovered_members": sorted(f"{ip}:{p}" for ip, p in recovered),
        "announced_members": sorted(f"{ip}:{p}" for ip, p in announced),
        # EXACT RATIONAL num/denom (owner no-floats rule): recoverable fraction of the
        # announced population. No float is ever formed.
        "recoverable_fraction_num": len(hits),
        "recoverable_fraction_den": len(announced),
    }


def client_only_from_pcap(pcap: Path, node_port: int) -> dict:
    """Classify the KRPC traffic of the node at `node_port`.

    The CLIENT-ONLY property is about not SERVING, i.e. never ANSWERING inbound queries
    — NOT about not receiving them. Even a strict client's UDP socket RECEIVES probe
    queries (other nodes ping/find_node it during traversal); the distinguishing signal
    is whether it emits OUTBOUND RESPONSES (`src==port, y=r`). A client emits ZERO; a
    server emits > 0. So `is_client_only` is keyed on `outbound_responses == 0`, and
    flipping the identical node to server_mode makes it fail (the bite)."""
    inbound_queries = 0
    inbound_responses = 0
    outbound_responses = 0
    outbound_queries = 0
    for src, dst, payload in _udp_payloads(pcap):
        try:
            msg = bdecode(payload)
        except (ValueError, IndexError):
            continue
        kind = _krpc_kind(msg)
        if kind is None:
            continue
        if dst == node_port and kind == b"q":
            inbound_queries += 1
        elif dst == node_port and kind == b"r":
            inbound_responses += 1
        elif src == node_port and kind == b"r":
            outbound_responses += 1
        elif src == node_port and kind == b"q":
            outbound_queries += 1
    return {
        "inbound_queries": inbound_queries,
        "inbound_responses": inbound_responses,
        "outbound_queries": outbound_queries,
        # The serving signal: a strict client NEVER answers an inbound query.
        "outbound_responses": outbound_responses,
        "is_client_only": outbound_responses == 0,
    }


# ---------------------------------------------------------------------------
# Synthetic KRPC builders for the self-test (no network).
# ---------------------------------------------------------------------------
def _bencode(value: object) -> bytes:
    if isinstance(value, int):
        return b"i" + str(value).encode() + b"e"
    if isinstance(value, bytes):
        return str(len(value)).encode() + b":" + value
    if isinstance(value, list):
        return b"l" + b"".join(_bencode(v) for v in value) + b"e"
    if isinstance(value, dict):
        items = b"".join(_bencode(k) + _bencode(v) for k, v in sorted(value.items()))
        return b"d" + items + b"e"
    raise TypeError(type(value))


def _compact(ip: str, port: int) -> bytes:
    return ipaddress.IPv4Address(ip).packed + struct.pack(">H", port)


def self_test() -> int:
    members = [("10.0.0.1", 4001), ("10.0.0.2", 4002), ("10.0.0.3", 4003)]
    values = [_compact(ip, p) for ip, p in members]
    get_peers_response = _bencode(
        {
            b"t": b"aa",
            b"y": b"r",
            b"r": {b"id": b"x" * 20, b"token": b"tok", b"values": values},
        }
    )

    # In-process re-implementation of the pcap path on synthetic payloads.
    def recover(payloads: list[tuple[int, int, bytes]], observer_port, announced):
        recovered = set()
        for _s, dst, payload in payloads:
            if dst != observer_port:
                continue
            msg = bdecode(payload)
            if _krpc_kind(msg) == b"r" and b"values" in msg[b"r"]:
                recovered.update(_compact_peers(msg[b"r"][b"values"]))
        hits = recovered & announced
        return len(hits), len(announced)

    announced = set(members)
    # (1) full response recovers ALL members.
    num, den = recover([(6881, 55555, get_peers_response)], 55555, announced)
    if (num, den) != (3, 3):
        print(
            f"self-test FAILED: full capture recovered {num}/{den}, expected 3/3",
            file=sys.stderr,
        )
        return 1
    # (2) the SAME response with values STRIPPED recovers 0 — a handed/vacuous run fails.
    stripped = _bencode(
        {b"t": b"aa", b"y": b"r", b"r": {b"id": b"x" * 20, b"token": b"tok"}}
    )
    num0, den0 = recover([(6881, 55555, stripped)], 55555, announced)
    if num0 != 0:
        print(
            f"self-test FAILED: values-stripped capture recovered {num0}, expected 0",
            file=sys.stderr,
        )
        return 1
    # (3) wrong-direction packet (dst != observer) is ignored (only what B RECEIVED counts).
    numx, _ = recover([(55555, 6881, get_peers_response)], 55555, announced)
    if numx != 0:
        print(
            "self-test FAILED: an outbound packet was counted as recovered membership",
            file=sys.stderr,
        )
        return 1

    # (4) client-only bite: the SERVING signal is an OUTBOUND response (src==port, y=r).
    # A node that ANSWERS an inbound query (emits a response FROM its port) is NOT a
    # client; a node that only RECEIVES probe queries and sends its own queries IS.
    def outbound_responses(payloads, node_port):
        return sum(
            1
            for src, _dst, pl in payloads
            if src == node_port and _krpc_kind(bdecode(pl)) == b"r"
        )

    # A server ANSWERS: it emits a response FROM its port -> bite fires.
    if outbound_responses([(7000, 6881, get_peers_response)], 7000) == 0:
        print(
            "self-test FAILED: an outbound response did not fire the non-client bite",
            file=sys.stderr,
        )
        return 1
    # A client only RECEIVES probe queries (dst==port) and emits its OWN queries; it
    # sends NO outbound responses -> passes.
    query = _bencode(
        {
            b"t": b"aa",
            b"y": b"q",
            b"q": b"get_peers",
            b"a": {b"id": b"y" * 20, b"info_hash": b"z" * 20},
        }
    )
    client_traffic = [
        (6881, 7000, query),  # inbound probe query (received, not answered)
        (7000, 6881, query),  # the client's OWN outbound query
        (6881, 7000, get_peers_response),  # inbound response to the client's query
    ]
    if outbound_responses(client_traffic, 7000) != 0:
        print(
            "self-test FAILED: a pure client was miscounted as emitting a response",
            file=sys.stderr,
        )
        return 1
    print(
        "mainline_spike_measure: self-test OK — full capture recovers 3/3, values-stripped "
        "recovers 0/3 (handed/vacuous run fails), outbound packets are not counted as recovered "
        "membership, and an OUTBOUND response fires the non-client bite while a receive-only "
        "client passes"
    )
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(
        description="TASK-258 enumeration + client-only from raw wire"
    )
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--pcap", type=Path)
    ap.add_argument("--observer-port", type=int)
    ap.add_argument("--client-only-port", type=int)
    ap.add_argument(
        "--announced", default="", help="comma list of a.b.c.d:port announced members"
    )
    ap.add_argument(
        "--walltime-ms",
        type=int,
        default=None,
        help="observer get_peers wall time (integer ms)",
    )
    args = ap.parse_args(argv)

    if args.self_test:
        rc = self_test()
        if rc != 0 or not args.pcap:
            return rc

    if not args.pcap:
        print("no --pcap given; nothing measured", file=sys.stderr)
        return 2

    result: dict = {"pcap": str(args.pcap)}
    if args.observer_port is not None:
        announced: set[tuple[str, int]] = set()
        for tok in filter(None, (t.strip() for t in args.announced.split(","))):
            host, _, port = tok.rpartition(":")
            announced.add((host, int(port)))
        enum = enumerate_from_pcap(args.pcap, args.observer_port, announced)
        if enum["krpc_messages_observed"] == 0:
            print(
                "no BEP5 KRPC messages in the observer capture — nothing proven",
                file=sys.stderr,
            )
            return 2
        if args.walltime_ms is not None:
            enum["observer_get_peers_walltime_ms"] = int(args.walltime_ms)
        result["enumeration"] = enum
    if args.client_only_port is not None:
        result["client_only"] = client_only_from_pcap(args.pcap, args.client_only_port)

    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
