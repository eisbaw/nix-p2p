#!/usr/bin/env bash
# TASK-258 SPIKE — hermetic rootless-netns measurement of the Mainline rendezvous.
#
# Stands up, inside an UNPRIVILEGED network namespace (`unshare -Urn`, the repo's
# rootless-capture pattern — see scripts/shaped_link*.py), a LOCAL Mainline DHT plus
# N announcer nodes plus a third-party observer, captures the observer's wire with
# tcpdump, and derives BOTH:
#   * AC#7 node-membership ENUMERATION (recoverable fraction, exact rational) from the
#     observer's OWN capture — never handed the peer list; and
#   * AC#1 CLIENT-ONLY (zero inbound BEP5 queries to a client vs. > 0 to the server).
# NEVER contacts the real public Mainline swarm — the only bootstrap is the local node.
#
# Usage: mainline_spike_e2e.sh <path-to-rendezvous-spike-bin> <out-dir>
set -euo pipefail

BIN="${1:?usage: mainline_spike_e2e.sh <rendezvous-spike-bin> <out-dir>}"
OUT="${2:?usage: mainline_spike_e2e.sh <rendezvous-spike-bin> <out-dir>}"
BIN="$(readlink -f "$BIN")"
mkdir -p "$OUT"
PYTHON="${NIX_P2P_PYTHON:+${NIX_P2P_PYTHON}/bin/python3}"
PYTHON="${PYTHON:-python3}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Re-exec under an unprivileged user+net namespace so tcpdump on lo gets CAP_NET_RAW.
if [ "${MAINLINE_SPIKE_INNS:-0}" != "1" ]; then
    exec unshare -Urn env MAINLINE_SPIKE_INNS=1 NIX_P2P_PYTHON="${NIX_P2P_PYTHON:-}" \
        "${BASH_SOURCE[0]}" "$BIN" "$OUT"
fi

ip link set lo up
# lo covers 127.0.0.0/8, so 127.0.0.2..6 are usable distinct loopback source IPs,
# making the recovered membership a set of distinct IPs (closer to a real swarm).

BOOT_PORT=16881
OBS_PORT=16999
N=5
pids=()
cleanup() { for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null || true; done; kill "${TCPDUMP_PID:-}" 2>/dev/null || true; }
trap cleanup EXIT

echo "[e2e] starting local Mainline bootstrap (SERVER) on 127.0.0.1:${BOOT_PORT}"
"$BIN" local-bootstrap --bind 127.0.0.1 --port "$BOOT_PORT" --hold-secs 60 >"$OUT/bootstrap.log" 2>&1 &
pids+=($!)
sleep 2

# Capture ALL udp on lo for the whole run; the analyzer scopes by port.
PCAP="$OUT/observer.pcap"
tcpdump -i lo -w "$PCAP" -U udp >"$OUT/tcpdump.log" 2>&1 &
TCPDUMP_PID=$!
sleep 1

ANNOUNCED=""
for i in $(seq 1 "$N"); do
    ip=$((i + 1))            # 127.0.0.2 .. 127.0.0.6
    dht_port=$((16890 + i))  # distinct DHT sockets
    l2p=$((14000 + i))       # announced libp2p port
    "$BIN" announce --bootstrap 127.0.0.1:${BOOT_PORT} --bind 127.0.0.${ip} \
        --port "$dht_port" --libp2p-port "$l2p" --hold-secs 45 \
        >"$OUT/announce_${i}.log" 2>&1 &
    pids+=($!)
    ANNOUNCED="${ANNOUNCED}${ANNOUNCED:+,}127.0.0.${ip}:${l2p}"
done
echo "[e2e] ${N} announcers up; announced set = ${ANNOUNCED}"
# Let announces settle on the server.
sleep 6

echo "[e2e] third-party OBSERVER runs get_peers (bind 127.0.0.9, port ${OBS_PORT})"
"$BIN" discover --bootstrap 127.0.0.1:${BOOT_PORT} --bind 127.0.0.9 --port "$OBS_PORT" \
    --deadline-ms 10000 >"$OUT/observer.log" 2>&1
cat "$OUT/observer.log"
WALLTIME_MS="$(grep -oE 'elapsed_ms=[0-9]+' "$OUT/observer.log" | tail -1 | cut -d= -f2)"
WALLTIME_MS="${WALLTIME_MS:-0}"

# One client announcer's DHT port (client-only PASS should show 0 inbound queries);
# the bootstrap server's port (the bite: a server RECEIVES inbound queries > 0).
CLIENT_PORT=16891
sleep 1
kill "$TCPDUMP_PID" 2>/dev/null || true
wait "$TCPDUMP_PID" 2>/dev/null || true

echo "[e2e] ==== ENUMERATION (from observer's OWN capture) ===="
"$PYTHON" "$HERE/mainline_spike_measure.py" --pcap "$PCAP" \
    --observer-port "$OBS_PORT" --announced "$ANNOUNCED" --walltime-ms "$WALLTIME_MS" \
    | tee "$OUT/enumeration.json"

echo "[e2e] ==== CLIENT-ONLY (a client announcer's port) ===="
"$PYTHON" "$HERE/mainline_spike_measure.py" --pcap "$PCAP" \
    --client-only-port "$CLIENT_PORT" | tee "$OUT/client_only.json"

echo "[e2e] ==== SERVER BITE (the bootstrap server's port RECEIVES queries > 0) ===="
"$PYTHON" "$HERE/mainline_spike_measure.py" --pcap "$PCAP" \
    --client-only-port "$BOOT_PORT" | tee "$OUT/server_bite.json"

echo "[e2e] done; artifacts in $OUT"
