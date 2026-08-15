#!/usr/bin/env bash
# In-namespace driver for the TASK-198 raw-vs-zstd DEMONSTRATION over a shaped peer link.
#
# Structurally identical to `scripts/shaped_libp2p_inner.sh` (the proven TASK-206 / TASK-70 link
# substrate): runs INSIDE `unshare -Urn` (ns A, full caps via userns map-root, no real root),
# builds a SECOND netns (ns B) by the child-pid pattern, wires a veth pair A<->B, and (optionally)
# applies `tc netem delay+rate` to BOTH egress directions so packets actually traverse a shaped
# link with BOTH ends shaped.
#
# The difference from TASK-206: it serves a COMPRESSIBLE nar and runs TWO real libp2p fetches over
# the SAME shaped link against the SAME provider — a RAW arm (raw-only accept set) and a ZSTD arm
# (raw+zstd accept set, so the TASK-203 streaming zstd serve compresses). Same nar, same link; the
# ONLY difference is the codec. That is the like-for-like raw-vs-zstd comparison the harness times.
#
# Emits the machine-parseable lines `scripts/shaped_compress.py` consumes:
#   - ping's native `rtt min/avg/max/mdev = .../.../.../... ms` (host-side RTT over the link)
#   - the provider's `PROVIDE_META raw_bytes=... zstd_frame_bytes=...` (deterministic wire volumes)
#   - two `FETCH_DONE ... wire_body_bytes=... codec_requested=<raw|both>` lines (raw then zstd)
# A setup failure prints `FATAL <what>` and exits non-zero (fail fast; never a silent 0 that would
# read as a measurement). All shaping lives on this script/measurement surface — never in the
# product daemon.
#
# Args: SHAPE(yes|no)  NAR_BYTES  DELAY_MS  RATE_MBIT  PROBE_BIN  NAR_SEED
set -u
SHAPE="${1:?SHAPE}"; NAR_BYTES="${2:?NAR_BYTES}"; DELAY_MS="${3:?DELAY_MS}"
RATE_MBIT="${4:?RATE_MBIT}"; BIN="${5:?PROBE_BIN}"; NAR_SEED="${6:?NAR_SEED}"
IP_A=10.98.0.1; IP_B=10.98.0.2; PORT=9098

child=""; prov=""
cleanup() {
  # Kill by EXACT pid only — never `pkill -f` (self-match, exit 144). The veth and both netns die
  # with their processes.
  [ -n "$prov" ] && kill "$prov" 2>/dev/null
  [ -n "$child" ] && kill "$child" 2>/dev/null
}
trap cleanup EXIT

# ns A: loopback + veth pair (both ends start here).
ip link set lo up
ip link add veth0 type veth peer name veth1 || { echo "FATAL veth-add"; exit 3; }

# ns B: a child parked in its own fresh netns; its pid is our handle.
unshare -n sleep 600 &
child=$!
for _ in $(seq 1 100); do
  [ -e "/proc/$child/ns/net" ] && break
  sleep 0.05
done
[ -e "/proc/$child/ns/net" ] || { echo "FATAL child-netns"; exit 3; }
nsenter -t "$child" -n ip link set lo up || { echo "FATAL child-lo"; exit 3; }

# Move the peer end into ns B; address each end in its own ns.
ip link set veth1 netns "$child" || { echo "FATAL move-veth1"; exit 3; }
ip addr add "$IP_A/24" dev veth0 || { echo "FATAL addr-A"; exit 3; }
ip link set veth0 up || { echo "FATAL up-A"; exit 3; }
nsenter -t "$child" -n ip addr add "$IP_B/24" dev veth1 || { echo "FATAL addr-B"; exit 3; }
nsenter -t "$child" -n ip link set veth1 up || { echo "FATAL up-B"; exit 3; }

if [ "$SHAPE" = "yes" ]; then
  # Shape EGRESS of BOTH ends: delay each way (=> RTT ~= 2*DELAY_MS) and cap each direction at
  # RATE_MBIT. Shaping both ends is what makes the PEER link symmetric — the correction TASK-198
  # exists to make (TASK-206/70 shaped only one side of the earlier peer-vs-upstream numbers).
  tc qdisc add dev veth0 root netem delay "${DELAY_MS}ms" rate "${RATE_MBIT}mbit" \
    || { echo "FATAL tc-A"; exit 3; }
  nsenter -t "$child" -n tc qdisc add dev veth1 root netem \
    delay "${DELAY_MS}ms" rate "${RATE_MBIT}mbit" || { echo "FATAL tc-B"; exit 3; }
fi

# RTT across the pair (A -> B), a real ICMP round trip over the shaped link.
echo "=== RTT probe (shape=$SHAPE) ==="
ping -c 5 -i 0.2 -W 2 "$IP_B" 2>&1 | tail -2

# Provider (ns A) serves the COMPRESSIBLE nar on IP_A; it writes its PeerId to a file once
# listening. We poll for it (no probe-dial that would perturb timing).
echo "=== PROVIDER (shape=$SHAPE, nar=$NAR_BYTES bytes, compressible) ==="
pidf="$(dirname "$BIN")/.shaped_compress_peerid.$$"
rm -f "$pidf"
"$BIN" provide "$IP_A" "$PORT" 1 "$NAR_BYTES" "$NAR_SEED" "$pidf" compressible &
prov=$!
for _ in $(seq 1 200); do
  [ -s "$pidf" ] && break
  # Fail fast if the provider died during startup rather than spinning the full poll.
  kill -0 "$prov" 2>/dev/null || { echo "FATAL provider-exited"; exit 3; }
  sleep 0.05
done
[ -s "$pidf" ] || { echo "FATAL provider-not-ready"; exit 3; }
PEERID="$(cat "$pidf")"

# RAW arm: consumer (ns B) fetches offering the raw-only accept set (forces the raw codec).
echo "=== XFER raw ==="
nsenter -t "$child" -n "$BIN" fetch "$IP_A" "$PORT" "$PEERID" 2 "$NAR_BYTES" "$NAR_SEED" \
  compressible raw
rc_raw=$?
[ "$rc_raw" -eq 0 ] || { echo "FATAL fetch-raw-rc=$rc_raw"; rm -f "$pidf"; exit 3; }

# ZSTD arm: consumer (ns B) fetches offering raw+zstd (the TASK-203 streaming zstd serve compresses)
# over the SAME shaped link against the SAME provider.
echo "=== XFER zstd ==="
nsenter -t "$child" -n "$BIN" fetch "$IP_A" "$PORT" "$PEERID" 3 "$NAR_BYTES" "$NAR_SEED" \
  compressible both
rc_zstd=$?
rm -f "$pidf"
[ "$rc_zstd" -eq 0 ] || { echo "FATAL fetch-zstd-rc=$rc_zstd"; exit 3; }
