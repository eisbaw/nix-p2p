#!/usr/bin/env bash
# In-namespace driver for the shaped-link measurement primitive.
#
# Runs INSIDE `unshare -Urn` (ns A), which holds FULL capabilities via userns
# map-root (CapEff 000001ffffffffff) WITHOUT real root. It builds a SECOND netns
# (ns B) with the child-pid pattern and wires a veth pair across A<->B so packets
# must actually traverse the pair:
#
#   SETTLED ROUTE (task-70): rootless `ip netns add` cannot bind-mount
#   /var/run/netns, so instead fork a child that `unshare -n`s its own netns
#   (same userns => keeps caps) and address it by PID: move the peer veth end in
#   with `ip link set veth1 netns <pid>` and configure it with `nsenter -t <pid>
#   -n`. Putting the two ends in SEPARATE netns is load-bearing: with both ends
#   in one netns the kernel short-circuits the pair locally and netem never
#   shapes (the same-netns artifact the prior spike hit as 100% "loss").
#
# Then (optionally) applies tc netem to BOTH veth egress directions, probes RTT
# with ping, and runs one bulk TCP transfer (sender in A -> receiver in B). All
# shaping lives here, on the SCRIPT/TEST surface -- never in the product daemon.
#
# Emits two machine-parseable contract lines that shaped_link.py consumes:
#   - ping's native `rtt min/avg/max/mdev = .../.../.../... ms`
#   - xfer's `SEND_DONE bytes=... elapsed_s=... mbit_per_s=... MB_per_s=...`
# A setup failure prints `FATAL <what>` and exits non-zero (fail fast, never a
# silent 0 that would read as a measurement).
#
# Args: SHAPE(yes|no)  TOTAL_BYTES  DELAY_MS  RATE_MBIT  XFER_PY
set -u
SHAPE="${1:?SHAPE}"; TOTAL="${2:?TOTAL_BYTES}"; DELAY_MS="${3:?DELAY_MS}"
RATE_MBIT="${4:?RATE_MBIT}"; XFER="${5:?XFER_PY}"
IP_A=10.99.0.1; IP_B=10.99.0.2; PORT=9099

child=""
cleanup() {
  # Tear down the ONLY child we spawned, by its exact pid -- never pkill -f
  # (which would self-match). veth and both netns die with their processes.
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
  # Shape EGRESS of both ends: delay each way (=> RTT ~= 2*DELAY_MS) and cap
  # each direction at RATE_MBIT. Applying to both ends is what makes the link
  # symmetric; a single-end netem would shape one direction only.
  tc qdisc add dev veth0 root netem delay "${DELAY_MS}ms" rate "${RATE_MBIT}mbit" \
    || { echo "FATAL tc-A"; exit 3; }
  nsenter -t "$child" -n tc qdisc add dev veth1 root netem \
    delay "${DELAY_MS}ms" rate "${RATE_MBIT}mbit" || { echo "FATAL tc-B"; exit 3; }
fi

# RTT across the pair (A -> B). Outside any netem internal accounting: this is a
# real ICMP round trip over the shaped link.
echo "=== RTT probe (shape=$SHAPE) ==="
ping -c 5 -i 0.2 -W 2 "$IP_B" 2>&1 | tail -2

# Bulk transfer: receiver in ns B, sender in ns A. Poll a readiness file the
# receiver touches once listening (a probe-connect would eat its single accept).
echo "=== XFER (shape=$SHAPE, total=$TOTAL bytes) ==="
ready="$(dirname "$XFER")/.shaped_link_ready.$$"
rm -f "$ready"
nsenter -t "$child" -n python3 "$XFER" recv "$PORT" "$TOTAL" "$ready" &
recv_pid=$!
for _ in $(seq 1 100); do
  [ -e "$ready" ] && break
  sleep 0.05
done
python3 "$XFER" send "$IP_B" "$PORT" "$TOTAL"
wait "$recv_pid" 2>/dev/null
rm -f "$ready"
