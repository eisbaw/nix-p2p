#!/usr/bin/env bash
# In-namespace driver for the SHAPED-KAD-DISCOVERY proof (TASK-209).
#
# Extends the TASK-206 2-node substrate (`scripts/shaped_libp2p_inner.sh`) to THREE kad
# nodes so the DISCOVER half (kad `get_providers` + peer-routing) crosses the shaped link,
# not just the fetch. Runs INSIDE `unshare -Urn` (ns A, full caps via userns map-root, no
# real root), builds a SECOND netns (ns B) by the child-pid pattern, wires a veth pair
# A<->B, and (optionally) applies `tc netem delay+rate` to BOTH egress directions.
#
# TOPOLOGY (the whole point): BOOTSTRAP (B) and PROVIDER (P) live in ns A; CONSUMER (C)
# lives in ns B. So B<->P is unshaped (same ns), but EVERY C round-trip - join, kad
# get_providers, kad get_closest_peers (locate), and the /nar/4 fetch - crosses the shaped
# veth. C is told ONLY B's address (AC#9: discovery must be genuinely kad).
#
# Emits the machine-parseable lines `scripts/shaped_kad.py` consumes:
#   - ping's native `rtt min/avg/max/mdev = .../.../.../... ms` (host-side RTT, C->A)
#   - the consumer's DISCOVERY_DONE / DISCOVERED_PROVIDER / FETCH_DONE lines
# A setup failure prints `FATAL <what>` and exits non-zero (fail fast; never a silent 0
# that would read as a measurement). All shaping lives on this measurement surface.
#
# Args: SHAPE(yes|no) NAR_BYTES DELAY_MS RATE_MBIT PROBE_BIN NAR_SEED DISC_BUDGET_SECS OUTER_SECS
set -u
SHAPE="${1:?SHAPE}"; NAR_BYTES="${2:?NAR_BYTES}"; DELAY_MS="${3:?DELAY_MS}"
RATE_MBIT="${4:?RATE_MBIT}"; BIN="${5:?PROBE_BIN}"; NAR_SEED="${6:?NAR_SEED}"
DISC_BUDGET="${7:?DISC_BUDGET_SECS}"; OUTER="${8:?OUTER_SECS}"
IP_A=10.99.0.1; IP_B=10.99.0.2; PORT_B=9098; PORT_P=9099
# id-seeds: bootstrap=1, provider=3, consumer=4 (distinct kad identities).
SEED_B=1; SEED_P=3; SEED_C=4

child=""; boot=""; prov=""
cleanup() {
  # Kill by EXACT pid only -- never `pkill -f` (self-match, exit 144). The veth and both
  # netns die with their processes.
  [ -n "$prov" ] && kill "$prov" 2>/dev/null
  [ -n "$boot" ] && kill "$boot" 2>/dev/null
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
  # Shape EGRESS of both ends: delay each way (=> RTT ~= 2*DELAY_MS) and cap each direction
  # at RATE_MBIT. Both ends is what makes the link symmetric.
  tc qdisc add dev veth0 root netem delay "${DELAY_MS}ms" rate "${RATE_MBIT}mbit" \
    || { echo "FATAL tc-A"; exit 3; }
  nsenter -t "$child" -n tc qdisc add dev veth1 root netem \
    delay "${DELAY_MS}ms" rate "${RATE_MBIT}mbit" || { echo "FATAL tc-B"; exit 3; }
fi

# RTT across the pair (C in ns B -> A), a real ICMP round trip over the shaped link. This is
# the host-side shaping witness: it must recover ~2*DELAY_MS or the "shaped" run is a lie.
# The per-reply wait (-W) MUST comfortably exceed the injected RTT (~2*DELAY_MS), or the ping
# times out before its own replies arrive and we would mis-read a working shaped link as
# "ping did not complete" (TASK-209 harness bug: a 2s -W hid the true >=1000ms-delay
# behaviour behind a ping artifact). Scale it: 2s + 4*DELAY_MS, generous vs 2*DELAY_MS RTT.
PING_W=$(( 2 + (4 * DELAY_MS) / 1000 ))
echo "=== RTT probe (shape=$SHAPE) ==="
nsenter -t "$child" -n ping -c 3 -i 0.3 -W "$PING_W" "$IP_A" 2>&1 | tail -2

echo "=== KAD DISCOVERY (shape=$SHAPE, nar=$NAR_BYTES bytes, disc_budget=${DISC_BUDGET}s) ==="
dir="$(dirname "$BIN")"
bpf="$dir/.shaped_kad_boot.$$"; rpf="$dir/.shaped_kad_prov.$$"
rm -f "$bpf" "$rpf"

# --- 1) BOOTSTRAP B in ns A. Writes its PeerId to $bpf once listening. ---
"$BIN" bootstrap "$IP_A" "$PORT_B" "$SEED_B" "$bpf" &
boot=$!
for _ in $(seq 1 200); do
  [ -s "$bpf" ] && break
  kill -0 "$boot" 2>/dev/null || { echo "FATAL bootstrap-exited"; exit 3; }
  sleep 0.05
done
[ -s "$bpf" ] || { echo "FATAL bootstrap-not-ready"; exit 3; }
BOOT_PEERID="$(cat "$bpf")"

# --- 2) PROVIDER P in ns A. Joins B, announces its signed record, writes $rpf. ---
"$BIN" provide-dht "$IP_A" "$PORT_P" "$SEED_P" "$NAR_BYTES" "$NAR_SEED" \
  "$IP_A" "$PORT_B" "$BOOT_PEERID" "$rpf" &
prov=$!
for _ in $(seq 1 600); do
  [ -s "$rpf" ] && break
  kill -0 "$prov" 2>/dev/null || { echo "FATAL provider-exited"; exit 3; }
  sleep 0.05
done
[ -s "$rpf" ] || { echo "FATAL provider-not-ready"; exit 3; }

# --- 3) CONSUMER C in ns B. Told ONLY B's addr+PeerId (NOT P's). Discovers via kad,
#        then fetches. All its round-trips cross the shaped veth. ---
nsenter -t "$child" -n "$BIN" fetch-dht "$IP_B" "$SEED_C" "$NAR_BYTES" "$NAR_SEED" \
  "$IP_A" "$PORT_B" "$BOOT_PEERID" "$DISC_BUDGET" "$OUTER"
rc=$?
rm -f "$bpf" "$rpf"
[ "$rc" -eq 0 ] || { echo "FATAL consumer-rc=$rc"; exit 3; }
