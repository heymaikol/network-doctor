#!/bin/bash
# Instrumented FRR only, inside disposable unprivileged namespaces.
# SCRATCH/frr-root holds the isolated build. MODE=proof or restart.
set -u
NDOC_LAB=$(cd "$(dirname "$0")/../../../testdata/frr/10.7.0/lab" && pwd) || exit 1
source <(sed '/^started=1$/,$d;s@^HERE=.*@HERE=$NDOC_LAB@' "$NDOC_LAB/bgp-withdraw.sh") || exit 1
[[ -n $ZP ]] || fail "set ZEBRA_VTY_PORT"
MODE=${MODE:-proof}
[[ $MODE == proof || $MODE == restart ]] || fail "unsupported mode"
cp "$0" "$OUT/producer-lab.sh" || fail "preserve recipe"
start_definition=$(declare -f start)
eval "${start_definition/start ()/legacy_start ()}"
start() {
  export NETDOC_CORRELATION_DIR="$OUT/identity/$1"
  mkdir -p "$NETDOC_CORRELATION_DIR" || return 1
  legacy_start "$@"
}
python3 -I - "$OUT" <<'PY'
from pathlib import Path
import sys
p = Path(sys.argv[1])
f = p / 'r1-bgpd.conf'
f.write_text(f.read_text().replace('remote-as 65003', 'remote-as 65002'))
f = p / 'r3-bgpd.conf'
f.write_text(f.read_text().replace('router bgp 65003', 'router bgp 65002')
             .replace('  network 10.10.2.0/24', '  network 10.10.2.0/24\n  neighbor 10.0.3.1 route-map SHARED out')
             + '\nip prefix-list SHARED seq 5 permit 10.10.2.0/24\nroute-map SHARED permit 10\n match ip address prefix-list SHARED\n set ip next-hop 10.0.1.2\nroute-map SHARED permit 20\n')
(p / 'r1-staticd.conf').write_text('hostname r1\nline vty\n no login\nip route 198.51.100.0/24 10.10.9.2\nip route 192.0.2.0/24 10.0.1.2 table 100\n')
PY
[[ $? == 0 ]] || fail "configure lab"
started=1
start r1 self || fail "start r1"
start r2 "$R2" || fail "start r2"
start r3 "$R3" || fail "start r3"
for daemon in mgmtd staticd; do
  "$FRR/$daemon" --version > "$OUT/$daemon-version.txt" 2>&1 || fail "version"
  "$FRR/$daemon" -d -i "/run/frr/r1/$daemon.pid" -z /run/frr/r1/zserv.api \
    --vty_socket /run/frr/r1 -P 0 -u root -g root >> "$OUT/r1-daemons.log" 2>&1 || fail "start $daemon"
  alive "/run/frr/r1/$daemon.pid" || fail "$daemon not alive"
done
sleep 2
"$S/frr-root/usr/bin/vtysh" --vty_socket /run/frr/r1 -f "$OUT/r1-staticd.conf" \
  > "$OUT/static-config-load.raw" 2>&1 || fail "load static routes"
capture_phase() {
  local phase=$1 name command port
  date -u +%Y-%m-%dT%H:%M:%S.%NZ > "$OUT/$phase.started_at" || fail "clock"
  cap "$phase" "show ip bgp summary json" || fail "BGP summary"
  cap "$phase" "show ip bgp json" || fail "BGP table"
  cap "$phase" "show ip bgp detail json" || fail "BGP detail"
  zcap "$phase" || fail "Zebra routes"
  capture "$ZP" "$phase" "show ip nht json" || fail "NHT"
  kernel "$phase" || fail "kernel routes"
  ip -j -4 route show table all > "$OUT/r1-$phase-all-routes.json" || fail "all tables"
  ip -j nexthop show > "$OUT/r1-$phase-nexthops.json" || fail "kernel next hops"
  ip -j -4 rule show > "$OUT/r1-$phase-rules.json" || fail "rules"
  readlink /proc/self/ns/net > "$OUT/r1-$phase-netns.txt" || fail "namespace"
  cat /proc/sys/kernel/random/boot_id > "$OUT/r1-$phase-boot-id.txt" || fail "boot ID"
  date -u +%Y-%m-%dT%H:%M:%S.%NZ > "$OUT/$phase.finished_at" || fail "clock"
}
wait_paths() {
  local i
  for (( i=0; i<30; i++ )); do
    query "show ip bgp json" "$OUT/poll-state.last"
    if python3 -I -c "$BGPOK" "$OUT/poll-state.last" "show ip bgp json" r1 "$@" 2>/dev/null; then return 0; fi
    sleep 1
  done
  fail "BGP state did not settle"
}
wait_paths paths:10.10.2.0/24=10.0.1.2,10.0.3.3 paths:10.10.9.0/24=10.0.1.2
capture_phase before
if [[ $MODE == proof ]]; then
  event "r2: no network 10.10.9.0/24"
  in_r2 "$S/frr-root/usr/bin/vtysh" --vty_socket /run/frr/r2 -c "configure terminal" \
    -c "router bgp 65002" -c "address-family ipv4 unicast" -c "no network 10.10.9.0/24" \
    > "$OUT/withdraw.raw" 2>&1 || fail "withdraw"
  wait_paths absent:10.10.9.0/24
  capture_phase withdrawn
  pid=$(cat /run/frr/r2/bgpd.pid) || fail "r2 pid"
  event "r2: SIGKILL bgpd $pid"
  kill -9 "$pid" || fail "session loss"
  wait_paths paths:10.10.2.0/24=10.0.3.3 absent:10.10.9.0/24
  capture_phase session_lost
else
  pid=$(cat /run/frr/r1/bgpd.pid) || fail "r1 pid"
  event "r1: SIGKILL bgpd $pid, then restart"
  kill -9 "$pid" || fail "kill r1"
  sleep 1
  export NETDOC_CORRELATION_DIR="$OUT/identity/r1"
  "$FRR/bgpd" -d -f "$OUT/r1-bgpd.conf" -i /run/frr/r1/bgpd.pid -z /run/frr/r1/zserv.api \
    --vty_socket /run/frr/r1 -P "$P" -A 127.0.0.1 -u root -g root >> "$OUT/r1-daemons.log" 2>&1 || fail "restart"
  wait_paths paths:10.10.2.0/24=10.0.1.2,10.0.3.3
  capture_phase restarted
fi
stop
for (( i=0; i<100; i++ )); do
  live=0
  for pid in $STOPPED; do if kill -0 "$pid" 2>/dev/null; then live=1; fi; done
  (( live == 0 )) && break
  sleep 0.1
done
(( live == 0 )) || fail "daemon still writes; no manifest"
python3 -I - "$OUT" <<'PY'
from pathlib import Path
import hashlib, sys
p = Path(sys.argv[1])
(p / 'SHA256SUMS').write_text(''.join(hashlib.sha256(f.read_bytes()).hexdigest() + '  ' + str(f.relative_to(p)) + '\n' for f in sorted(p.rglob('*')) if f.is_file() and f.name != 'SHA256SUMS'))
PY
[[ $? == 0 ]] || fail "manifest"
echo DONE
