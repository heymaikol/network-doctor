#!/bin/bash
# Collector investigation only. Run in unshare -Urnm with the same environment
# as bgp-withdraw.sh. Never produces attribution.
# Reuse the existing isolated topology and capture checks, stopping before start.
set -u
source <(sed '/^started=1$/,$d' "$(dirname "$0")/bgp-withdraw.sh") || exit 1
[[ -n $ZP ]] || fail "set ZEBRA_VTY_PORT"
cp "$0" "$OUT/producer-probe.sh" || fail "could not preserve producer"

# Exercise a BGP path with a non-connected next hop and a static route that
# resolves through a different, BGP-learned prefix.
python3 -I - "$OUT" <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1])
r1 = p / "r1-bgpd.conf"
r1.write_text(r1.read_text().replace("router bgp 65001", "bgp send-extra-data zebra\nrouter bgp 65001\n bgp suppress-fib-pending")
              .replace(" neighbor 10.0.1.2 remote-as 65002", " neighbor 10.0.1.2 remote-as 65002\n neighbor 10.0.1.2 ebgp-multihop 2")
              .replace("remote-as 65003", "remote-as 65002"))
r2 = p / "r2-bgpd.conf"
r2.write_text(r2.read_text().replace("  network 10.10.9.0/24", "  network 10.10.9.0/24\n  network 203.0.113.0/24\n  neighbor 10.0.1.1 route-map RECURSE out") + "\nip prefix-list RECURSE seq 5 permit 203.0.113.0/24\nroute-map RECURSE permit 10\n match ip address prefix-list RECURSE\n set ip next-hop 10.10.9.2\nroute-map RECURSE permit 20\n")
r3 = p / "r3-bgpd.conf"
r3.write_text(r3.read_text().replace("router bgp 65003", "router bgp 65002")
              .replace("  network 10.10.2.0/24", "  network 10.10.2.0/24\n  neighbor 10.0.3.1 route-map SHARED out")
              + "\nip prefix-list SHARED seq 5 permit 10.10.2.0/24\nroute-map SHARED permit 10\n match ip address prefix-list SHARED\n set ip next-hop 10.0.1.2\nroute-map SHARED permit 20\n")
(p / "r1-staticd.conf").write_text("hostname r1\nline vty\n no login\nip route 198.51.100.0/24 10.10.9.2\n")
PY
in_r2 ip addr add 203.0.113.2/24 dev stub2 || fail "recursive stub setup failed"
"$FRR/staticd" --version > "$OUT/staticd-version.txt" 2>&1 || fail "staticd version failed"

started=1
start r1 self || fail "r1 did not start"
start r2 "$R2" || fail "r2 did not start"
start r3 "$R3" || fail "r3 did not start"
"$FRR/mgmtd" --version > "$OUT/mgmtd-version.txt" 2>&1 || fail "mgmtd version failed"
"$FRR/mgmtd" -d -i /run/frr/r1/mgmtd.pid --vty_socket /run/frr/r1 -P 0 \
  -u root -g root >> "$OUT/r1-daemons.log" 2>&1 || fail "mgmtd did not start"
"$FRR/staticd" -d -i /run/frr/r1/staticd.pid \
  -z /run/frr/r1/zserv.api --vty_socket /run/frr/r1 -P 0 \
  -u root -g root >> "$OUT/r1-daemons.log" 2>&1 || fail "staticd did not start"
alive /run/frr/r1/staticd.pid || fail "staticd not alive"
sleep 2
"$S/frr-root/usr/bin/vtysh" --vty_socket /run/frr/r1 -f "$OUT/r1-staticd.conf" \
  > "$OUT/r1-static-config-load.raw" 2>&1 || fail "static configuration failed"

# A raw probe can intentionally return an unsupported-command response.
probe() {
  local phase=$1 port=$2 name=$3 command=$4 base
  base="$OUT/r1-$phase-$name"
  date -u +%Y-%m-%dT%H:%M:%S.%NZ > "$base.started_at" || fail "clock failed"
  query "$command" "$base.raw" "$port" || fail "query failed: $command"
  date -u +%Y-%m-%dT%H:%M:%S.%NZ > "$base.finished_at" || fail "clock failed"
}

lookup() {
  local phase=$1 name=$2 base rc
  shift 2
  base="$OUT/r1-$phase-$name"
  date -u +%Y-%m-%dT%H:%M:%S.%NZ > "$base.started_at" || fail "clock failed"
  "$@" > "$base.json" 2> "$base.stderr"; rc=$?
  printf '%s\n' "$rc" > "$base.status" || fail "lookup status write failed"
  date -u +%Y-%m-%dT%H:%M:%S.%NZ > "$base.finished_at" || fail "clock failed"
}

bracket() {
  local phase=$1
  cap "$phase" "show ip bgp json" || fail "BGP table capture failed"
  probe "$phase" "$P" bgp-detail "show ip bgp detail json"
  probe "$phase" "$P" bgp-nexthop "show ip bgp nexthop detail json"
  zcap "$phase" || fail "zebra route capture failed"
  probe "$phase" "$ZP" fib "show ip fib json"
  probe "$phase" "$ZP" nht "show ip nht json"
  probe "$phase" "$ZP" nhg "show nexthop-group rib json"
  "$S/frr-root/usr/bin/vtysh" --vty_socket /run/frr/r1 -c "show running-config" \
    > "$OUT/r1-$phase-running-config.raw" 2>&1 || fail "configuration capture failed"
  kernel "$phase" || fail "kernel capture failed"
  lookup "$phase" get ip -j -4 route get 10.10.9.2
  lookup "$phase" fibmatch ip -j -4 route get fibmatch 10.10.9.2
  ip -j -4 rule show > "$OUT/r1-$phase-rules.json" || fail "rules capture failed"
  probe "$phase" "$P" bgp-detail-end "show ip bgp detail json"
  probe "$phase" "$ZP" route-end "show ip route json"
  in_r2 ip -j -4 route show > "$OUT/r2-$phase-ip_route.json" || fail "r2 routes failed"
  timeout 30 nsenter -t "$R2" -n python3 -I "$TCP" "$P" "show ip bgp json" \
    > "$OUT/r2-$phase-bgp.raw" || fail "r2 capture failed"
}

# Wait on the expected BGP paths, then check installation separately in the
# saved observations. Matching addresses here never establishes attribution.
for (( i=0; i<20; i++ )); do
  query "show ip bgp json" "$OUT/poll-recursive.last"
  if python3 -I -c "$BGPOK" "$OUT/poll-recursive.last" "show ip bgp json" r1 \
    paths:10.10.9.0/24=10.0.1.2 paths:203.0.113.0/24=10.0.1.2 2>/dev/null; then break; fi
  sleep 2
done
(( i<20 )) || fail "recursive BGP paths never appeared"
bracket before
event "r2: no network 10.10.9.0/24"
in_r2 "$S/frr-root/usr/bin/vtysh" --vty_socket /run/frr/r2 \
  -c "configure terminal" -c "router bgp 65002" \
  -c "address-family ipv4 unicast" -c "no network 10.10.9.0/24" \
  > "$OUT/r2-withdraw.raw" 2>&1 || fail "resolver withdrawal failed"
for (( i=0; i<20; i++ )); do
  query "show ip bgp json" "$OUT/poll-withdraw.last"
  if python3 -I -c "$BGPOK" "$OUT/poll-withdraw.last" "show ip bgp json" r1 \
    absent:10.10.9.0/24 2>/dev/null; then break; fi
  sleep 2
done
(( i<20 )) || fail "resolver withdrawal never appeared"
bracket after
echo "--- stopping"
stop
sums
echo DONE
