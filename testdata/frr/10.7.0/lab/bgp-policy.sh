#!/bin/bash
# Local three-router FRR 10.7.0 BGP policy lab, one run, inside user+mount+net namespaces.
# The routers, addresses, and network statements are those of bgp-withdraw.sh:
# r1 (AS 65001, 1.1.1.1) peers with r2 (AS 65002, 2.2.2.2) at 10.0.1.2 and with r3 (AS 65003,
# 3.3.3.3) at 10.0.3.3. Each router originates prefixes from addresses on a dummy stub:
#   r1: 10.10.1.0/24
#   r2: 10.10.1.0/24, 10.10.2.0/24, 10.10.9.0/24
#   r3: 10.10.2.0/24, 10.10.3.0/24
# Before the change, r1 holds 10.10.2.0/24 from r2 and from r3, and bestpath is r2's path, which the
# router ID decides. The change is made on r1 over one vty session, without a restart:
#   ip prefix-list P10-2 seq 5 permit 10.10.2.0/24
#   route-map R3-IN permit 10: match ip address prefix-list P10-2, set weight 100
#   route-map R3-IN permit 20: no match and nothing set, so every other path is unchanged
#   address-family ipv4 unicast: neighbor 10.0.3.3 route-map R3-IN in
#   clear ip bgp 10.0.3.3 soft in, so r3's paths are received again through the policy
# The policy ID is R3-IN, the direction in, the peer 10.0.3.3, the VRF default, and the family IPv4
# unicast. Only zebra and bgpd run. No host network change.
# Run as: SCRATCH=<dir> BGPD_VTY_PORT=<port> unshare -Urnm bash bgp-policy.sh
#   SCRATCH must hold frr-root/ extracted from the FRR 10.7.0 RPM (see ../README.md).
#   BGPD_VTY_PORT is bgpd's vty TCP port, passed as -P. It must be 1 to 65535 and not 2604
#   (ospfd), 2601 (zebra's default vty), or 179 (bgpd's BGP listener).
# Output goes to $SCRATCH/run/bgp-policy, which must not exist. The run never removes anything.
#   For each phase (before, after): r1-PHASE-show_ip_bgp_summary_json.raw, r1-PHASE-show_ip_bgp_json.raw,
#   r1-PHASE-show_ip_bgp_neighbors_10.0.1.2_json.raw, r1-PHASE-show_ip_bgp_neighbors_10.0.3.3_json.raw,
#   and r1-PHASE-running-config.raw, each with a .collected_at UTC stamp. After the change, also
#   r1-after-route-map.raw and r1-after-prefix-list.raw, which are FRR's own view of the policy.
#   r1-policy-change.raw is the vty transcript of the change, with its own stamp. events.log holds
#   the UTC time of the change. Also bgpd-version.txt, zebra-version.txt, the six daemon configs as
#   written, the daemon logs, and SHA256SUMS, which lists every kept file except poll-*.last, the
#   vty stderr files, failed captures, and SHA256SUMS itself.
# A JSON capture passes as in bgp-withdraw.sh. A text transcript passes only if it ends with CRLF
# and "r1# " in enable mode, has no "% " (FRR's mark for a rejected line), and shows the phase's
# configuration. The checks are in bgp-policy-check.py. No capture is normalized.
# A failed capture is kept as .raw.failed with no .collected_at. The run exits 1, and DONE is never printed.
set -u
S=${SCRATCH:?set SCRATCH to a directory holding frr-root/ (see README)}
P=${BGPD_VTY_PORT-}
if ! [[ $P =~ ^[1-9][0-9]{0,4}$ ]] || (( P > 65535 )) || (( P == 2604 || P == 2601 || P == 179 )); then
  echo "bgp-policy.sh: BGPD_VTY_PORT must be 1 to 65535 and not 2604 (ospfd), 2601 (zebra), or 179 (bgpd BGP), not '$P'" >&2
  exit 2
fi
HERE=$(cd "$(dirname "$0")" && pwd)
TCP=$HERE/tcpvty2.py
CHECK=$HERE/bgp-policy-check.py
FRR=$S/frr-root/usr/libexec/frr
OUT=$S/run/bgp-policy
export LD_LIBRARY_PATH="$S/frr-root/usr/lib64:$S/frr-root/usr/lib64/frr"
R2=
R3=
started=0

fail() { echo "bgp-policy.sh: $*" >&2; exit 1; }

# Refuse to run in the initial user namespace: the script mounts over /run and /etc and adds veth
# links, so the host must not run it.
read -r uid_in uid_out uid_n < /proc/self/uid_map || fail "could not read /proc/self/uid_map"
[[ "$uid_in $uid_out $uid_n" != "0 0 4294967295" ]] \
  || fail "run under unshare -Urnm: this is the initial user namespace"
mkdir -p "$S/run" && mkdir "$OUT" || fail "$OUT already exists or could not be created; this run never removes it"
"$FRR/bgpd" --version > "$OUT/bgpd-version.txt" 2>&1 || fail "bgpd --version failed"
"$FRR/zebra" --version > "$OUT/zebra-version.txt" 2>&1 || fail "zebra --version failed"

stop() {
  if (( started )); then cat /run/frr/r1/*.pid /run/frr/r2/*.pid /run/frr/r3/*.pid 2>/dev/null | xargs -r kill 2>/dev/null; fi
  started=0
  if [[ -n $R2 ]]; then kill "$R2" 2>/dev/null; R2=; fi
  if [[ -n $R3 ]]; then kill "$R3" 2>/dev/null; R3=; fi
}
cleanup() {
  local rc=$?
  stop
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

{ mount -t tmpfs tmpfs /run && mkdir -p /run/frr \
  && mount -t tmpfs tmpfs /var/lib && mkdir -p /var/lib/frr \
  && mount --bind "$HERE/etc/group" /etc/group \
  && mount --bind "$HERE/etc/passwd" /etc/passwd; } || fail "mount setup failed"

unshare -n sleep 3600 &
R2=$!
unshare -n sleep 3600 &
R3=$!
sleep 0.5
kill -0 "$R2" 2>/dev/null && kill -0 "$R3" 2>/dev/null || fail "namespace holders did not start"
in_r2() { nsenter -t "$R2" -n "$@"; }
in_r3() { nsenter -t "$R3" -n "$@"; }
{ ip link set lo up \
  && ip link add e1 type veth peer name e2 \
  && ip link set e2 netns "$R2" \
  && ip link add e3 type veth peer name e4 \
  && ip link set e4 netns "$R3" \
  && ip link set e1 up && ip addr add 10.0.1.1/24 dev e1 \
  && ip link set e3 up && ip addr add 10.0.3.1/24 dev e3 \
  && ip link add stub1 type dummy && ip link set stub1 up \
  && ip addr add 10.10.1.1/24 dev stub1; } || fail "r1 namespace setup failed"
{ in_r2 ip link set lo up \
  && in_r2 ip link set e2 up && in_r2 ip addr add 10.0.1.2/24 dev e2 \
  && in_r2 ip link add stub2 type dummy && in_r2 ip link set stub2 up \
  && in_r2 ip addr add 10.10.1.2/24 dev stub2 \
  && in_r2 ip addr add 10.10.2.2/24 dev stub2 \
  && in_r2 ip addr add 10.10.9.2/24 dev stub2; } || fail "r2 namespace setup failed"
{ in_r3 ip link set lo up \
  && in_r3 ip link set e4 up && in_r3 ip addr add 10.0.3.3/24 dev e4 \
  && in_r3 ip link add stub3 type dummy && in_r3 ip link set stub3 up \
  && in_r3 ip addr add 10.10.2.3/24 dev stub3 \
  && in_r3 ip addr add 10.10.3.3/24 dev stub3; } || fail "r3 namespace setup failed"

cat > "$OUT/r1-bgpd.conf" <<CONF || fail "could not write r1-bgpd.conf"
hostname r1
line vty
 no login
router bgp 65001
 bgp router-id 1.1.1.1
 no bgp ebgp-requires-policy
 neighbor 10.0.1.2 remote-as 65002
 neighbor 10.0.1.2 timers connect 5
 neighbor 10.0.3.3 remote-as 65003
 neighbor 10.0.3.3 timers connect 5
 address-family ipv4 unicast
  network 10.10.1.0/24
  neighbor 10.0.1.2 activate
  neighbor 10.0.3.3 activate
 exit-address-family
CONF
cat > "$OUT/r2-bgpd.conf" <<CONF || fail "could not write r2-bgpd.conf"
hostname r2
line vty
 no login
router bgp 65002
 bgp router-id 2.2.2.2
 no bgp ebgp-requires-policy
 neighbor 10.0.1.1 remote-as 65001
 neighbor 10.0.1.1 timers connect 5
 address-family ipv4 unicast
  network 10.10.1.0/24
  network 10.10.2.0/24
  network 10.10.9.0/24
  neighbor 10.0.1.1 activate
 exit-address-family
CONF
cat > "$OUT/r3-bgpd.conf" <<CONF || fail "could not write r3-bgpd.conf"
hostname r3
line vty
 no login
router bgp 65003
 bgp router-id 3.3.3.3
 no bgp ebgp-requires-policy
 neighbor 10.0.3.1 remote-as 65001
 neighbor 10.0.3.1 timers connect 5
 address-family ipv4 unicast
  network 10.10.2.0/24
  network 10.10.3.0/24
  neighbor 10.0.3.1 activate
 exit-address-family
CONF
: > "$OUT/r1-zebra.conf" && : > "$OUT/r2-zebra.conf" && : > "$OUT/r3-zebra.conf" || fail "could not write zebra configs"

alive() {
  local f=$1 i pid
  for ((i = 0; i < 50; i++)); do
    pid=$(cat "$f" 2>/dev/null)
    if [[ $pid =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null; then return 0; fi
    sleep 0.2
  done
  return 1
}

# start NODE NS: zebra, then bgpd, in namespace NS (self, or a holder pid).
start() {
  local node=$1 ns=$2 sock=/run/frr/$1
  mkdir -p "$sock" || return 1
  local -a at=()
  if [[ $ns != self ]]; then at=(nsenter -t "$ns" -n); fi
  "${at[@]}" "$FRR/zebra" -d -f "$OUT/$node-zebra.conf" -i "$sock/zebra.pid" -z "$sock/zserv.api" \
    --vty_socket "$sock" -u root -g root >> "$OUT/$node-daemons.log" 2>&1 || return 1
  "${at[@]}" "$FRR/bgpd" -d -f "$OUT/$node-bgpd.conf" -i "$sock/bgpd.pid" -z "$sock/zserv.api" \
    --vty_socket "$sock" -P "$P" -A 127.0.0.1 -u root -g root >> "$OUT/$node-daemons.log" 2>&1 || return 1
  alive "$sock/zebra.pid" && alive "$sock/bgpd.pid"
}

# query CMD FILE: one raw bgpd vty query on r1 into FILE. Stderr goes to FILE.err.
query() {
  timeout 30 python3 -I "$TCP" "$P" "$1" > "$2" 2> "$2.err"
}

# VTYCFG PORT LINE...: send each line to r1's bgpd vty in one TCP session, and print the bytes it
# returns after each line. A line goes out only after the output of the line before has drained.
VTYCFG='import socket,sys
s=socket.create_connection(("127.0.0.1",int(sys.argv[1])),timeout=5)
def drain(q):
    s.settimeout(q); buf=b""
    while True:
        try: c=s.recv(65536)
        except socket.timeout: break
        if not c: break
        buf+=c
    return buf
drain(1.5)
for line in sys.argv[2:]:
    s.sendall(line.encode()+b"\n")
    sys.stdout.buffer.write(drain(0.8))
s.close()
'

# vtyrun FILE LINE...: run VTYCFG with LINE... and keep its bytes, unmodified, in FILE.
vtyrun() {
  local f=$1
  shift
  timeout 120 python3 -I -c "$VTYCFG" "$P" "$@" > "$f" 2> "$f.err"
}

# event TEXT: one line in events.log with the UTC time.
event() {
  printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)" "$1" >> "$OUT/events.log" || fail "could not write events.log"
}

# cap PHASE CMD REQ...: one r1 JSON capture into $OUT/r1-PHASE-CMD.raw, checked by bgp-policy-check.py
# as json. A capture that fails is kept as .raw.failed with no .collected_at. The UTC stamp is taken
# before the vty connects and is written only after the checks pass.
cap() {
  local phase=$1 cmd=$2 base rc at
  shift 2
  base="$OUT/r1-$phase-${cmd// /_}"
  at=$(date -u +%Y-%m-%dT%H:%M:%S.%NZ) || return 1
  query "$cmd" "$base.raw"; rc=$?
  if (( rc == 0 )) && python3 -I "$CHECK" json "$cmd" "r1> " "$@" < "$base.raw" 2>/dev/null; then
    rm -f "$base.raw.err"
    if printf '%s\n' "$at" > "$base.collected_at"; then return 0; fi
    rm -f "$base.collected_at"
  fi
  mv -f "$base.raw" "$base.raw.failed" 2>/dev/null
  echo "bgp-policy.sh: capture r1 $phase $cmd failed (vty, framing, JSON, or content check)" >&2
  return 1
}

# captxt PHASE NAME LINE CHECK...: one vty session on r1 that sends "terminal length 0", "enable", and
# LINE, kept in $OUT/r1-PHASE-NAME.raw. bgp-policy-check.py checks it as text, with CHECK. A failed
# capture is kept as .raw.failed with no .collected_at, as for cap.
captxt() {
  local phase=$1 name=$2 line=$3 base at rc=0
  shift 3
  base="$OUT/r1-$phase-$name"
  at=$(date -u +%Y-%m-%dT%H:%M:%S.%NZ) || return 1
  vtyrun "$base.raw" "terminal length 0" "enable" "$line" || rc=$?
  if (( rc == 0 )) && python3 -I "$CHECK" text "r1# " "$@" < "$base.raw" 2>/dev/null; then
    rm -f "$base.raw.err"
    if printf '%s\n' "$at" > "$base.collected_at"; then return 0; fi
    rm -f "$base.collected_at"
  fi
  mv -f "$base.raw" "$base.raw.failed" 2>/dev/null
  echo "bgp-policy.sh: capture r1 $phase $name failed (vty or content check)" >&2
  return 1
}

# POLICY: the change, one vty command per line, in the order it is applied. The prefix-list and the
# route-map exist before the binding names them. "end" returns to enable mode, and the last line
# asks r1 to receive r3's paths again through the new inbound policy.
POLICY=(enable "configure terminal"
  "ip prefix-list P10-2 seq 5 permit 10.10.2.0/24"
  "route-map R3-IN permit 10" "match ip address prefix-list P10-2" "set weight 100" "exit"
  "route-map R3-IN permit 20" "exit"
  "router bgp 65001" "address-family ipv4 unicast" "neighbor 10.0.3.3 route-map R3-IN in" "exit-address-family" "exit"
  "end" "clear ip bgp 10.0.3.3 soft in")

# policy: apply POLICY on r1, and keep the transcript as r1-policy-change.raw. The transcript must echo
# the change, end at "r1# ", and have no "% " line.
policy() {
  local base="$OUT/r1-policy-change" at rc=0
  at=$(date -u +%Y-%m-%dT%H:%M:%S.%NZ) || return 1
  event "r1: route-map R3-IN permit 10 (prefix-list P10-2, set weight 100) and permit 20; neighbor 10.0.3.3 route-map R3-IN in; clear ip bgp 10.0.3.3 soft in"
  vtyrun "$base.raw" "${POLICY[@]}" || rc=$?
  if (( rc == 0 )) && python3 -I "$CHECK" text "r1# " "has:set weight 100" "has:clear ip bgp 10.0.3.3 soft in" < "$base.raw" 2>/dev/null; then
    rm -f "$base.raw.err"
    if printf '%s\n' "$at" > "$base.collected_at"; then return 0; fi
    rm -f "$base.collected_at"
  fi
  mv -f "$base.raw" "$base.raw.failed" 2>/dev/null
  echo "bgp-policy.sh: the policy change on r1 failed (vty or transcript check)" >&2
  return 1
}

# settle PHASE LIMIT STEP: poll r1's summary and table every STEP seconds for up to LIMIT seconds until
# the summary matches SUM and the table matches TAB. Then take the phase's captures: the summary, the
# table, both neighbor captures, and the running configuration, which must match CFG.
settle() {
  local phase=$1 limit=$2 step=$3 t0=$SECONDS ok=0
  while (( SECONDS - t0 < limit )); do
    if query "show ip bgp summary json" "$OUT/poll-r1-summary.last" \
      && python3 -I "$CHECK" json "show ip bgp summary json" "r1> " "${SUM[@]}" < "$OUT/poll-r1-summary.last" 2>/dev/null \
      && query "show ip bgp json" "$OUT/poll-r1-table.last" \
      && python3 -I "$CHECK" json "show ip bgp json" "r1> " "${TAB[@]}" < "$OUT/poll-r1-table.last" 2>/dev/null; then
      ok=1
      break
    fi
    sleep "$step"
  done
  (( ok )) || fail "r1 did not reach the $phase state within $limit seconds (see $OUT/poll-r1-*.last)"
  echo "$phase: settled after ~$((SECONDS - t0))s; taking captures"
  cap "$phase" "show ip bgp summary json" "${SUM[@]}" || fail "r1 $phase summary capture failed"
  cap "$phase" "show ip bgp json" "${TAB[@]}" || fail "r1 $phase table capture failed"
  cap "$phase" "show ip bgp neighbors 10.0.1.2 json" key:10.0.1.2 || fail "r1 $phase neighbor 10.0.1.2 capture failed"
  cap "$phase" "show ip bgp neighbors 10.0.3.3 json" key:10.0.3.3 || fail "r1 $phase neighbor 10.0.3.3 capture failed"
  captxt "$phase" running-config "show running-config" "${CFG[@]}" || fail "r1 $phase running configuration capture failed"
}

# sums: SHA256SUMS for every kept file in $OUT, except poll-*, the vty stderr files, failed captures,
# and SHA256SUMS itself. The list is in C collation, in the "hash  name" form of the committed
# SHA256SUMS files, and is read back with sha256sum -c before the run is done.
sums() {
  (
    export LC_ALL=C
    cd "$OUT" || exit 1
    for f in *; do
      case $f in poll-*|*.err|*.failed|SHA256SUMS) continue ;; esac
      sha256sum -- "$f"
    done > SHA256SUMS && sha256sum -c --quiet SHA256SUMS
  ) || fail "could not write or verify SHA256SUMS in $OUT"
}

started=1
start r1 self || fail "r1 daemons did not start"
start r2 "$R2" || fail "r2 daemons did not start"
start r3 "$R3" || fail "r3 daemons did not start"
echo "daemons started"

# Before the change: both sessions Established, and the table as the withdrawal run's before phase
# recorded it. The running configuration has no policy. Its anchors, r1's BGP instance and network
# statement, keep an empty transcript from passing the "lacks" terms.
SUM=(est:10.0.1.2 est:10.0.3.3)
PATHS=(paths:10.10.1.0/24='(unspec)',10.0.1.2 paths:10.10.2.0/24=10.0.1.2,10.0.3.3
  paths:10.10.3.0/24=10.0.3.3 paths:10.10.9.0/24=10.0.1.2)
TAB=("${PATHS[@]}" best:10.10.1.0/24='(unspec)' best:10.10.2.0/24=10.0.1.2
  best:10.10.3.0/24=10.0.3.3 best:10.10.9.0/24=10.0.1.2)
CFG=("has:router bgp 65001" "inaf:network 10.10.1.0/24"
  "lacks:route-map R3-IN" "lacks:neighbor 10.0.3.3 route-map R3-IN in")
settle before 120 2

policy || fail "the policy change on r1 failed"

# After the change: the same peers and prefixes, with the same peerId sets. Only 10.10.2.0/24 moves
# its bestpath, to r3's path, which now carries weight 100. The other paths keep weight 0, as in the
# before capture. The running configuration shows the policy, with the binding inside the IPv4
# unicast address family.
echo "policy: applied; settling"
TAB=("${PATHS[@]}" best:10.10.1.0/24='(unspec)' best:10.10.2.0/24=10.0.3.3
  best:10.10.3.0/24=10.0.3.3 best:10.10.9.0/24=10.0.1.2 weight:10.10.2.0/24=10.0.3.3=100
  weight:10.10.2.0/24=10.0.1.2=0 weight:10.10.3.0/24=10.0.3.3=0)
CFG=("has:router bgp 65001" "inaf:network 10.10.1.0/24"
  "has:ip prefix-list P10-2 seq 5 permit 10.10.2.0/24" "has:route-map R3-IN permit 10"
  "has:match ip address prefix-list P10-2" "has:set weight 100" "has:route-map R3-IN permit 20"
  "inaf:neighbor 10.0.3.3 route-map R3-IN in")
settle after 120 2
captxt after route-map "show route-map" "has:R3-IN" || fail "r1 route-map capture failed"
captxt after prefix-list "show ip prefix-list" "has:P10-2" || fail "r1 prefix-list capture failed"
echo "--- stopping"
stop
sleep 1
sums
echo DONE
