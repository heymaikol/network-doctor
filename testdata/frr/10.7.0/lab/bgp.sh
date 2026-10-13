#!/bin/bash
# Local two-router FRR 10.7.0 BGP lab, one run, inside user+mount+net namespaces.
# r1 (AS 65001, router ID 1.1.1.1) peers with r2 (AS 65002, router ID 2.2.2.2) at 10.0.1.2.
# r1 also has a peer at 10.0.1.3 that does not exist. r2 originates 10.10.2.0/24 from a
# connected dummy stub. Only zebra and bgpd run. No host network change.
# Run as: SCRATCH=<dir> BGPD_VTY_PORT=<port> unshare -Urnm bash bgp.sh
#   SCRATCH must hold frr-root/ extracted from the FRR 10.7.0 RPM (see ../README.md).
#   BGPD_VTY_PORT is bgpd's vty TCP port, passed as -P. It must be 1 to 65535 and not 2604
#   (ospfd), 2601 (zebra's default vty), or 179 (bgpd's BGP listener). -p is not passed, so
#   BGP listens on 179 in each namespace.
# Output goes to $SCRATCH/run/bgp, which must not exist. The run never removes anything.
#   r1 and r2 each get <node>-show_ip_bgp_summary_json.raw and <node>-show_ip_bgp_json.raw,
#   with a .collected_at UTC stamp. Also kept: bgpd-version.txt, zebra-version.txt, the four
#   daemon configs as written, and the daemon logs. poll-*.last hold the r1 polls.
# A capture passes only if its bytes are the echoed command, CRLF, one strict JSON object, CRLF,
# and the node's "rN> " prompt, and its content shows the configured state: r1 has 10.0.1.2
# Established and 10.0.1.3 listed but not Established, r2 has 10.0.1.1 Established, and both
# tables hold 10.10.2.0/24. Only those peer addresses, that prefix, and the state value are matched.
# A failed capture is kept as .raw.failed with no .collected_at. The run exits 1, and DONE is never printed.
set -u
S=${SCRATCH:?set SCRATCH to a directory holding frr-root/ (see README)}
P=${BGPD_VTY_PORT-}
if ! [[ $P =~ ^[1-9][0-9]{0,4}$ ]] || (( P > 65535 )) || (( P == 2604 || P == 2601 || P == 179 )); then
  echo "bgp.sh: BGPD_VTY_PORT must be 1 to 65535 and not 2604 (ospfd), 2601 (zebra), or 179 (bgpd BGP), not '$P'" >&2
  exit 2
fi
HERE=$(cd "$(dirname "$0")" && pwd)
TCP=$HERE/tcpvty2.py
FRR=$S/frr-root/usr/libexec/frr
OUT=$S/run/bgp
export LD_LIBRARY_PATH="$S/frr-root/usr/lib64:$S/frr-root/usr/lib64/frr"
R2=
started=0

fail() { echo "bgp.sh: $*" >&2; exit 1; }

# Refuse to run in the initial user namespace: the script mounts over /run and /etc and adds veth
# links, so the host must not run it. Host root and an unshared user without a map both have the
# identity map there. Outside unshare -Urnm, the mounts and links then fail with EPERM.
read -r uid_in uid_out uid_n < /proc/self/uid_map || fail "could not read /proc/self/uid_map"
[[ "$uid_in $uid_out $uid_n" != "0 0 4294967295" ]] \
  || fail "run under unshare -Urnm: this is the initial user namespace"
# mkdir without -p on OUT: any existing path, including a dangling symlink, is refused.
mkdir -p "$S/run" && mkdir "$OUT" || fail "$OUT already exists or could not be created; this run never removes it"
"$FRR/bgpd" --version > "$OUT/bgpd-version.txt" 2>&1 || fail "bgpd --version failed"
"$FRR/zebra" --version > "$OUT/zebra-version.txt" 2>&1 || fail "zebra --version failed"

# stop kills the daemons this run started and the namespace holder. It runs once. Pid files are
# read only after the first daemon starts, so an early failure never signals a stale pid.
stop() {
  if (( started )); then cat /run/frr/r1/*.pid /run/frr/r2/*.pid 2>/dev/null | xargs -r kill 2>/dev/null; fi
  started=0
  if [[ -n $R2 ]]; then kill "$R2" 2>/dev/null; R2=; fi
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
sleep 0.5
kill -0 "$R2" 2>/dev/null || fail "namespace holder did not start"
{ ip link set lo up \
  && ip link add e1 type veth peer name e2 \
  && ip link set e2 netns "$R2" \
  && ip link set e1 up \
  && ip addr add 10.0.1.1/24 dev e1; } || fail "r1 namespace setup failed"
in_r2() { nsenter -t "$R2" -n "$@"; }
{ in_r2 ip link set lo up \
  && in_r2 ip link set e2 up \
  && in_r2 ip addr add 10.0.1.2/24 dev e2 \
  && in_r2 ip link add stub2 type dummy \
  && in_r2 ip link set stub2 up \
  && in_r2 ip addr add 10.10.2.1/24 dev stub2; } || fail "r2 namespace setup failed"

cat > "$OUT/r1-bgpd.conf" <<CONF || fail "could not write r1-bgpd.conf"
hostname r1
line vty
 no login
router bgp 65001
 bgp router-id 1.1.1.1
 no bgp ebgp-requires-policy
 neighbor 10.0.1.2 remote-as 65002
 neighbor 10.0.1.2 timers connect 5
 neighbor 10.0.1.3 remote-as 65003
 neighbor 10.0.1.3 timers connect 5
 address-family ipv4 unicast
  neighbor 10.0.1.2 activate
  neighbor 10.0.1.3 activate
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
  network 10.10.2.0/24
  neighbor 10.0.1.1 activate
 exit-address-family
CONF
: > "$OUT/r1-zebra.conf" && : > "$OUT/r2-zebra.conf" || fail "could not write zebra configs"

# alive FILE: the daemon that wrote pid file FILE holds a live pid within about ten seconds.
alive() {
  local f=$1 i pid
  for ((i = 0; i < 50; i++)); do
    pid=$(cat "$f" 2>/dev/null)
    if [[ $pid =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null; then return 0; fi
    sleep 0.2
  done
  return 1
}

# start NODE NS: zebra, then bgpd, in namespace NS (self, or the holder pid). Unix socket
# paths must fit sun_path (108 bytes), so each node uses /run/frr/NODE on the run's tmpfs.
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

# query NS CMD FILE: one raw bgpd vty query into FILE. NS is self or the holder pid. Stderr
# goes to FILE.err, which a passing capture removes.
query() {
  local ns=$1 cmd=$2 f=$3
  if [[ $ns = self ]]; then timeout 30 python3 -I "$TCP" "$P" "$cmd" > "$f" 2> "$f.err"
  else timeout 30 nsenter -t "$ns" -n python3 -I "$TCP" "$P" "$cmd" > "$f" 2> "$f.err"; fi
}

# BGPOK FILE CMD NODE REQ...: exit 0 only if FILE is the echoed CMD, CRLF, one strict JSON object,
# CRLF, and NODE's "> " prompt with nothing after it. Duplicate keys, NaN, and Infinity fail.
# A REQ is op:key. est: a dict under key has a direct value "Established". notest: key is present
# and no dict under it has "Established". key: key is present. Other fields are never read.
BGPOK='import json,sys
def bad(c): raise ValueError(c)
def pairs(p):
    d={}
    for k,v in p:
        if k in d: bad("duplicate key")
        d[k]=v
    return d
def find(o,k):
    if isinstance(o,dict):
        for kk,v in o.items():
            if kk==k: yield v
            yield from find(v,k)
    elif isinstance(o,list):
        for v in o: yield from find(v,k)
def est(o,k):
    return any(isinstance(v,dict) and "Established" in v.values() for v in find(o,k))
f,cmd,node=sys.argv[1:4]
b=open(f,"rb").read()
head=cmd.encode()+b"\r\n"
tail=b"\r\n"+node.encode()+b"> "
if len(b)<len(head)+len(tail) or not b.startswith(head) or not b.endswith(tail): sys.exit(1)
d=json.loads(b[len(head):len(b)-len(tail)].decode("utf-8"),object_pairs_hook=pairs,parse_constant=bad)
if not isinstance(d,dict): sys.exit(1)
for r in sys.argv[4:]:
    op,_,k=r.partition(":")
    vals=list(find(d,k))
    if op=="est": good=est(d,k)
    elif op=="notest": good=bool(vals) and not est(d,k)
    elif op=="key": good=bool(vals)
    else: good=False
    if not good: sys.exit(1)
'

# cap NS NODE CMD REQ...: one bgpd capture into $OUT/NODE-CMD.raw, checked by BGPOK with the REQ
# terms. A capture that fails is kept as .raw.failed with no .collected_at. The UTC stamp is taken
# before the vty connects and is written only after the checks pass.
cap() {
  local ns=$1 node=$2 cmd=$3 base rc at
  shift 3
  base="$OUT/$node-${cmd// /_}"
  at=$(date -u +%Y-%m-%dT%H:%M:%S.%NZ) || return 1
  query "$ns" "$cmd" "$base.raw"; rc=$?
  if (( rc == 0 )) && python3 -I -c "$BGPOK" "$base.raw" "$cmd" "$node" "$@" 2>/dev/null; then
    rm -f "$base.raw.err"
    if printf '%s\n' "$at" > "$base.collected_at"; then return 0; fi
    rm -f "$base.collected_at"
  fi
  mv -f "$base.raw" "$base.raw.failed" 2>/dev/null
  echo "bgp.sh: capture $node $cmd failed (vty, framing, JSON, or content check)" >&2
  return 1
}

SUM_R1=(est:10.0.1.2 notest:10.0.1.3)
SUM_R2=(est:10.0.1.1)
TABLE=(key:10.10.2.0/24)

started=1
start r1 self || fail "r1 daemons did not start"
start r2 "$R2" || fail "r2 daemons did not start"
echo "daemons started; waiting for r1 to reach Established with 10.10.2.0/24"

# Poll r1 for up to 120 seconds. Each poll output is kept as poll-*.last.
converged=0
t0=$SECONDS
while (( SECONDS - t0 < 120 )); do
  if query self "show ip bgp summary json" "$OUT/poll-r1-summary.last" \
    && python3 -I -c "$BGPOK" "$OUT/poll-r1-summary.last" "show ip bgp summary json" r1 "${SUM_R1[@]}" 2>/dev/null \
    && query self "show ip bgp json" "$OUT/poll-r1-table.last" \
    && python3 -I -c "$BGPOK" "$OUT/poll-r1-table.last" "show ip bgp json" r1 "${TABLE[@]}" 2>/dev/null; then
    converged=1
    break
  fi
  sleep 2
done
(( converged )) || fail "r1 did not reach Established with 10.10.2.0/24 within 120 seconds (see $OUT/poll-r1-*.last)"
echo "converged after ~$((SECONDS - t0))s; taking captures"

# The final captures recheck each node, since a session can flap after the poll.
cap self r1 "show ip bgp summary json" "${SUM_R1[@]}" || fail "r1 summary capture failed"
cap self r1 "show ip bgp json" "${TABLE[@]}" || fail "r1 table capture failed"
cap "$R2" r2 "show ip bgp summary json" "${SUM_R2[@]}" || fail "r2 summary capture failed"
cap "$R2" r2 "show ip bgp json" "${TABLE[@]}" || fail "r2 table capture failed"
echo "--- killing"
stop
echo DONE
