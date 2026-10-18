#!/bin/bash
# Local three-router FRR 10.7.0 OSPF adjacency-loss lab, one arm per run, inside user+mount+net
# namespaces. Every link is a veth pair set to "ip ospf network point-to-point" in area 0.0.0.0:
#   r1 e1 10.0.1.1/24 to r2 e2 10.0.1.2/24
#   r1 e3 10.0.3.1/24 to r2 e4 10.0.3.2/24
#   r1 e5 10.0.5.1/24 to r3 e6 10.0.5.2/24
#   backup arm only: r2 e7 10.0.7.1/24 to r3 e8 10.0.7.2/24, "ip ospf cost 100" on both ends
# r2 holds stub2 10.10.2.1/24 and r3 holds stub3 10.10.3.1/24, each a passive OSPF interface. r3
# also holds static3 10.30.0.1/24, which no OSPF network statement covers, and r1 reaches it by
# "ip route add 10.30.0.0/24 via 10.0.5.2 dev e5 proto static". Router IDs are 1.1.1.1, 2.2.2.2,
# and 3.3.3.3. Every node sets net.ipv4.ip_forward to 1.
# ARM selects the topology and the adjacency that r1 loses:
#   ecmp:   no r2-r3 link. r1 loses its adjacency with r2 on e1, and keeps the one on e3.
#   single: no r2-r3 link. r1 loses its adjacency with r3 on e5, its only one with r3.
#   backup: the r2-r3 link is up. r1 loses its adjacency with r3 on e5.
# The fault is a tc clsact filter on r1's interface that drops IP protocol 89 (OSPF) in both
# directions. Nothing else is filtered, and no link, address, route, or daemon is touched, so the
# link stays up and only OSPF packets on it are lost. Both neighbors then time out on their own.
# Run as: SCRATCH=<dir> ARM=ecmp|single|backup unshare -Urnm bash ospf-adjacency.sh
#   SCRATCH must hold frr-root/ extracted from the FRR 10.7.0 RPM (see ../README.md).
# Output goes to $SCRATCH/run/ospf-adjacency-$ARM, which must not exist. The run never removes anything.
#   For each phase (before, after) and node: <node>-<phase>-<command>.raw for "show ip ospf
#   neighbor detail json", "show ip ospf interface json", and "show ip ospf route json", and
#   <node>-<phase>-ip_addr.json, -ip_route.json, and -ip_link.json, the output of "ip -j -4 addr
#   show", "ip -j -4 route show table main", and "ip -j link show" in that node's namespace. Each
#   has a .collected_at UTC stamp taken before the command ran. r1-<phase>-probes.json holds, for
#   every IPv4 address any node holds, "ip -j route get" and a three-packet ping from r1. After the
#   fault, r1-after-tc_<ingress|egress>.json hold "tc -s -j filter show" with the drop counters.
#   Also ospfd-version.txt, zebra-version.txt, sysctl.txt, the daemon configs as written, the
#   daemon logs, and events.log (UTC times of each fault command and of each settled state). poll-*.last
#   hold the last poll outputs.
# Each wait is bounded. A run that times out, or whose capture fails, exits 1 naming the step,
# keeps a failed capture as .raw.failed or .json.failed with no .collected_at, and never prints DONE.
set -u
S=${SCRATCH:?set SCRATCH to a directory holding frr-root/ (see README)}
A=${ARM-}
case $A in
  ecmp) FAULT_IF=e1 PEER=r2 PEER_IF=e2 ;;
  single | backup) FAULT_IF=e5 PEER=r3 PEER_IF=e6 ;;
  *) echo "ospf-adjacency.sh: ARM must be ecmp, single, or backup, not '$A'" >&2; exit 2 ;;
esac
HERE=$(cd "$(dirname "$0")" && pwd)
TCP=$HERE/tcpvty2.py
FRR=$S/frr-root/usr/libexec/frr
OUT=$S/run/ospf-adjacency-$A
export LD_LIBRARY_PATH="$S/frr-root/usr/lib64:$S/frr-root/usr/lib64/frr"
export TZ=UTC
R2=
R3=
started=0

fail() { echo "ospf-adjacency.sh: $*" >&2; exit 1; }

# Refuse to run in the initial user namespace: the script mounts over /run and /etc and adds links.
read -r uid_in uid_out uid_n < /proc/self/uid_map || fail "could not read /proc/self/uid_map"
[[ "$uid_in $uid_out $uid_n" != "0 0 4294967295" ]] \
  || fail "run under unshare -Urnm: this is the initial user namespace"
mkdir -p "$S/run" && mkdir "$OUT" || fail "$OUT already exists or could not be created; this run never removes it"
"$FRR/ospfd" --version > "$OUT/ospfd-version.txt" 2>&1 || fail "ospfd --version failed"
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
# at NODE CMD...: run CMD in NODE's namespace.
at() {
  local n=$1; shift
  case $n in
    r1) "$@" ;;
    r2) nsenter -t "$R2" -n "$@" ;;
    r3) nsenter -t "$R3" -n "$@" ;;
  esac
}
NODES=(r1 r2 r3)
{ ip link set lo up \
  && ip link add name e1 type veth peer name e2 && ip link set e2 netns "$R2" \
  && ip link add name e3 type veth peer name e4 && ip link set e4 netns "$R2" \
  && ip link add name e5 type veth peer name e6 && ip link set e6 netns "$R3" \
  && ip link set e1 up && ip addr add 10.0.1.1/24 dev e1 \
  && ip link set e3 up && ip addr add 10.0.3.1/24 dev e3 \
  && ip link set e5 up && ip addr add 10.0.5.1/24 dev e5; } || fail "r1 namespace setup failed"
{ at r2 ip link set lo up \
  && at r2 ip link set e2 up && at r2 ip addr add 10.0.1.2/24 dev e2 \
  && at r2 ip link set e4 up && at r2 ip addr add 10.0.3.2/24 dev e4 \
  && at r2 ip link add name stub2 type dummy && at r2 ip link set stub2 up \
  && at r2 ip addr add 10.10.2.1/24 dev stub2; } || fail "r2 namespace setup failed"
{ at r3 ip link set lo up \
  && at r3 ip link set e6 up && at r3 ip addr add 10.0.5.2/24 dev e6 \
  && at r3 ip link add name stub3 type dummy && at r3 ip link set stub3 up \
  && at r3 ip addr add 10.10.3.1/24 dev stub3 \
  && at r3 ip link add name static3 type dummy && at r3 ip link set static3 up \
  && at r3 ip addr add 10.30.0.1/24 dev static3; } || fail "r3 namespace setup failed"
if [[ $A == backup ]]; then
  { at r2 ip link add name e7 type veth peer name e8 && at r2 ip link set e8 netns "$R3" \
    && at r2 ip link set e7 up && at r2 ip addr add 10.0.7.1/24 dev e7 \
    && at r3 ip link set e8 up && at r3 ip addr add 10.0.7.2/24 dev e8; } || fail "r2-r3 link setup failed"
fi
ip route add 10.30.0.0/24 via 10.0.5.2 dev e5 proto static || fail "r1 static route failed"
for n in "${NODES[@]}"; do
  at "$n" sysctl -q -w net.ipv4.ip_forward=1 || fail "$n ip_forward failed"
  { echo "# $n"; at "$n" sysctl net.ipv4.ip_forward net.ipv4.conf.all.rp_filter net.ipv4.conf.default.rp_filter; } >> "$OUT/sysctl.txt" \
    || fail "$n sysctl record failed"
done

P2P=' ip ospf network point-to-point'
COST=' ip ospf cost 100'
{ printf 'hostname r1\nline vty\n no login\n'
  for i in e1 e3 e5; do printf 'interface %s\n%s\n' "$i" "$P2P"; done
  printf 'router ospf\n ospf router-id 1.1.1.1\n'
  printf ' network %s area 0.0.0.0\n' 10.0.1.0/24 10.0.3.0/24 10.0.5.0/24
} > "$OUT/r1-ospfd.conf" || fail "could not write r1-ospfd.conf"
{ printf 'hostname r2\nline vty\n no login\n'
  for i in e2 e4; do printf 'interface %s\n%s\n' "$i" "$P2P"; done
  if [[ $A == backup ]]; then printf 'interface e7\n%s\n%s\n' "$P2P" "$COST"; fi
  printf 'router ospf\n ospf router-id 2.2.2.2\n passive-interface stub2\n'
  printf ' network %s area 0.0.0.0\n' 10.0.1.0/24 10.0.3.0/24 10.10.2.0/24
  if [[ $A == backup ]]; then printf ' network 10.0.7.0/24 area 0.0.0.0\n'; fi
} > "$OUT/r2-ospfd.conf" || fail "could not write r2-ospfd.conf"
{ printf 'hostname r3\nline vty\n no login\n'
  printf 'interface e6\n%s\n' "$P2P"
  if [[ $A == backup ]]; then printf 'interface e8\n%s\n%s\n' "$P2P" "$COST"; fi
  printf 'router ospf\n ospf router-id 3.3.3.3\n passive-interface stub3\n'
  printf ' network %s area 0.0.0.0\n' 10.0.5.0/24 10.10.3.0/24
  if [[ $A == backup ]]; then printf ' network 10.0.7.0/24 area 0.0.0.0\n'; fi
} > "$OUT/r3-ospfd.conf" || fail "could not write r3-ospfd.conf"
for n in "${NODES[@]}"; do : > "$OUT/$n-zebra.conf" || fail "could not write $n-zebra.conf"; done

alive() {
  local f=$1 i pid
  for ((i = 0; i < 50; i++)); do
    pid=$(cat "$f" 2>/dev/null)
    if [[ $pid =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null; then return 0; fi
    sleep 0.2
  done
  return 1
}

# start NODE: zebra, then ospfd, in NODE's namespace. Socket paths must fit sun_path, so each node
# gets a short directory under the run's private /run tmpfs.
start() {
  local n=$1 sock=/run/frr/$1
  mkdir -p "$sock" || return 1
  at "$n" "$FRR/zebra" -d -f "$OUT/$n-zebra.conf" -i "$sock/zebra.pid" -z "$sock/zserv.api" \
    --vty_socket "$sock" -u root -g root >> "$OUT/$n-daemons.log" 2>&1 || return 1
  at "$n" "$FRR/ospfd" -d -f "$OUT/$n-ospfd.conf" -i "$sock/ospfd.pid" -z "$sock/zserv.api" \
    --vty_socket "$sock" -u root -g root >> "$OUT/$n-daemons.log" 2>&1 || return 1
  alive "$sock/zebra.pid" && alive "$sock/ospfd.pid"
}

# VTYOK FILE CMD NODE: exit 0 only if FILE is the echoed CMD, CRLF, one JSON object, CRLF, and
# NODE's "> " prompt with nothing after it.
VTYOK='import json,sys
b=open(sys.argv[1],"rb").read()
head=sys.argv[2].encode()+b"\r\n"
tail=b"\r\n"+sys.argv[3].encode()+b"> "
if len(b)<len(head)+len(tail) or not b.startswith(head) or not b.endswith(tail): sys.exit(1)
sys.exit(0 if isinstance(json.loads(b[len(head):len(b)-len(tail)].decode("utf-8")),dict) else 1)'

# NBR FILE MODE: read a framed "show ip ospf neighbor json". MODE full:N exits 0 when exactly N
# neighbors are Full. MODE gone:IF exits 0 when no neighbor on interface IF is Full.
NBR='import json,sys
t=open(sys.argv[1]).read()
d=json.loads(t[t.index("{"):t.rindex("}")+1])
ns=[n for v in d.get("neighbors",{}).values() for n in v]
full=[n for n in ns if str(n.get("nbrState","")).startswith("Full")]
op,_,arg=sys.argv[2].partition(":")
if op=="full": sys.exit(0 if len(full)==int(arg) else 1)
sys.exit(0 if not any(str(n.get("ifaceName","")).split(":")[0]==arg for n in full) else 1)'

# stamp: the UTC time, before a command runs.
stamp() { date -u +%Y-%m-%dT%H:%M:%S.%NZ; }

# vtycap NODE PHASE CMD: one framed vty capture into $OUT/NODE-PHASE-CMD.raw.
vtycap() {
  local n=$1 phase=$2 cmd=$3 base t rc
  base="$OUT/$n-$phase-${cmd// /_}"
  t=$(stamp) || return 1
  at "$n" timeout 30 python3 -I "$TCP" 2604 "$cmd" > "$base.raw" 2> "$base.raw.err"; rc=$?
  if (( rc == 0 )) && python3 -I -c "$VTYOK" "$base.raw" "$cmd" "$n" 2>/dev/null; then
    rm -f "$base.raw.err"
    printf '%s\n' "$t" > "$base.collected_at" && return 0
  fi
  rm -f "$base.collected_at"
  mv -f "$base.raw" "$base.raw.failed" 2>/dev/null
  echo "ospf-adjacency.sh: capture $n $phase $cmd failed (status $rc, or not one framed JSON object)" >&2
  return 1
}

# ipcap NODE PHASE NAME ARGS...: "ip -j ARGS" in NODE's namespace into $OUT/NODE-PHASE-NAME.json,
# which must be one JSON array.
ipcap() {
  local n=$1 phase=$2 name=$3 base t
  shift 3
  base="$OUT/$n-$phase-$name"
  t=$(stamp) || return 1
  if at "$n" ip -j "$@" > "$base.json" 2> "$base.json.err" \
    && python3 -I -c 'import json,sys; sys.exit(0 if isinstance(json.load(open(sys.argv[1])),list) else 1)' "$base.json"; then
    rm -f "$base.json.err"
    printf '%s\n' "$t" > "$base.collected_at" && return 0
  fi
  rm -f "$base.collected_at"
  mv -f "$base.json" "$base.json.failed" 2>/dev/null
  echo "ospf-adjacency.sh: capture $n $phase $name failed" >&2
  return 1
}

# PROBES OUT ADDR_FILE...: for every IPv4 address the addr captures hold, other than on lo, "ip -j
# route get" and "ping -n -c 3 -i 0.2 -W 1" from this namespace, as one JSON array in OUT. Each
# command is bounded by a 10 second timeout. Nothing is graded here.
PROBES='import datetime,json,subprocess,sys
dests=set()
for f in sys.argv[2:]:
    for l in json.load(open(f)):
        if l.get("ifname")=="lo": continue
        for a in l.get("addr_info",[]):
            if a.get("family")=="inet": dests.add(a["local"])
def run(argv):
    try:
        p=subprocess.run(argv,capture_output=True,text=True,timeout=10)
        return p.returncode,p.stdout+p.stderr
    except subprocess.TimeoutExpired:
        return None,"timeout"
out=[]
for d in sorted(dests,key=lambda s:tuple(int(x) for x in s.split("."))):
    at=datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    rc,rg=run(["ip","-j","route","get",d])
    prc,pout=run(["ping","-n","-c","3","-i","0.2","-W","1",d])
    out.append({"destination":d,"collected_at":at,"route_get_exit":rc,"route_get":json.loads(rg) if rc==0 else rg,"ping_exit":prc,"ping_output":pout})
json.dump(out,open(sys.argv[1],"w"),indent=1)
open(sys.argv[1],"a").write("\n")'

# capture PHASE: every capture of the phase, then r1's probes.
capture() {
  local phase=$1 n c
  for n in "${NODES[@]}"; do
    for c in "show ip ospf neighbor detail json" "show ip ospf interface json" "show ip ospf route json"; do
      vtycap "$n" "$phase" "$c" || return 1
    done
    ipcap "$n" "$phase" ip_addr -4 addr show || return 1
    ipcap "$n" "$phase" ip_route -4 route show table main || return 1
    ipcap "$n" "$phase" ip_link link show || return 1
  done
  timeout 120 python3 -I -c "$PROBES" "$OUT/r1-$phase-probes.json" "$OUT"/r?-before-ip_addr.json \
    || { echo "ospf-adjacency.sh: r1 $phase probes failed" >&2; return 1; }
}

# event TEXT: one line in events.log with the UTC time.
event() {
  printf '%s %s\n' "$(stamp)" "$1" >> "$OUT/events.log" || fail "could not write events.log"
}

# nbr NODE MODE: poll NODE's "show ip ospf neighbor json" once and check it with NBR.
nbr() {
  local f="$OUT/poll-$1-neighbor.last"
  at "$1" timeout 30 python3 -I "$TCP" 2604 "show ip ospf neighbor json" > "$f" 2>&1 \
    && python3 -I -c "$NBR" "$f" "$2" 2>/dev/null
}

# tables: every node's main table, in node order.
tables() {
  local n
  for n in "${NODES[@]}"; do at "$n" ip -4 route show table main || return 1; done
}

# settle NAME LIMIT CHECK...: poll every 2 seconds for up to LIMIT seconds until each CHECK, a
# "NODE MODE" pair for nbr, holds, and then until the three main tables are unchanged over five
# polls in a row. A timeout names which wait ran out, and exits 1.
settle() {
  local name=$1 limit=$2 t0=$SECONDS ok=0 c prev="" cur same=0
  shift 2
  while (( SECONDS - t0 < limit )); do
    ok=1
    for c in "$@"; do
      # shellcheck disable=SC2086 # c is "NODE MODE", split on purpose
      nbr $c || { ok=0; break; }
    done
    (( ok )) && break
    sleep 2
  done
  (( ok )) || fail "timeout: the neighbor states for $name did not hold within $limit seconds (see $OUT/poll-*-neighbor.last)"
  event "$name: neighbor states hold after ~$((SECONDS - t0))s"
  t0=$SECONDS
  while (( SECONDS - t0 < 60 )); do
    cur=$(tables) || fail "could not read the main tables"
    if [[ $cur == "$prev" ]]; then ((same++)); else same=0; prev=$cur; fi
    (( same >= 4 )) && break
    sleep 2
  done
  printf '%s\n' "$cur" > "$OUT/poll-tables.last"
  (( same >= 4 )) || fail "timeout: the main tables for $name did not hold still within 60 seconds (see $OUT/poll-tables.last)"
  event "$name: main tables unchanged over five polls"
}

started=1
for n in "${NODES[@]}"; do start "$n" || fail "$n daemons did not start"; done
echo "daemons started"

if [[ $A == backup ]]; then
  settle before 120 "r1 full:3" "r2 full:3" "r3 full:2"
else
  settle before 120 "r1 full:3" "r2 full:2" "r3 full:1"
fi
capture before || fail "before captures failed"

# fault CMD...: one line in events.log naming CMD, then CMD in r1's namespace.
fault() { event "r1: $*"; "$@"; }
{ fault tc qdisc add dev "$FAULT_IF" clsact \
  && fault tc filter add dev "$FAULT_IF" ingress protocol ip pref 1 u32 match ip protocol 89 0xff action drop \
  && fault tc filter add dev "$FAULT_IF" egress protocol ip pref 1 u32 match ip protocol 89 0xff action drop; } \
  || fail "could not install the OSPF drop filter on r1 $FAULT_IF"

settle after 120 "r1 gone:$FAULT_IF" "$PEER gone:$PEER_IF"
capture after || fail "after captures failed"
for d in ingress egress; do
  { tc -s -j filter show dev "$FAULT_IF" "$d" > "$OUT/r1-after-tc_$d.json" \
    && python3 -I -c 'import json,sys; sys.exit(0 if isinstance(json.load(open(sys.argv[1])),list) else 1)' "$OUT/r1-after-tc_$d.json"; } \
    || fail "could not read the $d filter"
done
echo "--- stopping"
stop
echo DONE
