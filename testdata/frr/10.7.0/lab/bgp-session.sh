#!/bin/bash
# Local three-router FRR 10.7.0 BGP session-loss lab, one arm per run, inside user+mount+net
# namespaces. The routers, addresses, and network statements are those of bgp-withdraw.sh:
# r1 (AS 65001, 1.1.1.1) peers with r2 (AS 65002, 2.2.2.2) at 10.0.1.2 and with r3 (AS 65003,
# 3.3.3.3) at 10.0.3.3. Each router originates prefixes from addresses on a dummy stub:
#   r1: 10.10.1.0/24
#   r2: 10.10.1.0/24, 10.10.2.0/24, 10.10.9.0/24
#   r3: 10.10.2.0/24, 10.10.3.0/24
# ARM selects how r1 loses its session with r2, and which phases are captured on r1:
#   plain: FRR defaults. SIGKILL r2's bgpd. Phases: before, after.
#   gr:    r2 adds "bgp graceful-restart" and "bgp graceful-restart restart-time 30". SIGKILL r2's
#          bgpd, which is not restarted. Phases: before, during (r2's paths still listed, each
#          marked stale), expired (the restart timer has run out).
#   admin: r2 configured as in gr. r1 applies "neighbor 10.0.1.2 shutdown". Phases: before, after.
# SIGKILL leaves the link and r2's zebra up, so the change is the BGP session alone.
# Only zebra and bgpd run. No host network change.
# Run as: SCRATCH=<dir> BGPD_VTY_PORT=<port> ARM=plain|gr|admin unshare -Urnm bash bgp-session.sh
#   SCRATCH must hold frr-root/ extracted from the FRR 10.7.0 RPM (see ../README.md).
#   BGPD_VTY_PORT is bgpd's vty TCP port, passed as -P. It must be 1 to 65535 and not 2604
#   (ospfd), 2601 (zebra's default vty), or 179 (bgpd's BGP listener).
# Output goes to $SCRATCH/run/bgp-session-$ARM, which must not exist. The run never removes anything.
#   For each phase: r1-<phase>-show_ip_bgp_summary_json.raw, r1-<phase>-show_ip_bgp_json.raw,
#   r1-<phase>-show_ip_bgp_neighbors_10.0.1.2_json.raw, and r1-<phase>-ip_route.json (the output
#   of "ip -j -4 route show" in r1's namespace, kept as lab context only), each with a
#   .collected_at UTC stamp. Also bgpd-version.txt, zebra-version.txt, the six daemon configs as
#   written, the daemon logs, events.log (the UTC time of the failure), and for admin the vty
#   transcript of the shutdown (r1-shutdown.raw). poll-*.last hold the last r1 polls.
# A vty capture passes only if its bytes are the echoed command, CRLF, one strict JSON object,
# CRLF, and "r1> ", and its content shows the phase's expected state. Only session state, the
# route keys, the stable attributes of each path (peerId, pathFrom, path, origin, next-hop
# addresses), the stale key, and the remote graceful-restart mode are matched. Fields FRR may
# change when another path goes, such as bestpath, selectionReason, or version, are kept in the
# captures and never matched.
# ZEBRA_VTY_PORT, when set, adds zebra evidence to every phase. Zebra runs on that port at 127.0.0.1
# with a config that names its router, so its prompt is "r1> " and the port queried is the port
# bound. Each phase adds r1-<phase>-show_ip_route_json.raw (zebra's unfiltered route table) with a
# .collected_at stamp, and zebra-version.txt is written. The port must be 1 to 65535 and not 179
# (bgpd BGP), 2604 (ospfd), or BGPD_VTY_PORT. SHA256SUMS lists the run's files once every daemon has
# exited. Unset, the run writes the files described above and no others, and the zebra configs stay
# empty. The zebra capture is checked for framing and one JSON object only: no zebra field is read,
# because none has been verified for BGP routes.
# A failed capture is kept as .raw.failed with no .collected_at. The run exits 1, and DONE is never printed.
set -u
S=${SCRATCH:?set SCRATCH to a directory holding frr-root/ (see README)}
P=${BGPD_VTY_PORT-}
A=${ARM-}
if ! [[ $P =~ ^[1-9][0-9]{0,4}$ ]] || (( P > 65535 )) || (( P == 2604 || P == 2601 || P == 179 )); then
  echo "bgp-session.sh: BGPD_VTY_PORT must be 1 to 65535 and not 2604 (ospfd), 2601 (zebra), or 179 (bgpd BGP), not '$P'" >&2
  exit 2
fi
if [[ $A != plain && $A != gr && $A != admin ]]; then
  echo "bgp-session.sh: ARM must be plain, gr, or admin, not '$A'" >&2
  exit 2
fi
# Unset ZEBRA_VTY_PORT leaves the legacy run. Set, the port is checked here, before any file is touched.
ZP=
if [[ -n ${ZEBRA_VTY_PORT+set} ]]; then
  ZP=${ZEBRA_VTY_PORT-}
  if ! [[ $ZP =~ ^[1-9][0-9]{0,4}$ ]] || (( ZP > 65535 )) || (( ZP == 179 || ZP == 2604 || ZP == P )); then
    echo "bgp-session.sh: ZEBRA_VTY_PORT must be 1 to 65535 and not 179 (bgpd BGP), 2604 (ospfd), or BGPD_VTY_PORT, not '$ZP'" >&2
    exit 2
  fi
fi
HERE=$(cd "$(dirname "$0")" && pwd)
TCP=$HERE/tcpvty2.py
FRR=$S/frr-root/usr/libexec/frr
OUT=$S/run/bgp-session-$A
export LD_LIBRARY_PATH="$S/frr-root/usr/lib64:$S/frr-root/usr/lib64/frr"
R2=
R3=
started=0

fail() { echo "bgp-session.sh: $*" >&2; exit 1; }

# Refuse to run in the initial user namespace: the script mounts over /run and /etc and adds veth
# links, so the host must not run it.
read -r uid_in uid_out uid_n < /proc/self/uid_map || fail "could not read /proc/self/uid_map"
[[ "$uid_in $uid_out $uid_n" != "0 0 4294967295" ]] \
  || fail "run under unshare -Urnm: this is the initial user namespace"
mkdir -p "$S/run" && mkdir "$OUT" || fail "$OUT already exists or could not be created; this run never removes it"
"$FRR/bgpd" --version > "$OUT/bgpd-version.txt" 2>&1 || fail "bgpd --version failed"
"$FRR/zebra" --version > "$OUT/zebra-version.txt" 2>&1 || fail "zebra --version failed"

# STOPPED holds the pids that stop signaled. sums waits on them, not on the pid files, so it does not
# depend on when a daemon removes its pid file.
STOPPED=
stop() {
  if (( started )); then
    STOPPED=$(cat /run/frr/r1/*.pid /run/frr/r2/*.pid /run/frr/r3/*.pid 2>/dev/null)
    xargs -r kill <<< "$STOPPED" 2>/dev/null
  fi
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

GR=
if [[ $A != plain ]]; then
  GR=$' bgp graceful-restart\n bgp graceful-restart restart-time 30\n'
fi
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
${GR} no bgp ebgp-requires-policy
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
# Unset ZEBRA_VTY_PORT keeps the empty zebra configs. Set, each names its router, so zebra's prompt
# is "rN> ", the form lsdb.sh writes.
if [[ -n $ZP ]]; then
  for n in 1 2 3; do printf 'hostname r%s\nline vty\n no login\n' "$n" > "$OUT/r$n-zebra.conf" || fail "could not write zebra configs"; done
else
  : > "$OUT/r1-zebra.conf" && : > "$OUT/r2-zebra.conf" && : > "$OUT/r3-zebra.conf" || fail "could not write zebra configs"
fi

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
  local -a zopt=()
  if [[ -n $ZP ]]; then zopt=(-P "$ZP" -A 127.0.0.1); fi
  "${at[@]}" "$FRR/zebra" -d -f "$OUT/$node-zebra.conf" -i "$sock/zebra.pid" -z "$sock/zserv.api" \
    --vty_socket "$sock" "${zopt[@]}" -u root -g root >> "$OUT/$node-daemons.log" 2>&1 || return 1
  "${at[@]}" "$FRR/bgpd" -d -f "$OUT/$node-bgpd.conf" -i "$sock/bgpd.pid" -z "$sock/zserv.api" \
    --vty_socket "$sock" -P "$P" -A 127.0.0.1 -u root -g root >> "$OUT/$node-daemons.log" 2>&1 || return 1
  alive "$sock/zebra.pid" && alive "$sock/bgpd.pid"
}

# query CMD FILE [PORT]: one raw vty query on r1 into FILE. PORT defaults to bgpd's.
query() {
  timeout 30 python3 -I "$TCP" "${3:-$P}" "$1" > "$2" 2> "$2.err"
}

# BGPOK FILE CMD NODE REQ...: exit 0 only if FILE is the echoed CMD, CRLF, one strict JSON object,
# CRLF, and NODE's "> " prompt with nothing after it. Duplicate keys, NaN, and Infinity fail.
# A REQ is op:arg.
#   est:ADDR             a dict under key ADDR has a direct value "Established".
#   notest:ADDR          at least one dict is under key ADDR, and none has a direct value "Established".
#   state:ADDR=TEXT      a dict under key ADDR has "state" equal to TEXT.
#   paths:PREFIX=ID,ID   routes[PREFIX] lists exactly these peerId values, as a sorted multiset.
#   absent:PREFIX        routes has no key PREFIX.
#   stale:PREFIX=ADDR    routes[PREFIX] lists a path from ADDR, and every such path has "stale": true.
#   staleonly:ADDR       every path with a stale key is from ADDR and has "stale": true.
#   nostale              no path has a stale key.
#   grmode:ADDR=MODE     the neighbor ADDR's gracefulRestartInfo.remoteGrMode is MODE.
#   same:FILE=ADDR       the paths not from ADDR, as (prefix, peerId, pathFrom, path, origin,
#                        next-hop addresses), are the same multiset as in the table FILE.
# Other fields are never read.
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
def body(f,cmd,node):
    b=open(f,"rb").read()
    head=cmd.encode()+b"\r\n"
    tail=b"\r\n"+node.encode()+b"> "
    if len(b)<len(head)+len(tail) or not b.startswith(head) or not b.endswith(tail): sys.exit(1)
    d=json.loads(b[len(head):len(b)-len(tail)].decode("utf-8"),object_pairs_hook=pairs,parse_constant=bad)
    if not isinstance(d,dict): sys.exit(1)
    return d
def paths(routes):
    if not isinstance(routes,dict): bad("no routes")
    out=[]
    for pfx,ps in routes.items():
        if not isinstance(ps,list) or not all(isinstance(p,dict) for p in ps): bad("paths")
        out+=[(pfx,p) for p in ps]
    return out
def stable(routes,skip):
    out=[]
    for pfx,p in paths(routes):
        if p.get("peerId")==skip: continue
        hops=tuple(h.get("ip") for h in p.get("nexthops",[]) if isinstance(h,dict))
        out.append(repr((pfx,p.get("peerId"),p.get("pathFrom"),p.get("path"),p.get("origin"),hops)))
    return sorted(out)
f,cmd,node=sys.argv[1:4]
d=body(f,cmd,node)
routes=d.get("routes")
for r in sys.argv[4:]:
    op,_,arg=r.partition(":")
    if op=="est":
        good=any(isinstance(v,dict) and "Established" in v.values() for v in find(d,arg))
    elif op=="notest":
        vs=[v for v in find(d,arg) if isinstance(v,dict)]
        good=bool(vs) and not any("Established" in v.values() for v in vs)
    elif op=="state":
        addr,_,want=arg.partition("=")
        good=any(isinstance(v,dict) and v.get("state")==want for v in find(d,addr))
    elif op=="paths":
        pfx,_,ids=arg.partition("=")
        ps=routes.get(pfx) if isinstance(routes,dict) else None
        good=isinstance(ps,list) and all(isinstance(p,dict) for p in ps) and sorted(p.get("peerId") for p in ps)==sorted(ids.split(","))
    elif op=="absent":
        good=isinstance(routes,dict) and arg not in routes
    elif op=="stale":
        pfx,_,addr=arg.partition("=")
        ps=[p for q,p in paths(routes) if q==pfx and p.get("peerId")==addr]
        good=bool(ps) and all(p.get("stale") is True for p in ps)
    elif op=="staleonly":
        good=all(p.get("peerId")==arg and p["stale"] is True for _,p in paths(routes) if "stale" in p)
    elif op=="nostale":
        good=not any("stale" in p for _,p in paths(routes))
    elif op=="grmode":
        addr,_,want=arg.partition("=")
        n=d.get(addr)
        gr=n.get("gracefulRestartInfo") if isinstance(n,dict) else None
        good=isinstance(gr,dict) and gr.get("remoteGrMode")==want
    elif op=="same":
        ref,_,addr=arg.rpartition("=")
        good=stable(routes,addr)==stable(body(ref,"show ip bgp json",node).get("routes"),addr)
    else: good=False
    if not good: sys.exit(1)
'

# capture PORT PHASE CMD REQ...: one r1 capture on vty PORT into $OUT/r1-PHASE-CMD.raw, checked by
# BGPOK. A capture that fails is kept as .raw.failed with no .collected_at. The UTC stamp is taken
# before the vty connects and is written only after the checks pass.
capture() {
  local port=$1 phase=$2 cmd=$3 base rc at
  shift 3
  base="$OUT/r1-$phase-${cmd// /_}"
  at=$(date -u +%Y-%m-%dT%H:%M:%S.%NZ) || return 1
  query "$cmd" "$base.raw" "$port"; rc=$?
  if (( rc == 0 )) && python3 -I -c "$BGPOK" "$base.raw" "$cmd" r1 "$@" 2>/dev/null; then
    rm -f "$base.raw.err"
    if printf '%s\n' "$at" > "$base.collected_at"; then return 0; fi
    rm -f "$base.collected_at"
  fi
  mv -f "$base.raw" "$base.raw.failed" 2>/dev/null
  echo "bgp-session.sh: capture r1 $phase $cmd failed (vty, framing, JSON, or content check)" >&2
  return 1
}
# cap PHASE CMD REQ...: a capture on bgpd's vty port.
cap() { capture "$P" "$@"; }
# zcap PHASE: r1's zebra route table on ZEBRA_VTY_PORT. Only framing and one JSON object are checked.
zcap() { capture "$ZP" "$1" "show ip route json"; }

# kernel PHASE: r1's IPv4 kernel routes as ip -j prints them, into $OUT/r1-PHASE-ip_route.json.
# They are lab context: only that the output is one JSON array is checked.
kernel() {
  local base="$OUT/r1-$1-ip_route" at
  at=$(date -u +%Y-%m-%dT%H:%M:%S.%NZ) || return 1
  if ip -j -4 route show > "$base.json" 2> "$base.json.err" \
    && python3 -I -c 'import json,sys; sys.exit(0 if isinstance(json.load(open(sys.argv[1])),list) else 1)' "$base.json"; then
    rm -f "$base.json.err"
    printf '%s\n' "$at" > "$base.collected_at" && return 0
  fi
  rm -f "$base.collected_at"
  mv -f "$base.json" "$base.json.failed" 2>/dev/null
  echo "bgp-session.sh: kernel route capture $1 failed" >&2
  return 1
}

# settle PHASE LIMIT STEP: poll r1's summary and table every STEP seconds for up to LIMIT seconds
# until the summary matches SUM and the table matches TAB, then capture the summary, the table,
# and the neighbor (checked against NBR), and the kernel routes.
NB="show ip bgp neighbors 10.0.1.2 json"
settle() {
  local phase=$1 limit=$2 step=$3 t0=$SECONDS ok=0
  while (( SECONDS - t0 < limit )); do
    if query "show ip bgp summary json" "$OUT/poll-r1-summary.last" \
      && python3 -I -c "$BGPOK" "$OUT/poll-r1-summary.last" "show ip bgp summary json" r1 "${SUM[@]}" 2>/dev/null \
      && query "show ip bgp json" "$OUT/poll-r1-table.last" \
      && python3 -I -c "$BGPOK" "$OUT/poll-r1-table.last" "show ip bgp json" r1 "${TAB[@]}" 2>/dev/null; then
      ok=1
      break
    fi
    sleep "$step"
  done
  (( ok )) || fail "r1 did not reach the $phase state within $limit seconds (see $OUT/poll-r1-*.last)"
  echo "$phase: settled after ~$((SECONDS - t0))s; taking captures"
  cap "$phase" "show ip bgp summary json" "${SUM[@]}" || fail "r1 $phase summary capture failed"
  cap "$phase" "show ip bgp json" "${TAB[@]}" || fail "r1 $phase table capture failed"
  cap "$phase" "$NB" "${NBR[@]}" || fail "r1 $phase neighbor capture failed"
  kernel "$phase" || fail "r1 $phase kernel route capture failed"
  if [[ -n $ZP ]]; then zcap "$phase" || fail "r1 $phase zebra route capture failed"; fi
}

# event TEXT: one line in events.log with the UTC time.
event() {
  printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)" "$1" >> "$OUT/events.log" || fail "could not write events.log"
}

# sums: under ZEBRA_VTY_PORT, after stop has sent SIGTERM, waits up to 10 seconds for each pid stop
# signaled to exit, so no log can still grow. It then writes SHA256SUMS for the run's files in byte
# order, leaving out the poll and error files, and checks the file it wrote.
sums() {
  local i pid live f
  local -a names=()
  for ((i = 0; i < 100; i++)); do
    live=0
    for pid in $STOPPED; do
      if kill -0 "$pid" 2>/dev/null; then live=1; fi
    done
    (( live )) || break
    sleep 0.1
  done
  (( live == 0 )) || fail "a daemon outlived SIGTERM, so its logs may still change; no SHA256SUMS written"
  local LC_ALL=C
  for f in "$OUT"/*; do
    case ${f##*/} in poll-*.last | *.err) ;; *) names+=("${f##*/}") ;; esac
  done
  (cd "$OUT" && sha256sum -- "${names[@]}" > SHA256SUMS && sha256sum -c --strict SHA256SUMS > /dev/null) \
    || fail "could not write or check SHA256SUMS"
}

# VTYCFG PORT LINE...: send each line to r1's bgpd vty over TCP and print the bytes it returns.
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

started=1
start r1 self || fail "r1 daemons did not start"
start r2 "$R2" || fail "r2 daemons did not start"
start r3 "$R3" || fail "r3 daemons did not start"
echo "daemons started"

BEFORE="$OUT/r1-before-show_ip_bgp_json.raw"
ALL=(paths:10.10.1.0/24='(unspec)',10.0.1.2 paths:10.10.2.0/24=10.0.1.2,10.0.3.3
  paths:10.10.3.0/24=10.0.3.3 paths:10.10.9.0/24=10.0.1.2)
GONE=(paths:10.10.1.0/24='(unspec)' paths:10.10.2.0/24=10.0.3.3 paths:10.10.3.0/24=10.0.3.3
  absent:10.10.9.0/24 nostale "same:$BEFORE=10.0.1.2")
SUM=(est:10.0.1.2 est:10.0.3.3)
TAB=("${ALL[@]}" nostale)
NBR=(grmode:10.0.1.2=Helper)
[[ $A == plain ]] || NBR=(grmode:10.0.1.2=Restart)
settle before 120 2

if [[ $A == admin ]]; then
  event "r1: neighbor 10.0.1.2 shutdown"
  python3 -I -c "$VTYCFG" "$P" "enable" "configure terminal" "router bgp 65001" \
    "neighbor 10.0.1.2 shutdown" "end" > "$OUT/r1-shutdown.raw" 2>&1 || fail "the shutdown vty session failed"
  SUM=('state:10.0.1.2=Idle (Admin)' est:10.0.3.3)
  TAB=("${GONE[@]}")
  NBR=()
  settle after 60 1
else
  pid=$(cat /run/frr/r2/bgpd.pid) && [[ $pid =~ ^[0-9]+$ ]] || fail "no r2 bgpd pid"
  event "r2: SIGKILL bgpd pid $pid"
  kill -9 "$pid" || fail "could not kill r2's bgpd"
  for ((i = 0; i < 50; i++)); do kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
  ! kill -0 "$pid" 2>/dev/null || fail "r2's bgpd survived SIGKILL"
  SUM=(notest:10.0.1.2 est:10.0.3.3)
  if [[ $A == plain ]]; then
    TAB=("${GONE[@]}")
    NBR=()
    settle after 60 1
  else
    # Every path from 10.0.1.2 is still listed and marked stale, and no other path is.
    TAB=("${ALL[@]}" stale:10.10.1.0/24=10.0.1.2 stale:10.10.2.0/24=10.0.1.2
      stale:10.10.9.0/24=10.0.1.2 staleonly:10.0.1.2 "same:$BEFORE=10.0.1.2")
    NBR=(grmode:10.0.1.2=NotApplicable)
    settle during 20 1
    TAB=("${GONE[@]}")
    NBR=()
    settle expired 120 2
  fi
fi
echo "--- stopping"
stop
if [[ -n $ZP ]]; then sums; fi
echo DONE
