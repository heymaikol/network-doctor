#!/bin/bash
# Local two-router FRR 10.7.0 OSPF LSDB lab, one scenario per run, inside user+mount+net namespaces.
# In steady, flap, and kill9, r2 redistributes connected stub3 (10.20.0.0/24) as a Type 5 external LSA.
# Run as: SCRATCH=<dir> unshare -Urnm bash lsdb.sh <steady|flap|kill9|ecmp>
#   SCRATCH must hold frr-root/ extracted from the FRR 10.7.0 RPM (see ../README.md).
#   steady  no change inside the bracket
#   flap    stub1 down between the route capture and the closing process state
#   kill9   r2 daemons SIGKILL, and only the r1 bracket is captured
#   ecmp    three links between r1 and r2, r1 e5 at cost 50. Polls until each router
#           has three Full neighbors and the expected ECMP next-hop counts, then brackets both
# The ecmp captures are written to $SCRATCH/run/lsdb-ecmp, with ospfd-version.txt beside them.
# The max-age command (database max-age) is not captured: max-age is out of scope.
# Each capture is a vtysh transcript named <node>-<role>-<command>.raw. Its UTC
# start time is in the .collected_at file beside it. A failed capture exits nonzero,
# leaves <name>.raw.failed in place of .raw, and writes no .collected_at.
set -u
S=${SCRATCH:?set SCRATCH to a directory holding frr-root/ (see README)}
MODE=${1-}
case $MODE in
  steady | flap | kill9 | ecmp) ;;
  *) echo "lsdb.sh: MODE must be steady, flap, kill9, or ecmp, not '$MODE'" >&2; exit 2 ;;
esac
HERE=$(cd "$(dirname "$0")" && pwd)
TCP=$HERE/tcpvty2.py
L=$S/run/lsdb-$MODE
FRR=$S/frr-root/usr/libexec/frr
export LD_LIBRARY_PATH="$S/frr-root/usr/lib64:$S/frr-root/usr/lib64/frr"
R2=

# Stops every daemon this run started, the namespace holder, and restores the flap link.
# Pid files are read only once a daemon has started, so a run that failed earlier never signals a stale pid.
cleanup() {
  local rc=$?
  if [[ $MODE = flap ]]; then ip link set stub1 up 2>/dev/null; fi
  if (( started )); then cat "$L"/r1/*.pid "$L"/r2/*.pid 2>/dev/null | xargs -r kill 2>/dev/null; fi
  if [[ -n $R2 ]]; then kill "$R2" 2>/dev/null; fi
  exit "$rc"
}
started=0
trap cleanup EXIT

fail() { echo "lsdb.sh: $*" >&2; exit 1; }

# Move the old run aside, then remove it. If that fails, drop the old .collected_at markers so no old capture reads as kept.
{ { [[ ! -e $L ]] || mv -T "$L" "$L.discard.$$"; } && rm -rf "$L.discard.$$" && mkdir -p "$L/r1" "$L/r2"; } \
  || { rm -f "$L"/*.collected_at 2>/dev/null; fail "could not clear $L"; }
{ mount -t tmpfs tmpfs /run && mkdir -p /run/frr \
  && mount -t tmpfs tmpfs /var/lib && mkdir -p /var/lib/frr \
  && mount --bind "$HERE/etc/group" /etc/group \
  && mount --bind "$HERE/etc/passwd" /etc/passwd; } || fail "mount setup failed"

unshare -n sleep 3600 & R2=$!
sleep 0.5
{ ip link set lo up && ip link add e1 type veth peer name e2 && ip link set e2 netns "$R2" \
  && ip link set e1 up && ip addr add 10.0.1.1/24 dev e1 \
  && ip link add stub1 type dummy && ip link set stub1 up && ip addr add 10.10.1.1/24 dev stub1; } \
  || fail "host setup failed"
if [[ $MODE = ecmp ]]; then
  # Two more links: e3 to e4 at cost 10, e5 to e6 at cost 50 on r1 e5.
  { ip link add e3 type veth peer name e4 && ip link set e4 netns "$R2" \
    && ip link add e5 type veth peer name e6 && ip link set e6 netns "$R2" \
    && ip link set e3 up && ip addr add 10.0.3.1/24 dev e3 \
    && ip link set e5 up && ip addr add 10.0.5.1/24 dev e5; } \
    || fail "ecmp host setup failed"
  nsenter -t "$R2" -n sh -c 'ip link set lo up && ip link set e2 up && ip addr add 10.0.1.2/24 dev e2 && ip link set e4 up && ip addr add 10.0.3.2/24 dev e4 && ip link set e6 up && ip addr add 10.0.5.2/24 dev e6 && ip link add stub2 type dummy && ip link set stub2 up && ip addr add 10.10.2.1/24 dev stub2' \
    || fail "r2 namespace setup failed"
else
  nsenter -t "$R2" -n sh -c 'ip link set lo up && ip link set e2 up && ip addr add 10.0.1.2/24 dev e2 && ip link add stub2 type dummy && ip link set stub2 up && ip addr add 10.10.2.1/24 dev stub2 && ip link add stub3 type dummy && ip link set stub3 up && ip addr add 10.20.0.1/24 dev stub3' \
    || fail "r2 namespace setup failed"
fi

{ printf 'hostname r1\nline vty\n no login\n' > "$L/r1/zebra.conf" \
  && printf 'hostname r2\nline vty\n no login\n' > "$L/r2/zebra.conf"; } \
  || fail "config write failed"
if [[ $MODE = ecmp ]]; then
  { printf 'hostname r1\nline vty\n no login\ninterface e1\ninterface e3\ninterface e5\n ip ospf cost 50\nrouter ospf\n ospf router-id 1.1.1.1\n network 10.0.1.0/24 area 0.0.0.0\n network 10.0.3.0/24 area 0.0.0.0\n network 10.0.5.0/24 area 0.0.0.0\n network 10.10.1.0/24 area 0.0.0.0\n' > "$L/r1/ospfd.conf" \
    && printf 'hostname r2\nline vty\n no login\ninterface e2\ninterface e4\ninterface e6\nrouter ospf\n ospf router-id 2.2.2.2\n network 10.0.1.0/24 area 0.0.0.0\n network 10.0.3.0/24 area 0.0.0.0\n network 10.0.5.0/24 area 0.0.0.0\n network 10.10.2.0/24 area 0.0.0.0\n' > "$L/r2/ospfd.conf"; } \
    || fail "config write failed"
else
  { printf 'hostname r1\nline vty\n no login\ninterface e1\nrouter ospf\n ospf router-id 1.1.1.1\n network 10.0.1.0/24 area 0.0.0.0\n network 10.10.1.0/24 area 0.0.0.0\n' > "$L/r1/ospfd.conf" \
    && printf 'hostname r2\nline vty\n no login\ninterface e2\nrouter ospf\n ospf router-id 2.2.2.2\n network 10.0.1.0/24 area 0.0.0.0\n network 10.10.2.0/24 area 0.0.0.0\n redistribute connected\n' > "$L/r2/ospfd.conf"; } \
    || fail "config write failed"
fi

# start DIR NS: zebra, then ospfd if zebra started, in namespace NS (self, or the holder pid).
start() {
  local d=$1 ns=$2 sock
  sock=/run/frr/$(basename "$1")
  mkdir -p "$sock" || fail "could not create $sock"
  local -a at=()
  if [[ $ns != self ]]; then at=(nsenter -t "$ns" -n); fi
  "${at[@]}" "$FRR/zebra" -d -f "$d/zebra.conf" -i "$d/zebra.pid" -z "$sock/zserv.api" --vty_socket "$sock" -u root -g root >/dev/null 2>&1 \
    && "${at[@]}" "$FRR/ospfd" -d -f "$d/ospfd.conf" -i "$d/ospfd.pid" -z "$sock/zserv.api" --vty_socket "$sock" -u root -g root >/dev/null 2>&1
}
started=1
start "$L/r1" self || fail "r1 daemons did not start"
start "$L/r2" "$R2" || fail "r2 daemons did not start"
echo "daemons started"
if [[ $MODE = ecmp ]]; then
  "$FRR/ospfd" --version > "$L/ospfd-version.txt" || fail "could not write ospfd-version.txt"
  # vty_out NS CMD...: one raw vty query on r1 (NS self) or on r2 (NS is the holder pid).
  vty_out() {
    local ns=$1; shift
    if [[ $ns = self ]]; then timeout 10 python3 -I "$TCP" 2604 "$*" 2>/dev/null
    else timeout 10 nsenter -t "$ns" -n python3 -I "$TCP" 2604 "$*" 2>/dev/null; fi
  }
  # The checks read one framed vty output on stdin and exit 0 when it has the wanted shape.
  NBR3='import json,sys
t=sys.stdin.read()
d=json.loads(t[t.index("{"):t.rindex("}")+1])
full=[n for v in d.get("neighbors",{}).values() for n in v if str(n.get("nbrState","")).startswith("Full")]
sys.exit(0 if len(full)==3 else 1)'
  NHOPS='import json,sys
t=sys.stdin.read()
d=json.loads(t[t.index("{"):t.rindex("}")+1])
sys.exit(0 if len(d.get(sys.argv[1],{}).get("nexthops",[]))==int(sys.argv[2]) else 1)'
  # ecmp_ready: three Full neighbors on each router, r1 reaches 10.10.2.0/24 over two hops,
  # and r2 reaches 10.10.1.0/24 over three. The last outputs are kept as failure evidence.
  ecmp_ready() {
    local n1 n2 r1 r2
    n1=$(vty_out self "show ip ospf neighbor json") && n2=$(vty_out "$R2" "show ip ospf neighbor json") || return 1
    r1=$(vty_out self "show ip ospf route json") && r2=$(vty_out "$R2" "show ip ospf route json") || return 1
    printf '%s\n%s\n%s\n%s\n' "$n1" "$n2" "$r1" "$r2" > "$L/ecmp-poll.last"
    python3 -I -c "$NBR3" <<<"$n1" && python3 -I -c "$NBR3" <<<"$n2" \
      && python3 -I -c "$NHOPS" 10.10.2.0/24 2 <<<"$r1" && python3 -I -c "$NHOPS" 10.10.1.0/24 3 <<<"$r2"
  }
  ecmp_full=0
  for i in $(seq 1 45); do
    if ecmp_ready; then echo "ecmp converged after ~$((i*2))s"; ecmp_full=1; break; fi
    sleep 2
  done
  (( ecmp_full )) || fail "ECMP did not converge on r1 and r2 after the wait (see $L/ecmp-poll.last)"
else
  full=0
  for i in $(seq 1 45); do
    if out=$(timeout 10 python3 -I "$TCP" 2604 "show ip ospf neighbor json" 2>/dev/null) && grep -q '"Full' <<<"$out"; then
      echo "full after ~$((i*2))s"; full=1; break
    fi
    sleep 2
  done
  (( full )) || fail "no Full neighbor on r1 after the wait"
fi
sleep 25

# cap ns tag port name command...: one vtysh capture. On failure, keep the output as .raw.failed.
cap() {
  local ns=$1 tag=$2 port=$3 name=$4; shift 4
  local base="$L/$tag-$name-${*// /_}" at rc
  at=$(date -u +%Y-%m-%dT%H:%M:%S.%NZ) || return 1
  if [[ "$ns" = self ]]; then timeout 30 python3 -I "$TCP" "$port" "$*" > "$base.raw" 2>&1; rc=$?
  else timeout 30 nsenter -t "$ns" -n python3 -I "$TCP" "$port" "$*" > "$base.raw" 2>&1; rc=$?; fi
  if (( rc != 0 )) || [[ ! -s $base.raw ]]; then
    rm -f "$base.collected_at"
    mv -f "$base.raw" "$base.raw.failed" 2>/dev/null
    echo "lsdb.sh: capture $tag $name failed (status $rc)" >&2
    return 1
  fi
  printf '%s\n' "$at" > "$base.collected_at" && return 0
  rm -f "$base.collected_at"
  mv -f "$base.raw" "$base.raw.failed" 2>/dev/null
  echo "lsdb.sh: capture $tag $name failed (could not write .collected_at)" >&2
  return 1
}
bracket() { # ns tag port
  local ns=$1 tag=$2 port=$3
  cap "$ns" "$tag" "$port" A "show ip ospf json" || return 1
  cap "$ns" "$tag" "$port" B "show ip ospf database detail json" || return 1
  cap "$ns" "$tag" "$port" E "show ip ospf route json" || return 1
  if [[ "$MODE" = flap ]] && [[ "$ns" = self ]]; then ip link set stub1 down || return 1; sleep 4; fi
  cap "$ns" "$tag" "$port" D "show ip ospf json" || return 1
}
if [[ "$MODE" = kill9 ]]; then
  # SIGKILL r2 daemons: r2 LSAs stay in r1's LSDB, r1 loses the adjacency.
  [[ -s $L/r2/zebra.pid && -s $L/r2/ospfd.pid ]] || fail "r2 pid files missing"
  cat "$L"/r2/*.pid | xargs -r kill -9 || fail "could not SIGKILL r2 daemons"
  echo "r2 SIGKILL"; sleep 75
  bracket self r1 2604 || fail "r1 bracket failed"
else
  bracket self r1 2604 || fail "r1 bracket failed"
  bracket "$R2" r2 2604 || fail "r2 bracket failed"
fi
if [[ "$MODE" = flap ]]; then ip link set stub1 up || fail "could not restore stub1"; fi
echo "DONE"
