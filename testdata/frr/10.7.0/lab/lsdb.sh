#!/bin/bash
# Local two-router FRR 10.7.0 OSPF LSDB lab, one scenario per run, inside user+mount+net namespaces.
# r2 redistributes connected stub3 (10.20.0.0/24) as a Type 5 external LSA.
# Run as: SCRATCH=<dir> unshare -Urnm bash lsdb.sh <steady|flap|kill9>
#   SCRATCH must hold frr-root/ extracted from the FRR 10.7.0 RPM (see ../README.md).
#   steady  no change inside the bracket
#   flap    stub1 down between the route capture and the closing process state
#   kill9   r2 daemons SIGKILL, and only the r1 bracket is captured
# The max-age command (database max-age) is not captured: max-age is out of scope.
# Each capture is a vtysh transcript named <node>-<role>-<command>.raw. Its UTC
# start time is in the .collected_at file beside it.
set -u
S=${SCRATCH:?set SCRATCH to a directory holding frr-root/ (see README)}
MODE=$1
HERE=$(cd "$(dirname "$0")" && pwd)
TCP=$HERE/tcpvty2.py
L=$S/run/lsdb-$MODE
FRR=$S/frr-root/usr/libexec/frr
export LD_LIBRARY_PATH="$S/frr-root/usr/lib64:$S/frr-root/usr/lib64/frr"

mount -t tmpfs tmpfs /run && mkdir -p /run/frr
mount -t tmpfs tmpfs /var/lib && mkdir -p /var/lib/frr
mount --bind "$HERE/etc/group" /etc/group
mount --bind "$HERE/etc/passwd" /etc/passwd
rm -rf "$L"; mkdir -p "$L/r1" "$L/r2"

unshare -n sleep 3600 & R2=$!
sleep 0.5
ip link set lo up
ip link add e1 type veth peer name e2
ip link set e2 netns $R2
ip link set e1 up; ip addr add 10.0.1.1/24 dev e1
ip link add stub1 type dummy; ip link set stub1 up; ip addr add 10.10.1.1/24 dev stub1
nsenter -t $R2 -n sh -c 'ip link set lo up; ip link set e2 up; ip addr add 10.0.1.2/24 dev e2; ip link add stub2 type dummy; ip link set stub2 up; ip addr add 10.10.2.1/24 dev stub2; ip link add stub3 type dummy; ip link set stub3 up; ip addr add 10.20.0.1/24 dev stub3'

printf 'hostname r1\nline vty\n no login\n' > "$L/r1/zebra.conf"
printf 'hostname r2\nline vty\n no login\n' > "$L/r2/zebra.conf"
printf 'hostname r1\nline vty\n no login\ninterface e1\nrouter ospf\n ospf router-id 1.1.1.1\n network 10.0.1.0/24 area 0.0.0.0\n network 10.10.1.0/24 area 0.0.0.0\n' > "$L/r1/ospfd.conf"
printf 'hostname r2\nline vty\n no login\ninterface e2\nrouter ospf\n ospf router-id 2.2.2.2\n network 10.0.1.0/24 area 0.0.0.0\n network 10.10.2.0/24 area 0.0.0.0\n redistribute connected\n' > "$L/r2/ospfd.conf"

start() {
  local d=$1 ns=$2 sock
  sock=/run/frr/$(basename "$1")
  mkdir -p "$sock"
  local run="$FRR/zebra -d -f $d/zebra.conf -i $d/zebra.pid -z $sock/zserv.api --vty_socket $sock -u root -g root && $FRR/ospfd -d -f $d/ospfd.conf -i $d/ospfd.pid -z $sock/zserv.api --vty_socket $sock -u root -g root"
  if [ "$ns" = self ]; then sh -c "$run" >/dev/null 2>&1; else nsenter -t "$ns" -n sh -c "$run" >/dev/null 2>&1; fi
}
start "$L/r1" self
start "$L/r2" $R2
echo "daemons started"
for i in $(seq 1 45); do
  if timeout 10 python3 -I "$TCP" 2604 "show ip ospf neighbor json" 2>/dev/null | grep -q '"Full'; then echo "full after ~$((i*2))s"; break; fi
  sleep 2
done
sleep 25

# cap ns tag port name command
cap() {
  local ns=$1 tag=$2 port=$3 name=$4; shift 4
  local base="$L/$tag-$name-${*// /_}"
  date -u +%Y-%m-%dT%H:%M:%S.%NZ > "$base.collected_at"
  if [ "$ns" = self ]; then timeout 30 python3 -I "$TCP" "$port" "$*" > "$base.raw" 2>&1
  else timeout 30 nsenter -t "$ns" -n python3 -I "$TCP" "$port" "$*" > "$base.raw" 2>&1; fi
}
bracket() { # ns tag port
  local ns=$1 tag=$2 port=$3
  cap "$ns" "$tag" "$port" A "show ip ospf json"
  cap "$ns" "$tag" "$port" B "show ip ospf database detail json"
  cap "$ns" "$tag" "$port" E "show ip ospf route json"
  if [ "$MODE" = flap ] && [ "$ns" = self ]; then ip link set stub1 down; sleep 4; fi
  cap "$ns" "$tag" "$port" D "show ip ospf json"
}
if [ "$MODE" = kill9 ]; then
  # SIGKILL r2 daemons: r2 LSAs stay in r1's LSDB, r1 loses the adjacency.
  cat "$L"/r2/*.pid 2>/dev/null | xargs -r kill -9; echo "r2 SIGKILL"; sleep 75
  bracket self r1 2604
else
  bracket self r1 2604
  bracket $R2 r2 2604
fi
[ "$MODE" = flap ] && ip link set stub1 up
echo "DONE"
cat "$L"/r1/*.pid "$L"/r2/*.pid 2>/dev/null | xargs -r kill
kill $R2 2>/dev/null
