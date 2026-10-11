#!/bin/bash
# Local two-router FRR 10.7.0 lab, one scenario per run, inside user+mount+net namespaces.
# No host network change. Output is read over each daemon's loopback TCP vty from inside its netns.
# Run as: SCRATCH=<dir> unshare -Urnm bash run5.sh <mode>
#   SCRATCH must hold frr-root/ extracted from the FRR 10.7.0 RPM (see ../README.md).
#   bcast   broadcast adjacency, r1 DR/Backup pair, passive stub on r1
#   p2p     point-to-point adjacency
#   mtu     r2 e2 MTU 1400 vs 1500, adjacency held below Full
#   empty   r1 only, no peer daemon, valid empty neighbor list
#   nbma    r1 non-broadcast with static neighbor 10.0.1.2, peer absent, RID unknown
#   noinst  r2 ospfd running with no router ospf stanza
#   area    r2 puts e2 in area 0.0.0.1 while r1 keeps e1 in 0.0.0.0, so no adjacency forms
#   secondary  r1 adds 10.0.2.1/24 to e1 in area 0.0.0.1, so e1 holds two OSPF interfaces
#   secp1   secondary, plus "ip ospf passive 10.0.1.1" on e1 (primary address)
#   secp2   secondary, plus "ip ospf passive 10.0.2.1" on e1 (secondary address)
#   passive1  r1 e1 "ip ospf passive" with no neighbor configured on either side
#   cost50  r1 e1 "ip ospf cost 50" against r2 default cost 10
#   mixp2p  r1 e1 point-to-point, r2 e2 broadcast (default), so the two ends disagree
#   down1   r1 e1 set down after the adjacency forms, then captured
# Every mode also captures "show ip ospf route json" on each node. Only the
# modes committed after that change have it in their directories.
# A failed step names itself on stderr and exits nonzero, and DONE is never printed.
# A failed capture keeps its output as <name>.raw.failed and writes no .collected_at.
set -u
S=${SCRATCH:?set SCRATCH to a directory holding frr-root/ (see README)}
MODE=${1-}
case $MODE in
  bcast | p2p | mtu | empty | nbma | noinst | area | secondary | secp1 | secp2 | passive1 | cost50 | mixp2p | down1) ;;
  *) echo "run5.sh: MODE must be one of the modes in the header, not '$MODE'" >&2; exit 2 ;;
esac
HERE=$(cd "$(dirname "$0")" && pwd)
L=$S/run/$MODE
FRR=$S/frr-root/usr/libexec/frr
export LD_LIBRARY_PATH="$S/frr-root/usr/lib64:$S/frr-root/usr/lib64/frr"
R2=

fail() { echo "run5.sh: $*" >&2; exit 1; }

# started is set just before the first daemon starts. Pid files are read only after
# that, so an early failure never signals a pid that an old file names.
started=0

# stop kills the daemons this run started and the namespace holder. It runs once.
stop() {
  if (( started )); then cat "$L"/r1/*.pid "$L"/r2/*.pid 2>/dev/null | xargs -r kill 2>/dev/null; fi
  started=0
  if [[ -n $R2 ]]; then kill "$R2" 2>/dev/null; R2=; fi
}
cleanup() {
  local rc=$?
  stop
  exit "$rc"
}
trap cleanup EXIT

rm -rf "$L" || fail "could not clear $L"
mkdir -p "$L/r1" "$L/r2" "$L/meta" || fail "could not create $L"
{ mount -t tmpfs tmpfs /run && mkdir -p /run/frr \
  && mount -t tmpfs tmpfs /var/lib && mkdir -p /var/lib/frr \
  && mount --bind "$HERE/etc/group" /etc/group \
  && mount --bind "$HERE/etc/passwd" /etc/passwd; } || fail "mount setup failed"
"$FRR/ospfd" --version > "$L/meta/ospfd-version.txt" 2>&1 || fail "ospfd --version failed"

unshare -n sleep 3600 &
R2=$!
sleep 0.5
kill -0 "$R2" 2>/dev/null || fail "namespace holder did not start"
{ ip link add e1 type veth peer name e2 \
  && ip link set e2 netns "$R2" \
  && ip link set lo up \
  && ip link set e1 up \
  && ip addr add 10.0.1.1/24 dev e1; } || fail "host setup failed"
if [[ $MODE = secondary || $MODE = secp1 || $MODE = secp2 ]]; then
  ip addr add 10.0.2.1/24 dev e1 || fail "host secondary address failed"
fi
{ ip link add stub1 type dummy && ip link set stub1 up && ip addr add 10.10.1.1/24 dev stub1; } || fail "host stub setup failed"

in_r2() { nsenter -t "$R2" -n "$@"; }
{ in_r2 ip link set lo up \
  && in_r2 ip link set e2 up \
  && in_r2 ip addr add 10.0.1.2/24 dev e2 \
  && in_r2 ip link add stub2 type dummy \
  && in_r2 ip link set stub2 up \
  && in_r2 ip addr add 10.10.2.1/24 dev stub2; } || fail "r2 namespace setup failed"
if [[ $MODE = mtu ]]; then in_r2 ip link set e2 mtu 1400 || fail "could not set r2 e2 mtu"; fi
in_r2 ip -o link show e2 | grep -o 'mtu [0-9]*' > "$L/meta/r2-e2-mtu.txt" || fail "could not read r2 e2 mtu"

P2P=""; NBMA=""; R1_NEIGH=""; R1_SECOND=""; R2_OSPF=1; R2_AREA=0.0.0.0; PASS_LINE=""
case "$MODE" in
  p2p) P2P="ip ospf network point-to-point" ;;
  nbma) NBMA="ip ospf network non-broadcast"; R1_NEIGH=" neighbor 10.0.1.2"; R2_OSPF=0 ;;
  empty) R2_OSPF=0 ;;
  area) R2_AREA=0.0.0.1 ;;
  secondary) R1_SECOND=" network 10.0.2.0/24 area 0.0.0.1" ;;
  secp1|secp2) R1_SECOND=" network 10.0.2.0/24 area 0.0.0.1" ;;
  passive1|cost50) ;;
  mixp2p) P2P="ip ospf network point-to-point"; R2P="" ;;
esac
R2P=${R2P-$P2P}
case "$MODE" in
  secp1) PASS_LINE=" ip ospf passive 10.0.1.1" ;;
  secp2) PASS_LINE=" ip ospf passive 10.0.2.1" ;;
  passive1) PASS_LINE=" ip ospf passive" ;;
  cost50) PASS_LINE=" ip ospf cost 50" ;;
  down1) ;;
esac

cat > "$L/r1/ospfd.conf" <<CONF || fail "could not write r1 ospfd.conf"
hostname r1
line vty
 no login
interface e1
 $P2P$NBMA
$PASS_LINE
router ospf
 ospf router-id 1.1.1.1
 network 10.0.1.0/24 area 0.0.0.0
 network 10.10.1.0/24 area 0.0.0.0
 passive-interface stub1
$R1_SECOND
$R1_NEIGH
CONF
if [[ $MODE = noinst ]]; then
cat > "$L/r2/ospfd.conf" <<CONF || fail "could not write r2 ospfd.conf"
hostname r2
line vty
 no login
interface e2
CONF
else
cat > "$L/r2/ospfd.conf" <<CONF || fail "could not write r2 ospfd.conf"
hostname r2
line vty
 no login
interface e2
 $R2P
router ospf
 ospf router-id 2.2.2.2
 network 10.0.1.0/24 area $R2_AREA
 network 10.10.2.0/24 area $R2_AREA
CONF
fi
: > "$L/r1/zebra.conf" || fail "could not write zebra.conf"
: > "$L/r2/zebra.conf" || fail "could not write zebra.conf"

# alive FILE: the daemon that wrote pid file FILE holds a live pid within about ten seconds.
alive() {
  local i pid
  for ((i = 0; i < 50; i++)); do
    pid=$(cat "$1" 2>/dev/null)
    if [[ $pid =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null; then return 0; fi
    sleep 0.2
  done
  return 1
}

# start DIR NS: zebra, then ospfd, in namespace NS (self, or the holder pid). Unix
# socket paths must fit sun_path (108 bytes). The scratch path does not, so each node
# gets a short directory under the per-run /run tmpfs.
start() {
  local d=$1 ns=$2 sock
  sock=/run/frr/$(basename "$d")
  mkdir -p "$sock" || return 1
  local -a at=()
  if [[ $ns != self ]]; then at=(nsenter -t "$ns" -n); fi
  "${at[@]}" "$FRR/zebra" -d -f "$d/zebra.conf" -i "$d/zebra.pid" -z "$sock/zserv.api" --vty_socket "$sock" -u root -g root >/dev/null 2>&1 || return 1
  "${at[@]}" "$FRR/ospfd" -d -f "$d/ospfd.conf" -i "$d/ospfd.pid" -z "$sock/zserv.api" --vty_socket "$sock" -u root -g root >/dev/null 2>&1 || return 1
  alive "$d/zebra.pid" && alive "$d/ospfd.pid"
}

CMDS=(
  "show ip ospf neighbor detail json"
  "show ip ospf interface json"
  "show ip ospf route json"
  "show ip ospf vrf all neighbor detail json"
  "show ip ospf vrf nosuch neighbor detail json"
)
# cap NS TAG COMMAND: one vty capture into $L/TAG-<command>.raw. Its UTC stamp goes
# to $L/meta, taken before the vty connects. A failed capture keeps its output as
# .raw.failed, writes no stamp, and fails the run.
cap() {
  local ns=$1 tag=$2 cmd=$3 slug f at rc
  slug=${cmd// /_}
  f="$L/$tag-$slug.raw"
  at=$(date -u +%Y-%m-%dT%H:%M:%SZ) || return 1
  if [[ $ns = self ]]; then
    timeout 30 python3 -I "$HERE/tcpvty2.py" 2604 "$cmd" > "$f" 2>&1; rc=$?
  else
    timeout 30 nsenter -t "$ns" -n python3 -I "$HERE/tcpvty2.py" 2604 "$cmd" > "$f" 2>&1; rc=$?
  fi
  if (( rc != 0 )) || [[ ! -s $f ]]; then
    mv -f "$f" "$f.failed"
    echo "run5.sh: capture $tag $slug failed (status $rc)" >&2
    return 1
  fi
  printf '%s\n' "$at" > "$L/meta/$tag-$slug.collected_at" || return 1
}
dump() { # NS TAG
  local c
  for c in "${CMDS[@]}"; do cap "$1" "$2" "$c" || return 1; done
}

started=1
start "$L/r1" self || fail "r1 daemons did not start"
if [[ $R2_OSPF = 1 ]]; then start "$L/r2" "$R2" || fail "r2 daemons did not start"; fi
echo "daemons started; waiting for adjacency"
if [[ $MODE = nbma ]]; then
  # Early dump, before the settle window ends, to catch the static NBMA neighbor
  # in whatever state it holds then.
  sleep 15
  cap self r1-early "show ip ospf neighbor detail json" || fail "r1 early capture failed"
fi
sleep 75
if [[ $MODE = down1 ]]; then ip link set e1 down || fail "could not set r1 e1 down"; sleep 5; fi

dump self r1 || fail "r1 captures failed"
if [[ $R2_OSPF = 1 ]]; then dump "$R2" r2 || fail "r2 captures failed"; fi
echo "--- killing"
stop
echo DONE
