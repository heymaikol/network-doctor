#!/bin/bash
# Local two-router FRR 10.7.0 lab, one scenario per run, inside user+mount+net namespaces.
# No host network change. Output is read over each daemon's loopback TCP vty from inside its netns.
# Run as: SCRATCH=<dir> unshare -Urnm bash run5.sh <bcast|p2p|mtu|empty|nbma|noinst|area|secondary>
#   SCRATCH must hold frr-root/ extracted from the FRR 10.7.0 RPM (see ../README.md).
#   bcast   broadcast adjacency, r1 DR/Backup pair, passive stub on r1
#   p2p     point-to-point adjacency
#   mtu     r2 e2 MTU 1400 vs 1500, adjacency held below Full
#   empty   r1 only, no peer daemon, valid empty neighbor list
#   nbma    r1 non-broadcast with static neighbor 10.0.1.2, peer absent, RID unknown
#   noinst  r2 ospfd running with no router ospf stanza
#   area    r2 puts e2 in area 0.0.0.1 while r1 keeps e1 in 0.0.0.0, so no adjacency forms
#   secondary  r1 adds 10.0.2.1/24 to e1 in area 0.0.0.1, so e1 holds two OSPF interfaces
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
S=${SCRATCH:?set SCRATCH to a directory holding frr-root/ (see README)}
MODE=$1
L=$S/run/$MODE
FRR=$S/frr-root/usr/libexec/frr
export LD_LIBRARY_PATH="$S/frr-root/usr/lib64:$S/frr-root/usr/lib64/frr"

mount -t tmpfs tmpfs /run && mkdir -p /run/frr
mount -t tmpfs tmpfs /var/lib && mkdir -p /var/lib/frr
mount --bind "$HERE/etc/group" /etc/group
mount --bind "$HERE/etc/passwd" /etc/passwd

rm -rf "$L"; mkdir -p "$L/r1" "$L/r2" "$L/meta"
"$FRR/ospfd" --version > "$L/meta/ospfd-version.txt" 2>&1

unshare -n sleep 3600 &
R2=$!
sleep 0.5
ip link add e1 type veth peer name e2
ip link set e2 netns $R2
ip link set lo up
ip link set e1 up
ip addr add 10.0.1.1/24 dev e1
[ "$MODE" = secondary ] && ip addr add 10.0.2.1/24 dev e1
ip link add stub1 type dummy; ip link set stub1 up; ip addr add 10.10.1.1/24 dev stub1
nsenter -t $R2 -n sh -c 'ip link set lo up; ip link set e2 up; ip addr add 10.0.1.2/24 dev e2; ip link add stub2 type dummy; ip link set stub2 up; ip addr add 10.10.2.1/24 dev stub2'
[ "$MODE" = mtu ] && nsenter -t $R2 -n ip link set e2 mtu 1400
nsenter -t $R2 -n ip -o link show e2 | grep -o 'mtu [0-9]*' > "$L/meta/r2-e2-mtu.txt"

P2P=""; NBMA=""; R1_NEIGH=""; R1_SECOND=""; R2_OSPF=1; R2_AREA=0.0.0.0
case "$MODE" in
  p2p) P2P="ip ospf network point-to-point" ;;
  nbma) NBMA="ip ospf network non-broadcast"; R1_NEIGH=" neighbor 10.0.1.2"; R2_OSPF=0 ;;
  empty) R2_OSPF=0 ;;
  area) R2_AREA=0.0.0.1 ;;
  secondary) R1_SECOND=" network 10.0.2.0/24 area 0.0.0.1" ;;
esac

cat > "$L/r1/ospfd.conf" <<CONF
hostname r1
line vty
 no login
interface e1
 $P2P$NBMA
router ospf
 ospf router-id 1.1.1.1
 network 10.0.1.0/24 area 0.0.0.0
 network 10.10.1.0/24 area 0.0.0.0
 passive-interface stub1
$R1_SECOND
$R1_NEIGH
CONF
if [ "$MODE" = noinst ]; then
cat > "$L/r2/ospfd.conf" <<CONF
hostname r2
line vty
 no login
interface e2
CONF
else
cat > "$L/r2/ospfd.conf" <<CONF
hostname r2
line vty
 no login
interface e2
 $P2P
router ospf
 ospf router-id 2.2.2.2
 network 10.0.1.0/24 area $R2_AREA
 network 10.10.2.0/24 area $R2_AREA
CONF
fi
: > "$L/r1/zebra.conf"; : > "$L/r2/zebra.conf"

# Unix socket paths must fit sun_path (108 bytes). The scratch path does not,
# so each node gets a short directory under the per-run /run tmpfs.
start() { # dir, netns-pid or self
  local d=$1 ns=$2 sock=/run/frr/$(basename "$1")
  mkdir -p "$sock"
  local run="$FRR/zebra -d -f $d/zebra.conf -i $d/zebra.pid -z $sock/zserv.api --vty_socket $sock -u root -g root && $FRR/ospfd -d -f $d/ospfd.conf -i $d/ospfd.pid -z $sock/zserv.api --vty_socket $sock -u root -g root"
  if [ "$ns" = self ]; then sh -c "$run" >/dev/null 2>&1; else nsenter -t "$ns" -n sh -c "$run" >/dev/null 2>&1; fi
}
start "$L/r1" self
[ "$R2_OSPF" = 1 ] && start "$L/r2" $R2
echo "daemons started; waiting for adjacency"
if [ "$MODE" = nbma ]; then
  # Early dump, before the settle window ends, to catch the static NBMA neighbor
  # in whatever state it holds then.
  sleep 15
  date -u +%Y-%m-%dT%H:%M:%SZ > "$L/meta/r1-early-show_ip_ospf_neighbor_detail_json.collected_at"
  timeout 30 python3 -I "$HERE/tcpvty2.py" 2604 "show ip ospf neighbor detail json" > "$L/r1-early-show_ip_ospf_neighbor_detail_json.raw" 2>&1
fi
sleep 75

CMDS=(
  "show ip ospf neighbor detail json"
  "show ip ospf interface json"
  "show ip ospf vrf all neighbor detail json"
  "show ip ospf vrf nosuch neighbor detail json"
)
dump() { # netns-pid-or-self, tag
  local ns=$1 tag=$2
  for c in "${CMDS[@]}"; do
    slug=$(echo "$c" | tr ' ' '_')
    date -u +%Y-%m-%dT%H:%M:%SZ > "$L/meta/$tag-$slug.collected_at"
    f="$L/$tag-$slug.raw"
    if [ "$ns" = self ]; then timeout 30 python3 -I "$HERE/tcpvty2.py" 2604 "$c" > "$f" 2>&1
    else timeout 30 nsenter -t "$ns" -n python3 -I "$HERE/tcpvty2.py" 2604 "$c" > "$f" 2>&1; fi
  done
}
dump self r1
if [ "$R2_OSPF" = 1 ]; then dump $R2 r2; fi
echo "--- killing"
kill $(cat "$L"/r1/*.pid "$L"/r2/*.pid 2>/dev/null) 2>/dev/null
kill $R2 2>/dev/null
echo DONE
