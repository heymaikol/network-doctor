#!/bin/bash
# Local single-router FRR 10.7.0 probe: what "show ip ospf json" prints when the
# OSPF instance has no router ID, has one from zebra, or does not exist.
# Run as: SCRATCH=<dir> unshare -Urnm bash unset-router-id.sh <none|addr|absent|noinst>
#   SCRATCH must hold frr-root/ extracted from the FRR 10.7.0 RPM (see ../README.md).
#   none    router ospf, no router-id, no IPv4 address on any interface
#   addr    as none, plus 10.9.9.9/32 on dummy d0, which zebra offers as the router ID
#   absent  no router ospf instance configured, and no interface address
#   noinst  an interface block for d0 and no router ospf stanza, with d0 as in addr
# Each run writes show.raw (a vtysh transcript) and show.collected_at to
# $SCRATCH/run/unset-router-id-<mode>/. A failed probe exits nonzero, leaves
# show.raw.failed in place of show.raw, and writes no show.collected_at.
set -u
S=${SCRATCH:?set SCRATCH to a directory holding frr-root/ (see README)}
MODE=${1-}
case $MODE in
  none | addr | absent | noinst) ;;
  *) echo "unset-router-id.sh: MODE must be none, addr, absent, or noinst, not '$MODE'" >&2; exit 2 ;;
esac
HERE=$(cd "$(dirname "$0")" && pwd)
TCP=$HERE/tcpvty2.py
OUT=$S/run/unset-router-id-$MODE
FRR=$S/frr-root/usr/libexec/frr
export LD_LIBRARY_PATH="$S/frr-root/usr/lib64:$S/frr-root/usr/lib64/frr"

# Stops the daemons this run started. Pid files are read only once a daemon has started, as in lsdb.sh.
cleanup() {
  local rc=$?
  if (( started )); then cat "$OUT"/*.pid 2>/dev/null | xargs -r kill 2>/dev/null; fi
  exit "$rc"
}
started=0
trap cleanup EXIT

fail() { echo "unset-router-id.sh: $*" >&2; exit 1; }

# Move the old run aside, then remove it, so a failed remove cannot leave old output at $OUT.
{ { [[ ! -e $OUT ]] || mv -T "$OUT" "$OUT.discard.$$"; } && rm -rf "$OUT.discard.$$" && mkdir -p "$OUT"; } \
  || fail "could not clear $OUT"
{ mount -t tmpfs tmpfs /run && mkdir -p /run/frr \
  && mount -t tmpfs tmpfs /var/lib && mkdir -p /var/lib/frr \
  && mount --bind "$HERE/etc/group" /etc/group \
  && mount --bind "$HERE/etc/passwd" /etc/passwd; } || fail "mount setup failed"

ip link set lo up || fail "lo up failed"
if [[ $MODE == addr || $MODE == noinst ]]; then
  { ip link add d0 type dummy && ip link set d0 up && ip addr add 10.9.9.9/32 dev d0; } || fail "d0 setup failed"
fi
printf 'hostname r1\nline vty\n no login\n' > "$OUT/zebra.conf" || fail "could not write zebra.conf"
if [[ $MODE == absent ]]; then
  printf 'hostname r1\nline vty\n no login\n' > "$OUT/ospfd.conf" || fail "could not write ospfd.conf"
elif [[ $MODE == noinst ]]; then
  printf 'hostname r1\nline vty\n no login\ninterface d0\n' > "$OUT/ospfd.conf" || fail "could not write ospfd.conf"
else
  printf 'hostname r1\nline vty\n no login\nrouter ospf\n' > "$OUT/ospfd.conf" || fail "could not write ospfd.conf"
fi

sock=/run/frr/r1
mkdir -p "$sock" || fail "could not create $sock"
started=1
"$FRR/zebra" -d -f "$OUT/zebra.conf" -i "$OUT/zebra.pid" -z "$sock/zserv.api" --vty_socket "$sock" -u root -g root || fail "zebra did not start"
"$FRR/ospfd" -d -f "$OUT/ospfd.conf" -i "$OUT/ospfd.pid" -z "$sock/zserv.api" --vty_socket "$sock" -u root -g root || fail "ospfd did not start"
sleep 5

at=$(date -u +%Y-%m-%dT%H:%M:%S.%NZ) || fail "could not read the UTC time"
timeout 30 python3 -I "$TCP" 2604 "show ip ospf json" > "$OUT/show.raw" 2>&1
rc=$?
if (( rc != 0 )) || [[ ! -s $OUT/show.raw ]]; then
  mv -f "$OUT/show.raw" "$OUT/show.raw.failed" 2>/dev/null
  fail "probe failed (status $rc)"
fi
if ! printf '%s\n' "$at" > "$OUT/show.collected_at"; then
  rm -f "$OUT/show.collected_at"
  mv -f "$OUT/show.raw" "$OUT/show.raw.failed" 2>/dev/null
  fail "could not write show.collected_at"
fi
echo "DONE $MODE"
