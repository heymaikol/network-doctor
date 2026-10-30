#!/bin/bash
# One FRR launch-policy probe for the cohort namespace supervisor. It starts zebra and
# bgpd in the foreground, applies the given setpriv policy to both, waits, records what
# the kernel reports for each process, queries zebra for its clients, then stops both
# with SIGTERM and records their exit status.
#
# Run as: STAGE=<dir> OUT=<dir> unshare -Urnm bash launch-policy.sh NAME [setpriv args...]
#   STAGE  a private copy of an FRR install: usr/libexec/frr, usr/lib64, usr/bin/vtysh and
#          runtime/usr/lib64. Never point it at an evidence archive.
#   OUT    an existing scratch directory for configs and daemon logs.
#   NAME   a label for the output.
# With no setpriv arguments the policy is --keep-groups (the control).
#
# FRR writes /var/tmp/frr/<daemon>.<pid>/ unconditionally, so the script mounts tmpfs over
# /run, /var/lib and /var/tmp inside the private mount namespace. It refuses to run in the
# initial user namespace. It changes nothing on the host and needs no privilege.
set -u
NAME=${1:?usage: launch-policy.sh NAME [setpriv args...]}; shift
ST=${STAGE:?set STAGE to a private copy of the FRR install}
OUT=${OUT:?set OUT to a scratch directory}
read -r uid_in uid_out uid_n < /proc/self/uid_map || exit 9
[[ "$uid_in $uid_out $uid_n" != "0 0 4294967295" ]] || { echo "run under unshare -Urnm" >&2; exit 9; }
FRR=$ST/usr/libexec/frr
LD="$ST/usr/lib64/frr:$ST/usr/lib64:$ST/runtime/usr/lib64"
mount -t tmpfs tmpfs /run && mount -t tmpfs tmpfs /var/lib && mount -t tmpfs tmpfs /var/tmp || exit 9
mkdir -p /run/frr
sock=/run/frr
printf 'hostname r1\nline vty\n no login\n' > "$OUT/zebra.conf"
printf 'router bgp 65001\n bgp router-id 1.1.1.1\n' > "$OUT/bgpd.conf"
POLICY=("$@")
[ ${#POLICY[@]} -gt 0 ] || POLICY=(--keep-groups)
run() { # run DAEMON ARGS...: foreground, empty environment except the library path
  local d=$1; shift
  : > "$OUT/$NAME-$d.log"
  env -i LD_LIBRARY_PATH="$LD" ASAN_OPTIONS=detect_leaks=0 HOME="$OUT" \
    setpriv "${POLICY[@]}" -- "$FRR/$d" "$@" >> "$OUT/$NAME-$d.log" 2>&1 &
}
status() { # status PID: the kernel's view of the process
  grep -E '^(CapPrm|CapEff|CapBnd|NoNewPrivs|Seccomp):' "/proc/$1/status" 2>/dev/null | tr -s '\t \n' ' ' || true
}
run zebra -f "$OUT/zebra.conf" -i $sock/zebra.pid -z $sock/zserv.api --vty_socket $sock -P 0 -u root -g root
ZP=$!
for _ in $(seq 1 100); do [ -S $sock/zserv.api ] && break; kill -0 $ZP 2>/dev/null || break; sleep 0.1; done
run bgpd -f "$OUT/bgpd.conf" -i $sock/bgpd.pid -z $sock/zserv.api --vty_socket $sock -P 0 -u root -g root
BP=$!
sleep 3
alive=""
kill -0 $ZP 2>/dev/null && alive=zebra
kill -0 $BP 2>/dev/null && alive="$alive bgpd"
echo "policy=$NAME setpriv=${POLICY[*]} setgroups=$(cat /proc/self/setgroups)"
echo "  zebra: $(status $ZP)"
echo "  bgpd:  $(status $BP)"
echo "  alive: ${alive:-none}"
attached=no
env -i LD_LIBRARY_PATH="$LD" ASAN_OPTIONS=detect_leaks=0 HOME="$OUT" "$ST/usr/bin/vtysh" -H /dev/null \
  --vty_socket $sock -c 'show zebra client' 2>&1 | grep -q 'Client: bgp' && attached=yes
echo "  bgpd attached to zebra: $attached"
kill -TERM $BP 2>/dev/null; wait $BP; echo "  bgpd exit: $?"
kill -TERM $ZP 2>/dev/null; wait $ZP; echo "  zebra exit: $?"
for d in zebra bgpd; do
  echo "  $d fatal: $(grep -E 'privs_init|AddressSanitizer|runtime error' "$OUT/$NAME-$d.log" | head -1 | cut -c1-160)"
done
