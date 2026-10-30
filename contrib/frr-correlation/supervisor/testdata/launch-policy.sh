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
# Every wait is bounded, and no daemon outlives the script:
#   QUERY_TIMEOUT  whole seconds the vtysh query may run before it is killed (default 10).
#   STOP_GRACE     whole seconds a daemon gets after SIGTERM before SIGKILL (default 5).
# Both are from 1 to 60. Anything else exits 9 before the script mounts or starts anything.
# A timeout or an escalation adds one line to the output; a normal run prints none. The
# daemons are also stopped, in the same way, if the script is interrupted or exits early.
#
# FRR writes /var/tmp/frr/<daemon>.<pid>/ unconditionally, so the script mounts tmpfs over
# /run, /var/lib and /var/tmp inside the private mount namespace. It refuses to run in the
# initial user namespace, and refuses a STAGE or OUT that the tmpfs mounts would hide. It
# changes nothing on the host and needs no privilege.
set -u
NAME=${1:?usage: launch-policy.sh NAME [setpriv args...]}; shift
ST=${STAGE:?set STAGE to a private copy of the FRR install}
OUT=${OUT:?set OUT to a scratch directory}
QUERY_TIMEOUT=${QUERY_TIMEOUT:-10}
STOP_GRACE=${STOP_GRACE:-5}
for v in QUERY_TIMEOUT STOP_GRACE; do # at most two digits, so the arithmetic in await cannot overflow
  if ! [[ ${!v} =~ ^[1-9][0-9]?$ ]] || ((${!v} > 60)); then
    echo "$v must be a whole number of seconds from 1 to 60, not '${!v}'" >&2; exit 9
  fi
done
read -r uid_in uid_out uid_n < /proc/self/uid_map || exit 9
[[ "$uid_in $uid_out $uid_n" != "0 0 4294967295" ]] || { echo "run under unshare -Urnm" >&2; exit 9; }
for v in STAGE OUT; do
  case $(realpath -m -- "${!v}") in
    /run | /run/* | /var/lib | /var/lib/* | /var/tmp | /var/tmp/*)
      echo "$v=${!v} would be hidden by the tmpfs mounted over /run, /var/lib and /var/tmp" >&2; exit 9 ;;
  esac
done
FRR=$ST/usr/libexec/frr
LD="$ST/usr/lib64/frr:$ST/usr/lib64:$ST/runtime/usr/lib64"
ZP='' BP=''
gone() { # gone PID: true once the process has exited, a zombie included
  local k v state=
  while IFS=: read -r k v; do
    [[ $k == State ]] && { state=${v//[[:space:]]/}; break; }
  done 2> /dev/null < "/proc/$1/status"
  [[ -z $state || $state == [ZX]* ]]
}
await() { # await PID SECONDS: true if the process exits within the time
  local i
  for ((i = 0; i < $2 * 10; i++)); do gone "$1" && return 0; sleep 0.1; done
  gone "$1"
}
stop() { # stop LABEL VAR: SIGTERM the process whose PID is in VAR, SIGKILL it after STOP_GRACE, reap it
  local label=$1 pid=${!2} note=
  [[ -n $pid ]] || return 0
  printf -v "$2" ''
  kill -TERM "$pid" 2> /dev/null
  if ! await "$pid" "$STOP_GRACE"; then
    kill -KILL "$pid" 2> /dev/null
    note="  $label stop: SIGKILL after ${STOP_GRACE}s"
    if ! await "$pid" 2; then # only an uninterruptible process gets here, and wait would not return
      echo "$note"; echo "  $label stop: still running after SIGKILL, not waited for"
      return 0
    fi
  fi
  wait "$pid"
  echo "  $label exit: $?"
  [[ -z $note ]] || echo "$note"
}
cleanup() {
  trap - EXIT
  trap '' INT TERM HUP # a second interrupt must not cut the stop short; it is bounded by the grace periods
  stop bgpd BP
  stop zebra ZP
  local left # a child the two variables missed, such as one forked just before a signal
  left=$(jobs -p)
  if [[ -n $left ]]; then
    echo "  killed unaccounted children: ${left//$'\n'/ }"
    # shellcheck disable=SC2086 # one word per PID is the point
    kill -KILL $left 2> /dev/null
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
mount -t tmpfs tmpfs /run && mount -t tmpfs tmpfs /var/lib && mount -t tmpfs tmpfs /var/tmp || exit 9
mkdir -p /run/frr
sock=/run/frr
printf 'hostname r1\nline vty\n no login\n' > "$OUT/zebra.conf"
printf 'router bgp 65001\n bgp router-id 1.1.1.1\n' > "$OUT/bgpd.conf"
POLICY=("$@")
[[ ${#POLICY[@]} -gt 0 ]] || POLICY=(--keep-groups)
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
for _ in $(seq 1 100); do [[ -S $sock/zserv.api ]] && break; kill -0 $ZP 2>/dev/null || break; sleep 0.1; done
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
# timeout runs vtysh in its own process group and signals the group, so a hung query ends here.
reply=$(timeout --kill-after=2 "$QUERY_TIMEOUT" env -i LD_LIBRARY_PATH="$LD" ASAN_OPTIONS=detect_leaks=0 HOME="$OUT" \
  "$ST/usr/bin/vtysh" -H /dev/null --vty_socket $sock -c 'show zebra client' 2>&1)
query_rc=$?
grep -q 'Client: bgp' <<< "$reply" && attached=yes
echo "  bgpd attached to zebra: $attached"
[[ $query_rc -ne 124 && $query_rc -ne 137 ]] || echo "  vtysh query: timed out after ${QUERY_TIMEOUT}s"
stop bgpd BP
stop zebra ZP
for d in zebra bgpd; do
  echo "  $d fatal: $(grep -E 'privs_init|AddressSanitizer|runtime error' "$OUT/$NAME-$d.log" | head -1 | cut -c1-160)"
done
