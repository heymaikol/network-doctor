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
# Every wait is bounded, and the script tries to stop both daemons before it ends:
#   QUERY_TIMEOUT  whole seconds the vtysh query may run before it is killed (default 10).
#   STOP_GRACE     whole seconds a daemon gets after SIGTERM before SIGKILL (default 5).
# Both are from 1 to 60. Anything else exits 9 before the script mounts or starts anything.
# A timeout or an escalation adds one line to the output; a normal run prints none. A query
# that timeout ended at its deadline (status 124) reads "timed out". A query that died of
# SIGKILL (status 137) reads "ended by SIGKILL ... cause not confirmed": the status does not
# say who sent the signal, and timeout returns it too after a query that ignored SIGTERM.
# The daemons are also stopped, in the same way, if the script is interrupted or exits early.
#
# The script keeps a daemon's PID until /proc shows the process gone, and signals a PID only
# while that process is still its own child. A daemon that is still running 2 seconds after
# SIGKILL (a process in uninterruptible sleep, for one) cannot be stopped by any script: the
# exit trap tries it once more, then the script names it on stderr ("may still be running")
# and exits 10 in place of any other status. SIGKILL sent to the script itself runs no trap
# and leaves the daemons behind. The check of /proc is not a pidfd, so a PID reused between
# the check and the signal is possible in principle.
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
gone() { # gone PID: true once PID is not a live child of this script (exited, reaped by bash, or the number reused)
  local stat state ppid
  read -r stat 2> /dev/null < "/proc/$1/stat" || return 0
  read -r state ppid _ <<< "${stat##*) }" # the fields after "(comm) ", which may itself hold a ")"
  [[ $ppid != "$$" || $state == [ZX]* ]]
}
await() { # await PID SECONDS: true if the process exits within the time
  local i
  for ((i = 0; i < $2 * 10; i++)); do gone "$1" && return 0; sleep 0.1; done
  gone "$1"
}
stop() { # stop LABEL VAR: SIGTERM the process whose PID is in VAR, SIGKILL it after STOP_GRACE, reap it
  # VAR keeps the PID until the process is confirmed gone, so a later call can try again. A
  # process that is no longer a child of this script is never signalled: its PID may be someone else's.
  local label=$1 pid=${!2} note='' rc
  [[ -n $pid ]] || return 0
  if ! gone "$pid"; then
    kill -TERM "$pid" 2> /dev/null
    if ! await "$pid" "$STOP_GRACE"; then
      kill -KILL "$pid" 2> /dev/null
      note="  $label stop: SIGKILL after ${STOP_GRACE}s"
      if ! await "$pid" 2; then # only an uninterruptible process gets here, and wait would not return
        echo "$note"; echo "  $label stop: still running after SIGKILL, not waited for"
        return 1
      fi
    fi
  fi
  printf -v "$2" '' # before wait: once the process is gone nothing is left to retry
  wait "$pid"
  rc=$?
  echo "  $label exit: $rc"
  [[ -z $note ]] || echo "$note"
}
cleanup() {
  trap - EXIT
  trap '' INT TERM HUP # a second interrupt must not cut the stop short; it is bounded by the grace periods
  stop bgpd BP # a call that already failed is tried once more here, because VAR still holds the PID
  stop zebra ZP
  local p left=() strays=()
  for p in $(jobs -p); do # a child the two variables missed, such as one forked just before a signal
    [[ $p == "$BP" || $p == "$ZP" ]] || gone "$p" || left+=("$p")
  done
  if ((${#left[@]})); then
    echo "  killed unaccounted children: ${left[*]}"
    kill -KILL "${left[@]}" 2> /dev/null
    for p in "${left[@]}"; do await "$p" 2 || strays+=("$p"); done
  fi
  [[ -n $BP$ZP || ${#strays[@]} -gt 0 ]] || return 0
  { # a failed cleanup is never silent and never ends in a success status
    [[ -z $BP ]] || echo "launch-policy: bgpd (pid $BP) may still be running"
    [[ -z $ZP ]] || echo "launch-policy: zebra (pid $ZP) may still be running"
    [[ ${#strays[@]} -eq 0 ]] || echo "launch-policy: unaccounted children may still be running: ${strays[*]}"
  } >&2
  exit 10
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
case $query_rc in # 137 is SIGKILL from anyone (the OOM killer, a person, or timeout after a query that ignored SIGTERM)
  124) echo "  vtysh query: timed out after ${QUERY_TIMEOUT}s" ;;
  137) echo "  vtysh query: ended by SIGKILL (status 137), cause not confirmed" ;;
esac
stop bgpd BP
stop zebra ZP
for d in zebra bgpd; do
  echo "  $d fatal: $(grep -E 'privs_init|AddressSanitizer|runtime error' "$OUT/$NAME-$d.log" | head -1 | cut -c1-160)"
done
