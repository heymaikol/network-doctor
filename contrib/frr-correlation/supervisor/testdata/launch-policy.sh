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
#   QUERY_TIMEOUT  whole seconds the vtysh query may run before it is killed (default 10; unset, not empty).
#   STOP_GRACE     whole seconds a daemon gets after SIGTERM before SIGKILL (default 5; unset, not empty).
# Both are from 1 to 60. Anything else exits 9 before the script mounts or starts anything.
# A timeout or an escalation adds one line to the output; a normal run prints none. A query
# that returned status 124 reads "status 124 (timeout or command exit)": timeout returns it
# when it ends the query at the deadline, and a query can exit 124 by itself, so the status
# alone does not say which. A query that returned status 137 reads "status 137" and nothing
# more: SIGKILL gives it, whether from the OOM killer, a person or timeout after a query that
# ignored SIGTERM, but a query can also exit 137 by itself.
# The daemons are also stopped, in the same way, if the script is interrupted or exits early.
#
# The script keeps a daemon's PID until /proc shows the process gone, and signals a PID only
# while that process is still its own child. When the /proc entry cannot be read, kill -0
# says whether a process holds the number: none means it exited and was reaped, and any
# process there leaves the state unknown. An unknown daemon is not signalled and not waited
# for, because it may be running and wait would block on it. A daemon that is still running
# 2 seconds after SIGKILL (a process in uninterruptible sleep, for one) cannot be stopped by
# any script, and nor can one the script cannot observe: the exit trap tries it once more,
# then the script names it on stderr ("may still be running") and exits 10 in place of any
# other status. SIGKILL sent to the script itself runs no trap
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
QUERY_TIMEOUT=${QUERY_TIMEOUT-10} # a default only for an unset variable: an empty one is refused below
STOP_GRACE=${STOP_GRACE-5}
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
# child_state PID: 0 if PID is not a live child of this script (exited, reaped by bash, or the number
# reused), 1 if it is a running child, 2 if the script cannot tell. Only a readable /proc/PID/stat shows a
# running child: its parent is this script and it is not a zombie. When the stat cannot be read, kill -0
# is the second witness. Bash reaps its children as they end, so no process under that number means the
# child is gone. A process there may be the child or a stranger, so the answer is 2, never 0. This script
# is root in its own user namespace, so kill -0 can fail on its child only with ESRCH, never EPERM.
child_state() {
  local stat='' state='' ppid=''
  read -r stat 2> /dev/null < "/proc/$1/stat" && read -r state ppid _ <<< "${stat##*) }" # after "(comm) ", which may hold a ")"
  if [[ -n $ppid ]]; then
    [[ $ppid == "$$" && $state != [ZX]* ]] && return 1
    return 0
  fi
  kill -0 "$1" 2> /dev/null && return 2
  return 0
}
await() { # await PID SECONDS: wait up to the time for PID to exit; status is its last child_state, 0 if it exited
  local i
  for ((i = 0; i < $2 * 10; i++)); do child_state "$1" && return 0; sleep 0.1; done
  child_state "$1"
}
stop() { # stop LABEL VAR: SIGTERM the process whose PID is in VAR, SIGKILL it after STOP_GRACE, reap it
  # VAR keeps the PID until the process is confirmed gone, so a later call can try again. A
  # process that is no longer a child of this script is never signalled: its PID may be someone else's.
  # A process whose state cannot be read is neither signalled nor waited for: it may be running, and
  # wait would block on it. Only a process shown to have exited is waited for.
  local label=$1 pid=${!2} note='' rc st
  [[ -n $pid ]] || return 0
  child_state "$pid"; st=$?
  if ((st == 2)); then
    echo "  $label stop: cannot read the state of pid $pid, not signalled and not waited for"; return 1
  elif ((st == 1)); then
    kill -TERM "$pid" 2> /dev/null
    await "$pid" "$STOP_GRACE"; st=$?
    if ((st == 2)); then
      echo "  $label stop: cannot read the state of pid $pid after SIGTERM, not killed and not waited for"; return 1
    elif ((st == 1)); then
      kill -KILL "$pid" 2> /dev/null
      note="  $label stop: SIGKILL after ${STOP_GRACE}s"
      await "$pid" 2; st=$?
      if ((st != 0)); then # only an uninterruptible process gets here, and wait would not return
        echo "$note"
        if ((st == 1)); then echo "  $label stop: still running after SIGKILL, not waited for"
        else echo "  $label stop: cannot read the state of pid $pid after SIGKILL, not waited for"; fi
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
  local p st left=() strays=()
  for p in $(jobs -p); do # a child the two variables missed, such as one forked just before a signal
    [[ $p == "$BP" || $p == "$ZP" ]] && continue
    child_state "$p"; st=$?
    if ((st == 1)); then left+=("$p"); elif ((st == 2)); then strays+=("$p"); fi # 2 is reported, never signalled
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
case $query_rc in # both statuses are reported as numbers: neither proves its usual cause
  124) echo "  vtysh query: status 124 (timeout or command exit)" ;; # timeout returns 124, and so can a query
  137) echo "  vtysh query: status 137" ;; # 128 plus SIGKILL, from the OOM killer, a person or timeout, or an exit of 137
esac
stop bgpd BP
stop zebra ZP
for d in zebra bgpd; do
  echo "  $d fatal: $(grep -E 'privs_init|AddressSanitizer|runtime error' "$OUT/$NAME-$d.log" | head -1 | cut -c1-160)"
done
