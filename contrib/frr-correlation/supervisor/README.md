# FRR cohort namespace supervisor

This is the second slice of [issue #390](https://github.com/heymaikol/network-doctor/issues/390).
It is a Linux-only Go library that owns the lifetime of one rootless user and
network namespace pair and of the processes launched into it. It launches,
observes and cleans up. It does not authenticate or import evidence, advance a
`collector.Lifecycle`, freeze captures, package a bundle, hand anything off, or
rate forwarding. It imports nothing from `collector` and changes no certified
FRR producer, historical certificate or captured evidence.

## What it provides

`NewNamespace` starts a holder process (`sleep infinity`, empty environment) in
new user and network namespaces. It reads the holder's namespaces through
`pidfd` ioctls (`PIDFD_GET_USER_NAMESPACE`, `PIDFD_GET_NET_NAMESPACE`), so no
`/proc/<pid>` lookup is involved, and keeps both descriptors open. It refuses a
pair unless the user namespace owns the network namespace and both differ from
the supervisor's own. The holder is never reaped until `Close`, so its PID
cannot be reissued while the supervisor uses it.

`Namespace.Start` launches a program through `nsenter --target <holder> --user
--net --preserve-credentials` and accepts the child only after the child's own
`pidfd` reports exactly the retained pair. A child that stays in the
supervisor's namespaces, lands in a third pair, or exits before it reaches the
retained pair is killed, reaped and refused. A leader whose namespaces cannot be
read is given up to 50 ms to show that it is exiting, because a dying process
loses its namespaces just before it becomes a zombie, and is refused as a launch
failure if it does. One that stays alive and unreadable is refused as a
namespace mismatch.

`nsenter` enters the namespaces and only then execs, so a program it cannot run
leaves a window in which the child already holds the retained pair. `Start` may
refuse such a child or return it with `Done` closing at once, depending on which
the supervisor sees first. Verification is a point in time, and a caller treats
a child that exits right after `Start` like any other exit. The child runs in its own process group with
`Pdeathsig` set. It gets exactly the environment the caller passes, standard
input from `/dev/null`, and only the standard output and error files the caller
passes. `Start` refuses if the supervisor holds any inheritable
descriptor above 2, if the program path is not absolute, or if the namespace is
closing, closed or unclean.

`Child.Stop` sends SIGTERM to the child's process group while the leader is
still unreaped, waits the grace period, escalates to SIGKILL, sweeps the group
once the leader is a zombie, and reaps last. `Namespace.Close` stops every
child, then kills and reaps the holder and closes both descriptors.

## Cleanup that cannot be proven complete

A child is registered with its namespace as soon as the process exists, before
its namespaces are verified, and leaves the registry only when `Stop` has reaped
it. So a child whose verification failed and whose stop then also failed is still
accounted for. Whenever a leader cannot be shown reaped, `Stop` returns an error
wrapping `ErrCleanupIncomplete`, and:

- the namespace refuses new children from then on, whether `Stop` was called by
  `Close`, by `Start` cleaning up a refused child, or by the caller;
- the child keeps its pidfd and stays registered, and `Stop` can be called again;
- `Close` does not release the namespace descriptors or the holder while any
  child is unaccounted for. It returns the error and keeps every handle, and the
  next `Close` retries. `Close` returns nil, and keeps returning nil, only after
  everything is released;
- `NewNamespace` has the same rule: if releasing a half-built namespace fails, it
  returns the unusable `Namespace` together with the error so `Close` can retry.
  Check the namespace before the error when handling a failed constructor.

Process groups are signalled by number, so a retry must never signal a group ID
that was reissued. Before every group signal, `Stop` and the holder cleanup ask
the leader's pidfd whether it is still an unreaped child, through a non-blocking
`waitid` that never reaps. A state that cannot be read is treated as unknown, not
as an exit. Without that proof the group is not signalled: only the leader is
signalled, through the pidfd, which names exactly that process. The final sweep
needs the proof, so a leader that cannot be shown unreaped is not reaped either
(`ErrObservationLost` joins `ErrCleanupIncomplete`) and is left for a retry. The
proof rests on the supervisor being the only reaper of its children. A third
party that reaps a child between the probe and the signal is outside what this
package defends against.

Observing a child is separate from stopping it. A watcher goroutine blocks in
`waitid` on the child's pidfd and closes `Done` when it proves the exit. If that
`waitid` fails, nothing is proven: `Done` stays open, `Lost` is closed instead,
and `Start` reports `ErrObservationLost` for a child it was still verifying, not
`ErrLaunchFailed`. `Stop` does not depend on the watcher. It reads the pidfd
itself every 10 ms, so a lost watcher cannot hide an exit, and it ends the wait
at once if the pidfd reports that the child was reaped elsewhere. A caller that
waits on `Done` alone can wait forever after an observation failure, so it should
also select on `Lost`. `Stop` waits for the watcher to finish before it closes
the pidfd, so the descriptor number cannot be reused under a watcher that is
still reading it.

A retry is the supervised recovery path. If the process is already gone and
reaped by someone else, nothing can prove its cleanup and every retry fails the
same way. The namespace then stays pinned until the supervisor process exits,
and the holder and the children die with it through `Pdeathsig`.

The supervisor never calls `unshare` or `setns` on a Go thread. Everything that
changes namespaces happens in a child process.

## What it does not do

These are deliberate scope cuts, not oversights. None is claimed to hold.

- **No executable provenance.** The child's executable is an observation only.
  Nothing here ties a running process to a certified FRR artifact.
- **Helper binaries are trusted by name.** The holder (`sleep`) and `nsenter`
  are resolved through the supervisor's `PATH` with `exec.LookPath` and are not
  verified. `nsenter` comes from util-linux and must be installed. Whoever can
  alter that `PATH` or those binaries already runs code as the supervisor's UID.
- **No isolation of the supervisor from its children.** The children run as the
  same host UID and share the host mount namespace, so they can read and write
  every file the supervisor can, including any future inbox. FRR is root inside
  the user namespace, which maps to the supervisor's UID outside. Probed with a
  stand-in process in a child user namespace on the test host (not with FRR):
  `kill -0` on a same-UID host process succeeded, while reading its `environ` and
  `maps` was denied and `PTRACE_SEIZE` failed with EPERM. So a child can signal
  (and therefore stop or kill) the supervisor but, without `CAP_SYS_PTRACE` over
  it, apparently cannot trace it. The producer-to-supervisor boundary is still
  not established.
- **Namespace membership is verified at one moment.** A child that holds
  `CAP_SYS_ADMIN` in the user namespace can create further namespaces later.
  FRR requests that capability (see below), so this is a real gap.
- **No PID namespace, cgroup, mount namespace or seccomp policy.** A descendant
  that calls `setsid` leaves the process group and survives the group kill. FRR
  also writes `/var/tmp/frr/<daemon>.<pid>/` unconditionally, so a mount
  namespace is required for any real FRR launch and belongs to a later slice.
- **`Pdeathsig` fires when the creating OS thread exits, not the process.**
  Killing the whole supervisor is tested with the Go test helper as the child.
  The kernel clears the parent-death signal on some credential changes, and FRR
  changes credentials after it starts, so whether FRR children die with the
  supervisor is untested. A supervisor that retires one thread is also untested.
- **PID wraparound is not forced.** The holder and each leader stay unreaped
  while they are signalled, so the kernel cannot reissue their PID or process
  group ID. `TestExitedProcessesKeepTheirPIDUntilReaped` checks that an exited
  child and holder remain zombies until reaped. It does not wrap the PID space.
- **The descriptor check is a point-in-time scan** of `/proc/self/fd` for
  non-`CLOEXEC` descriptors above 2. A descriptor opened between the scan and
  the exec is covered only by Go's own `CLOEXEC` default.
- **Kernel support.** The `pidfd` namespace ioctls need Linux 6.11 or later.
  Without them `NewNamespace` returns `ErrUnsupported` and the tests skip, unless
  `NETDOC_SIM_REQUIRE_NETNS` is set, in which case they fail. Only kernel
  7.2.11 was exercised.

## FRR 10.7.0 launch policy

The launch-policy question is whether FRR 10.7.0 `zebra` and `bgpd` tolerate a
policy that would let a supervisor confine them more tightly. The answer, for
the one build tested, is that they do not tolerate losing `CAP_SYS_ADMIN`.

**Build tested.** An ASAN and UBSAN build of FRR source commit `87fe21fd` (`zebra`
and `bgpd` both report version 10.7.0), run from a private copy of the
instrumented install, on kernel 7.2.11 inside a rootless user namespace. It is
not the certified production artifact. The claims below are worded for this
build only. They say nothing about the release build, other kernels, other
distributions or another FRR version.

**Method.** `testdata/launch-policy.sh` runs both daemons in the foreground
(not `-d`, which daemonizes) with an empty environment except the library path
and `ASAN_OPTIONS=detect_leaks=0`, under `unshare -Urnm` with tmpfs mounted over
`/run`, `/var/lib` and `/var/tmp`. It applies a `setpriv` policy, waits three
seconds, records `/proc/<pid>/status`, asks zebra for its clients through
`vtysh`, then sends SIGTERM and records both exit statuses. The control ran first
and passed. The evidence archive was not executed or modified: the install was
copied first, and the SHA-256 of the eight binaries and libraries copied from
it was unchanged afterwards. No file under the archive tree had a newer
modification time.

| Policy (`setpriv`) | Daemons start | bgpd attached to zebra | SIGTERM exit |
| --- | --- | --- | --- |
| `--keep-groups` (control) | yes | yes | 0 and 0 |
| plus `--no-new-privs` | yes | yes | 0 and 0 |
| `--bounding-set -sys_admin` | no | no | 1 and 1 |
| `--no-new-privs --bounding-set -sys_admin` | no | no | 1 and 1 |
| `--no-new-privs`, bounding set limited to 10 capabilities (`SYS_ADMIN`, `NET_ADMIN`, `NET_RAW`, `NET_BIND_SERVICE`, `SETUID`, `SETGID`, `SETPCAP`, `DAC_OVERRIDE`, `CHOWN`, `KILL`) | yes | yes | 0 and 0 |
| `--no-new-privs`, bounding set limited to `SYS_ADMIN`, `NET_ADMIN`, `NET_RAW`, `NET_BIND_SERVICE` | yes | yes | 0 and 0 |
| `--no-new-privs --bounding-set -all` | no | no | 1 and 1 |

Every failing row logs `privs_init: initial cap_set_proc failed: Operation not
permitted` from both daemons. In every run `/proc/self/setgroups` read `deny`,
which is what `unshare --map-root-user` produces, and `-u root -g root` worked
under it.

After FRR drops its effective capabilities, `CapEff` is empty and the permitted
set that remains is `0x203000` for zebra (`NET_ADMIN`, `NET_RAW`, `SYS_ADMIN`)
and `0x203400` for bgpd (`NET_BIND_SERVICE`, `NET_ADMIN`, `NET_RAW`,
`SYS_ADMIN`). Both daemons keep `CAP_SYS_ADMIN` available for the rest of their
life. Removing it from the bounding set is not a compatible launch policy for
this build, and this slice does not weaken isolation to work around that.
`no_new_privs` and a smaller bounding set are compatible.

Not tested: seccomp filters, `RLIMIT` limits, a PID namespace, a cgroup,
supplementary groups other than the inherited set, and any run longer than a
few seconds.

`TestFRRRunsUnderTheSupervisor` is the in-repo check that the supervisor's own
launch path works for this build. It runs zebra and bgpd as supervisor-owned
children, wraps each in a private mount namespace with a tmpfs over `/var/tmp`
so FRR writes nothing to the host, waits for bgpd to appear in `show zebra
client`, then stops both and requires exit code 0, no escalation and reaping. It
skips unless `NETDOC_FRR_STAGE` names a private copy of the install, so it never
counts as passed on a machine without FRR.

## Tested failure cases

All of these run in the `netns_integration` tests against real rootless
namespaces on the test host. The cleanup-failure rows inject the failure of one
kernel operation (a dropped signal, a failed reap) through a per-namespace table
in `sys_linux.go`; the process itself is real and is stopped and reaped by the
same test once the fault is turned off. Nothing else is modeled.

| Case | Test |
| --- | --- |
| Namespaces retained, isolated from the supervisor's, released on close | `TestNamespaceIsRetainedIsolatedAndReleased` |
| Namespace destroyed and recreated never matches a released identity | `TestDestroyAndRecreateNeverComparesReleasedIdentity` |
| Holder killed before inspection: refused, nothing leaked | `TestHolderKilledBeforeInspectionRefusesAndLeaksNothing` |
| Holder killed while held: close still cleans up | `TestHolderKilledWhileHeldStillCleansUp` |
| Context cancelled during creation | `TestCancelledStartCreatesNothing` |
| Concurrent close | `TestConcurrentCloseIsSafe` |
| Child runs in the retained pair, as root in the user namespace | `TestChildRunsInTheRetainedNamespaces` |
| Child inherits no descriptor above 2 | `TestChildInheritsNoDescriptors` |
| Leaked non-`CLOEXEC` descriptor refuses `Start` | `TestLeakedDescriptorRefusesStart` |
| SIGKILL only when SIGTERM is ignored | `TestStopEscalatesOnlyWhenTermIsIgnored` |
| Daemonized grandchild that ignores SIGTERM dies with the group | `TestDaemonizedGrandchildDiesWithTheGroup` |
| Child in a third namespace pair: refused and reaped | `TestChildInAThirdNamespaceIsRefusedAndReaped` |
| Child left in the supervisor's namespaces: killed and reaped on deadline | `TestCancelWhileChildIsInTheSupervisorsNamespaces` |
| Child exits before reaching the retained pair: refused and reaped | `TestChildThatExitsDuringStartIsRefused` |
| Program `nsenter` cannot exec: refused, or returned with `Done` closing, and reaped either way | `TestChildThatFailsToExecAfterEnteringTheNamespaces` |
| Child that dies while its namespaces are unreadable is a launch failure | `TestChildLeavingWhileItsNamespacesAreUnreadableIsALaunchFailure` |
| Child that stays alive and unreadable is a mismatch | `TestRunningChildWithUnreadableNamespacesIsAMismatch` |
| Relative program path | `TestRelativeProgramIsRefused` |
| `Close` stops running children and refuses new ones | `TestCloseStopsRunningChildrenAndRefusesNewOnes` |
| Concurrent `Start`, `Stop` and `Close` under the race detector | `TestConcurrentStartStopAndClose` |
| Verification fails, then the stop fails: child stays registered, launches refused | `TestVerifyFailureThenStopFailureKeepsTheChildAccounted` |
| A failed `Close` keeps the pins and succeeds on retry | `TestCloseKeepsPinsWhileAChildIsNotProvenReaped` |
| A holder that cannot be reaped is retried by another `Close` | `TestFailedHolderReapIsRetriedByAnotherClose` |
| Constructor cleanup fails: the namespace is returned with the error | `TestConstructorCleanupFailureKeepsTheHolderHandle` |
| A failed reap is an error, not a panic, and is retryable | `TestReapFailureIsReportedAndRetryable` |
| A failed `Stop` made by the caller blocks launches | `TestStopFailureByTheCallerBlocksFurtherLaunches` |
| Concurrent `Close` and `Start` while cleanup keeps failing | `TestConcurrentCloseRetriesAfterFailure` |
| A failed watcher `waitid` is not an exit: `Done` stays open, `Stop` still proves it | `TestUnexpectedWaitErrorIsNotReportedAsAnExit` |
| Watcher lost while a child starts: `ErrObservationLost`, child stopped, namespace usable | `TestWatcherLostDuringStartIsNotALaunchFailure` |
| `Stop` keeps the pidfd open until the watcher has ended | `TestStopWaitsForTheWatcherBeforeClosingThePidfd` |
| A leader that cannot be read is never signalled as a group | `TestUnreadableLeaderIsNeverSignalledAsAGroup` |
| A child reaped by another process: no group signal, terminal, pinned | `TestChildReapedByAnotherProcessIsTerminalAndNeverSignalledAsAGroup` |
| Supervisor killed: holder and a Go helper child die with it | `TestSupervisorKilledTakesHolderAndChildWithIt` |
| Exited child and holder keep their PID as zombies until reaped | `TestExitedProcessesKeepTheirPIDUntilReaped` |
| FRR launch, attach, clean stop, reaping | `TestFRRRunsUnderTheSupervisor` (needs `NETDOC_FRR_STAGE`) |

The descriptor scan also has a rootless unit test in `fds_linux_test.go`.

## Validation

```sh
go test -count=1 ./contrib/frr-correlation/supervisor
go test -race -count=1 -tags netns_integration ./contrib/frr-correlation/supervisor
NETDOC_FRR_STAGE=<private copy> go test -count=1 -tags netns_integration -run FRR ./contrib/frr-correlation/supervisor
./scripts/check --race
```

Without the `netns_integration` tag only the descriptor-scan unit test runs.
`scripts/check` compile-checks the other supported platforms, where the package
reduces to a stub that returns `ErrUnsupported`.

The hosted `linux (coverage)` job runs a probe test first, with
`NETDOC_SIM_REQUIRE_NETNS` cleared. If the probe passes, the runner can host
rootless namespaces, and the whole tagged package then runs with `-race` and the
variable set, so a skip or a failure fails the job. If the probe skips, the job
prints a warning that names the reason and passes, so a runner without the
required kernel or policy does not turn the job permanently red. The job log
shows which of the two happened on a given run. Every host-dependent skip in the
tagged tests goes through one helper that fails instead when the variable is set. The
FRR test still skips there, because no FRR copy is staged.
