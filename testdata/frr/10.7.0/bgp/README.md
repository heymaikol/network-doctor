# FRR 10.7.0 BGP evidence

Original output from a successful two-router, isolated FRR 10.7.0 lab run
on 2026-10-13 UTC. The 14 source files were copied byte-for-byte from
the operator's preserved run and verified against their originals.

`steady/` contains four unmodified VTY transcripts, their four UTC
collection timestamps, four daemon configurations, two daemon version
records, and `SHA256SUMS`.

## Observed sessions

| Node | Peer | Remote AS | Reported state |
| --- | --- | --- | --- |
| r1 | 10.0.1.2 | 65002 | Established |
| r1 | 10.0.1.3 | 65003 | Active |
| r2 | 10.0.1.1 | 65001 | Established |

The session state is the JSON `state` field, not `peerState`.

## Observed prefix

r1 reports `10.10.2.0/24` with `peerId` 10.0.1.2, AS path
65002, and `pathFrom` external. This is evidence of a BGP-learned
route from r2.

r2 reports the same prefix with `peerId` `(unspec)`, an empty
AS path, and next hop 0.0.0.0. Its saved configuration originates
the prefix locally.

The JSON `origin` value `IGP` is a BGP ORIGIN attribute. It does
not identify OSPF as the source protocol.

## Boundaries

The reports describe BGP control-plane state at separate collection
times. They do not establish kernel FIB installation, route forwarding,
ongoing session health, or simultaneous network state.

The raw capture bytes must not be normalized or reformatted.
`SHA256SUMS` records the exact preserved file contents.

## Withdrawal run

`withdraw/` is original output from one three-router FRR 10.7.0 run of
`lab/bgp-withdraw.sh` on 2026-10-16 UTC. It holds r1's summary and table
transcripts for three phases, their six UTC collection timestamps, the six
daemon configurations, the bgpd and zebra version records, and `SHA256SUMS`.
Each file was copied byte for byte from the run directory and compared with
its original.

r1 (AS 65001) peers with r2 (AS 65002) at 10.0.1.2 and with r3 (AS 65003)
at 10.0.3.3. r2 withdraws a prefix by deleting the stub address that its
`network` statement imports, so its session stays up. Paths are listed by
`peerId`, in FRR's order:

| Phase | Change at r2 | r1 paths |
| --- | --- | --- |
| before | none | 10.10.1.0/24: `(unspec)`, 10.0.1.2; 10.10.2.0/24: 10.0.1.2, 10.0.3.3; 10.10.3.0/24: 10.0.3.3; 10.10.9.0/24: 10.0.1.2 |
| after1 | deleted 10.10.2.2/24 | 10.10.2.0/24: 10.0.3.3; the rest as before |
| after2 | also deleted 10.10.9.2/24 and 10.10.1.2/24 | 10.10.1.0/24: `(unspec)`; 10.10.9.0/24 absent; the rest as after1 |

Every summary shows both sessions Established with no dropped connection.

`internal/app/frr_bgp_withdraw_test.go` reads a `--withdraw-bgp` prediction
from one phase and checks it against the table FRR printed in the next. That
shows FRR removed exactly the withdrawing peer's paths for the prefix and kept
the other peer's path, the locally originated path, the peer's other prefixes,
and the session. It does not show a zebra RIB or kernel FIB, which were not
captured. The run has no peer that sends a path only after another is
withdrawn, and no route reflector, multipath, add-path, graceful restart, or
policy.

## Session-loss runs

`session/plain`, `session/gr`, and `session/admin` are original output from
three FRR 10.7.0 runs of `lab/bgp-session.sh` on 2026-10-16 UTC, one per arm.
Each holds, for every phase, r1's summary, table, and `show ip bgp neighbors
10.0.1.2 json` transcripts and r1's kernel IPv4 routes (`ip -j -4 route show`),
each with a UTC collection timestamp, plus the six daemon configurations, the
bgpd and zebra version records, the daemon logs, `events.log` with the UTC time
of the failure, and `SHA256SUMS`. `admin` also holds `r1-shutdown.raw`, the vty
transcript of the shutdown. Each file was copied byte for byte from the run
directory and compared with its original. An earlier `admin` run passed the same
checks and was set aside unchanged only because it named the shutdown
transcript `.vty`, which Git would have stored with LF line ends.

The routers, addresses, and `network` statements are those of the withdrawal
run, and every `before` phase lists the same paths. In each arm r1 loses its
session with r2 at 10.0.1.2, and r3's session stays Established:

| Arm | Failure | Phase | 10.0.1.2 state / peerState | r1 paths from 10.0.1.2 |
| --- | --- | --- | --- | --- |
| plain | SIGKILL r2's bgpd, FRR defaults | after | Active / OK | none |
| gr | SIGKILL r2's bgpd, r2 configured `bgp graceful-restart` and `restart-time 30` | during | Active / NSF passive | all three still listed, each `"stale": true` |
| gr | the same, r2 not restarted | expired | Active / OK | none |
| admin | `neighbor 10.0.1.2 shutdown` on r1, r2 configured as in gr | after | Idle (Admin) / Admin | none, and no stale key |

In every phase without paths from 10.0.1.2, r1 lists 10.10.1.0/24 from
`(unspec)`, 10.10.2.0/24 and 10.10.3.0/24 from 10.0.3.3, and no 10.10.9.0/24.
No path carries a stale key except r2's paths in `gr/during`. The neighbor
capture shows `remoteGrMode` `Helper` (plain) or `Restart` (gr, admin) before the
loss and `NotApplicable` after it, so the remote mode was visible only while the
session was up.

`internal/app/frr_bgp_session_test.go` checks the bytes, that every path not
from 10.0.1.2 keeps its prefix, `peerId`, `pathFrom`, AS path, BGP origin, and
next hops in every later phase with no path added, and the states, stale keys,
and graceful-restart modes above. FRR did change dynamic fields of those paths:
r3's path for 10.10.2.0/24 became `bestpath` with a new `version` and
`selectionReason` once r2's path was gone, and the `(unspec)` path's
`selectionReason` changed. The test lists those changes and does not treat them
as failures.

The runs show what FRR's BGP table recorded for one session loss of each kind.
They do not show why FRR sets a stale flag in general, propagation beyond r1,
iBGP, route reflection, add-path, multipath, policy, recursive next hops, hold
timer or BFD detection, long-lived graceful restart, or timing. The kernel route
captures are context: netdoc reads none of them, and no forwarding conclusion is
drawn from the BGP table.
