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

## Live FIB evidence (opt-in, not yet captured)

`lab/bgp-withdraw.sh` and `lab/bgp-session.sh` take an opt-in `ZEBRA_VTY_PORT`.
Set, each phase adds r1's zebra route table (`show ip route json`) with a
`.collected_at` stamp, and the run writes `SHA256SUMS` once every daemon has
exited. The withdraw run also adds r1's kernel IPv4 routes (`ip -j -4 route
show`) and an `events.log` line before each deletion. The session runs already
take the kernel routes, with or without the opt-in. Unset, the runs write the
files they wrote before, and no `SHA256SUMS`. The repo holds no run of this
opt-in and no zebra capture of any BGP phase, so nothing here is FIB evidence yet.

Run each command from `lab/` with the header's conditions: `SCRATCH` holds
`frr-root/` from the FRR 10.7.0 RPM, `BGPD_VTY_PORT` and `ZEBRA_VTY_PORT` are
distinct free ports, neither 179 nor 2604, and `BGPD_VTY_PORT` is not 2601 (zebra's
default). The output directory does not exist.

```sh
SCRATCH=<dir> BGPD_VTY_PORT=<port> ZEBRA_VTY_PORT=<zport> unshare -Urnm bash bgp-withdraw.sh
SCRATCH=<dir> BGPD_VTY_PORT=<port> ZEBRA_VTY_PORT=<zport> ARM=plain unshare -Urnm bash bgp-session.sh
SCRATCH=<dir> BGPD_VTY_PORT=<port> ZEBRA_VTY_PORT=<zport> ARM=gr unshare -Urnm bash bgp-session.sh
SCRATCH=<dir> BGPD_VTY_PORT=<port> ZEBRA_VTY_PORT=<zport> ARM=admin unshare -Urnm bash bgp-session.sh
```

Outputs are `$SCRATCH/run/bgp-withdraw` and `$SCRATCH/run/bgp-session-<arm>`.
Verify a finished run as described under Operator run requirements below.
The phases are withdraw: before, after1, after2; plain: before, after; gr:
before, during, expired; admin: before, after. Each phase adds
`r1-<phase>-show_ip_route_json.raw` with its `.collected_at` file, and the
withdraw run also writes `r1-<phase>-ip_route.json` with its `.collected_at`.

### Operator run requirements

Run these only from a controlled shell, after reading both scripts. Do not run
them in CI or from an automated agent. They need Linux with unprivileged user
namespaces, `unshare`, `nsenter`, `ip -j`, `python3`, `sha256sum`, and `timeout`.
Record the FRR build, the host, and the date in an operator note beside the run.

A run counts as evidence only if all of these hold:

1. It printed `DONE` and exited 0. A run that exits nonzero, or prints no
   `DONE`, is not evidence, even if a manifest exists.
2. `cd <output> && sha256sum -c --strict SHA256SUMS` exits 0, with `OK` on each
   line.
3. The manifest is complete. The `diff` below prints nothing, which means the
   directory and the manifest list the same names, so no file was added after the
   manifest was written:

   ```sh
   cd <output>
   diff <(LC_ALL=C ls -1A | grep -Ev '^(SHA256SUMS|poll-.*\.last|.*\.err)$') \
     <(awk '{print $2}' SHA256SUMS | LC_ALL=C sort)
   ```

   `sha256sum -c` checks only the listed files. It does not catch an unlisted one.
4. No `*.failed` file exists, and each phase capture, `r1-<phase>-*.raw` or
   `r1-<phase>-ip_route.json`, has a `.collected_at` beside it. The admin run's
   `r1-shutdown.raw` is the vty transcript of the shutdown, not a capture, and has
   no stamp.

A legacy run, without `ZEBRA_VTY_PORT`, writes no `SHA256SUMS` and no zebra
capture. It is not FIB evidence.

### Evidence still to obtain

1. Zebra route tables for each BGP phase of all four runs. No zebra field is
   verified for a BGP route. The repo's zebra captures are OSPF only: neither R
   capture under `zebra-rib/steady/` holds a `"protocol": "bgp"` entry.
2. Zebra's vty port and prompt. `lsdb.sh` says the repo never proves them. The
   opt-in writes `hostname rN` and binds zebra to `ZEBRA_VTY_PORT`, but a live
   run decides. A prompt other than `r1> ` fails the first zebra capture, and
   the `.raw.failed` file is kept.
3. Kernel routes from a withdrawal run. `bgp/withdraw` holds none. The session
   fixtures hold kernel captures, and `session/plain` shows `"protocol":"bgp"`
   routes, but no kernel capture was taken alongside a zebra capture.
4. Provenance for each new run: the FRR build, the host, and the operator's
   record of the run. The steady R capture's operator record is the model.
5. A producer for the recursive resolution identity (see Missing evidence
   producers).
6. A producer for the mapping from a BGP path to its installed entry (see
   Missing evidence producers).

### Known unknowns

These are not verified, and no existing run resolves them:

- Zebra's vty port and prompt. A prompt other than `r1> ` fails the first zebra
  capture, keeps `.raw.failed`, and exits 1.
- Zebra's fields. The zebra capture is checked for framing and one JSON object
  only. No selection, install, protocol, or next-hop field is read, and which keys
  carry those for BGP routes is unverified.
- Kernel routes are context only. The capture records no resolution for a next
  hop, and a `proto bgp` line does not show that BGP installed it.
- Order is not simultaneity. The zebra and kernel captures come after the BGP
  captures, and nothing checks them against the BGP table again.
- Graceful-restart timing. In `gr` `during`, the zebra and kernel captures
  (`r1-during-show_ip_route_json.raw` and `r1-during-ip_route.json`) are `during`
  captures only if their `.collected_at` is less than 30 seconds after the
  `r2: SIGKILL bgpd` line in `events.log`, the configured restart time. Otherwise,
  they may show paths that the restart timer has already removed. The committed
  `session/gr/r1-during-ip_route.json` is a kernel capture of that kind, so the
  rule applies to it too. No zebra capture of a BGP phase is committed.

### Missing evidence producers

These are gaps. No lab command captures them, and nothing here implements them:

- The recursive resolution identity: the zebra or kernel route that resolves each
  BGP next hop, such as 10.0.1.2. Neither BGP script queries zebra for a next hop
  or runs `ip route get`. A candidate, unverified: `ip -j -4 route get <next hop>`.
  Before using it, verify that its output names the resolving route. Until a producer exists, a next hop is not tied to a resolving route, and a route
  is never matched by its gateway alone.
- The mapping from a BGP path to its installed zebra entry. The join rules below
  are a target. They are not implemented, and `forwarding_impact` stays unknown.
- A future producer must be checked against live FRR 10.7.0 output before its
  fields are read.

### Join rules for a later stage (not implemented)

A BGP path can be considered for crediting with an installed forwarding entry
only when every rule holds in the same phase. Each rule is necessary. Together
they are still not sufficient:

- FRR's table lists the prefix with exactly one `bestpath` path from the named
  peer, and that path is `valid`. The `valid`, `bestpath`, and
  `selectionReason` keys are FRR's, and the repo's session captures show them.
  The decoder does not read them yet.
- The path is not stale.
- Zebra's entry for the prefix has `protocol` `bgp`, its install indicators
  are set, and its next hop is the path's next hop. The next hop must be
  unique to that path, and the entry must not be recursive or unresolved.
- The kernel shows a `proto bgp` route for the prefix with the same gateway.

Refuse the join, and keep `forwarding_impact` unknown with the reason, when:

- a next hop is shared by more than one path for the prefix, or the prefix
  has multipath;
- a next hop is recursive or unresolved;
- an install indicator is missing, or a field is absent from the capture;
- the path is stale, or it has no peer (`(unspec)`).

Prefix plus next hop plus `proto bgp` does not prove the selected path, and
`bestpath` on the path does not show that the installed entry came from it.
Until a direct mapping from the path to its installed entry is present,
`forwarding_impact` stays unknown.

### Limits of this lab

- Recursion is not exercised. Each peer next hop here is directly connected on
  r1 (10.0.1.2 on e1, 10.0.3.3 on e3). Recursion needs a separate arm in a
  later stage.
- 10.10.1.0/24 is also connected on r1 (stub1), so a kernel route for it cannot
  be credited to BGP. Locally originated paths (`(unspec)`) have no peer to join.
- Install is asynchronous. Zebra and kernel captures taken after the BGP table
  settles can lag it. The stamps record order, not simultaneity.
- The lab has no policy and no route reflector, and r2 and r3 do not peer with
  each other, so nothing propagates beyond r1.
