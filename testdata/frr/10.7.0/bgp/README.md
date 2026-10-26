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

## Opt-in FIB capture recipe

The producer choice has now been approved. The [Phase 1 instrumented producer
and validation report](correlation-v1/README.md) record its implementation and
live identity evidence, awaiting independent review before any Network Doctor
importer or forwarding ratings. The earlier investigation remains historical.

`lab/bgp-withdraw.sh` and `lab/bgp-session.sh` take an opt-in `ZEBRA_VTY_PORT`.
Set, each phase adds r1's zebra route table (`show ip route json`) with a
`.collected_at` stamp, and the run writes `SHA256SUMS` once every daemon has
exited. The withdraw run also adds r1's kernel IPv4 routes (`ip -j -4 route
show`) and an `events.log` line before each deletion. The session runs already
take the kernel routes, with or without the opt-in. Unset, the runs write the
files they wrote before, and no `SHA256SUMS`.

[The producer investigation](correlation-investigation/README.md) now holds
verified opt-in withdrawal and plain session-loss runs, plus a separate
recursive/shared-next-hop experiment. It compares producer candidates and
proposes an explicit identity contract for maintainer review. These captures
do not yet prove a FIB-to-BGP-path relationship or implement forwarding ratings.

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

### Producer decision and remaining evidence

See [the investigation and proposed contract](correlation-investigation/README.md)
for live fields, provenance, limitations, candidate comparison, and the exact
producer decision awaiting ChatGPT review. The former speculative join rules
are superseded by that investigation. Prefixes, next hops, protocol labels,
AS paths, destination-level installation flags, and shared next-hop-group IDs
do not supply the missing explicit path identity.

The enhanced GR and administrative-shutdown arms have not been recaptured.
In a GR `during` capture, each Zebra/kernel timestamp must still fall within
the configured restart window after the event. Otherwise the phase name alone
cannot establish that stale routes were retained.

The ordinary withdrawal and session recipes still exercise directly connected
BGP next hops. Their `10.10.1.0/24` route is connected on r1 and cannot be
credited to a remote BGP peer. The separate research recipe exercises a BGP
recursive next hop, a static route resolving through BGP, and shared forwarding
groups. Its recorded NHT resolution names a prefix/protocol and client, but
still does not emit a consuming-route-to-originating-BGP-peer identity chain.

The captures record separate collection times. Neither convergence polling nor
equal bracket endpoints makes cross-daemon state atomic. Installation is
asynchronous, and no forwarding rating follows merely from observed route loss.
Until the maintainer selects and validates a producer for the explicit links,
`forwarding_impact` remains unknown. Do not start a broad Zebra RIB import solely
for this decision.

Previous Phase 1 hardening and its build evidence: [correlation-v1-hardened](correlation-v1-hardened/README.md). The original correlation-v1 evidence remains unchanged and proves only its original build.

Latest Phase 1 no-replace implementation and new-build proof: [correlation-v1-noreplace](correlation-v1-noreplace/README.md). Exact-head Sonar review: [7df7be1](correlation-review-7df7be1/README.md).
