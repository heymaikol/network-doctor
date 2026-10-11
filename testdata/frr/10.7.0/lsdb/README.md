# FRR 10.7.0 OSPF LSDB captures

These are recorded vty outputs from the same two-router lab as `../` (see
`../README.md` for the binaries, their sha256, and the framing). Each scenario
brackets one comparison: the process state, the link-state database, the
calculated routes, and the process state again. The `internal/ospf` comparison
and the `internal/frrospf` tests read them. Nothing here came from a production
network.

## Lab

- r1: e1 10.0.1.1/24, router ID 1.1.1.1, network 10.10.1.0/24 on stub1.
- r2: e2 10.0.1.2/24, router ID 2.2.2.2, network 10.10.2.0/24 on stub2, and
  10.20.0.0/24 on stub3 redistributed as connected, so r2 originates it as a
  Type 5 external LSA.
- One area, 0.0.0.0. The adjacency is broadcast on e1.
- The lab driver is `../lab/lsdb.sh`. It runs one scenario per `unshare`
  invocation and writes the files here in this layout. `steady/` was rerun with
  the committed driver: it gave the same file set, and its bracket passes the
  guard with no finding. `flap/` and `kill9/` came from an earlier run of the
  same driver, before its paths were made relative and before the max-age
  command was removed from it. Their captures are unchanged.

## Files

`<scenario>/<node>-<role>-<command>.raw` holds one vtysh transcript, framed as
in `../README.md`. The role is the position in the bracket:

| Role | Command | What it gives |
| --- | --- | --- |
| A | `show ip ospf json` | Process state before the bracket: counters, checksums, and the areas. |
| B | `show ip ospf database detail json` | The link-state database, one entry per LSA. |
| E | `show ip ospf route json` | The calculated routes. |
| D | `show ip ospf json` | Process state after the bracket. |

A and D are the same command, and the comparison needs both. The importer
takes them as a pair and compares their SPF counters and checksums.

Each `.collected_at` file holds the UTC time of its capture, before the vty
helper connects.

## Scenarios

| Directory | What it shows |
| --- | --- |
| `steady/` | Both routers, no change inside the bracket. Captures for r1 and r2. The comparison should give no finding for either node. |
| `flap/` | Both routers. stub1 on r1 goes down for four seconds after the E capture of r1, so the SPF counter of area 0.0.0.0 moves from 4 to 5 between A and D, and the router checksum changes. Captures for r1 and r2. The r1 bracket fails the guard and gives only `ospf_comparison_unverified`. The tests read only the r1 bracket. |
| `kill9/` | r2 daemons are killed with SIGKILL, then r1 waits 75 seconds. Only r1 is captured. r1 keeps the Type 1 and Type 5 LSAs of r2 that it no longer has a route for. The comparison should report two prefixes for r1 and no others. |

The `kill9/` B capture also holds the network LSA for 10.0.1.1 advertised by
1.1.1.1 with age 3600 (MaxAge). The comparison skips it for findings. It still
counts toward the per-area reconciliation, which matches the counters.

## Not included

- The max-age command (`show ip ospf database max-age json`). The driver can
  run it, but max-age LSAs are not part of the comparison, so the capture is
  not committed.
- Topo-ecmp and topo-area runs. They are not committed, so no test reads them.
- NSSA (Type 7) LSAs. No lab run produced one, so the NSSA decode is tested
  only on synthetic input.
- Point-to-point and virtual links in the LSDB. The comparison keeps those as
  facts and unsupported entries, and no capture here exercises them.

## Limits

- Each scenario is one run. Ages, sequence numbers, checksums, and timestamps
  vary between runs, so a reproduction matches structure, not bytes.
- The timing of the kill9 and flap brackets depends on the daemons settling.
  The driver waits for a Full neighbor, then waits 25 seconds, before the first
  capture.
- A single area. The comparison's per-area reconciliation is tested on one
  area here, and on more than one only in synthetic tests.
