# FRR 10.7.0 OSPFv2 captures

These are recorded outputs of `show ip ospf ... json` from FRRouting 10.7.0,
taken from a two-router lab on one Linux host. They are the main input the
`internal/frrospf` tests read. Some tests also edit a copy of a capture, add a
record by hand, or seed the fuzz target with hand-written shapes. Each such case
says so. Nothing here came from a production network, and no authentication
material is present.

## Provenance

- Binaries: `frr-10.7.0-1.fc44.x86_64.rpm`, sha256
  `7280fea0a256346eeb513e65fb32ecbac06daade46b7134b5d97d38667657b3a`.
  Dependency `libyang-3.13.5-2.fc44.x86_64.rpm`, sha256
  `4dc594162c3af6e6c3de5586d42bc33887cc7d5f625b1f05fa8b6457709962fb`.
  Both were extracted with `rpm2cpio`. FRR was not installed on the host.
- Source line references in the tests use the `frr-10.7.0` tag.
- Each scenario's `ospfd-version.txt` holds the `ospfd --version` output from
  the run.
- `<node>-<command>.collected_at` is the UTC time taken with `date -u` just
  before the vty helper connects. The helper then waits about two seconds
  before it sends the command, so the stamp is a few seconds early.

## Framing

The vty echoes the command on the first line and ends with the prompt `rN> `
on the last line. Lines end in CRLF. The `.raw` files are the exact bytes read
from the vty, and `.gitattributes` marks them `-text` so git does not rewrite
the line endings. The tests unframe them by dropping the echo and the prompt
and converting CRLF to LF. A fixture whose echo does not match the declared
command fails the test.

## Scenarios

Each scenario was run serially with `lab/run5.sh`, one scenario per
`unshare` invocation.

| Directory | What it shows |
| --- | --- |
| `bcast/` | Broadcast adjacency. r1 e1 10.0.1.1/24, router ID 1.1.1.1; r2 e2 10.0.1.2/24, router ID 2.2.2.2. Passive `stub1` on r1; `stub2` on r2 is an active OSPF interface with no peer. `vrf all` output from r1 is kept as a shape the neighbor command must refuse. |
| `p2p/` | Point-to-point variant of the same topology. |
| `mtu/` | r2 e2 MTU 1400 against 1500. The adjacency stays below Full. `r2-e2-mtu.txt` records the MTU read back after the change. |
| `empty/` | r1 alone, with no peer daemon. Valid empty neighbor list. |
| `nbma/` | r1 e1 set to `ip ospf network non-broadcast` with a static `neighbor 10.0.1.2`. The peer is absent. `r1-early-*` is a detail dump taken 15 seconds after start and holds the `noNbrId` record. The later dump, at the end of the settle window, is an empty neighbor list. |
| `noinst/` | r2 runs ospfd with no `router ospf` stanza. Its commands return `{}`. |
| `area/` | r2 puts e2 in area 0.0.0.1 while r1 keeps e1 in 0.0.0.0, on one subnet. No adjacency forms, so both neighbor lists are empty. Each interface capture reports the area its side is in. |
| `secondary/` | r1 adds 10.0.2.1/24 to e1 in area 0.0.0.1, beside the primary 10.0.1.1/24 in area 0.0.0.0. The adjacency with r2 is Full in area 0.0.0.0. The interface record for e1 shows only the secondary: `ipAddress` 10.0.2.1, `area` 0.0.0.1, `nbrCount` 0. See the section below. |

## Area and secondary-address captures

`area/` and `secondary/` are genuine FRR 10.7.0 output from the same lab, run with `lab/run5.sh area` and `lab/run5.sh secondary`.

The interface `area` field is `ospf_area_desc_string(oi->area)` in `ospfd/ospf_vty.c`, which prints `A.B.C.D`, `A.B.C.D [Stub]`, `A.B.C.D [NSSA]`, or `(incomplete)`. The field is absent when the interface is not up, because the printer returns early with `ospfRunning` false. The importer writes a plain dotted area as `ospf.effective_area`. A qualified area, `(incomplete)`, or a missing area is noted and no area is written for that interface.

FRR prints one OSPF interface record per interface name. An interface that holds several OSPF interfaces, such as a secondary address in another area, shows only the last one it visits, because each loop iteration overwrites the same JSON keys. `secondary/` shows this: e1 holds two OSPF interfaces, and the record names only the secondary, while the Full adjacency on the primary is in area 0.0.0.0. So an area read from an interface name is not an inventory of that interface's areas, and it can differ from the area of an adjacency on it.

The declared links that the topology tests add to these captures are not FRR output. They are synthetic intended-plane rows written by the test, and each such test says so.

## Socket paths

Each daemon's zserv and vty sockets live under `/run/frr/<node>` in the run's
private tmpfs. An earlier version put them under the scratch directory. That
path is about 130 bytes, past the 108-byte `sun_path` limit. In that version
the two routers' socket paths collided, and an earlier run showed r1 reporting
the `e2` interface and MTU 1400 that belong to r2. We inferred that the socket
path was truncated; we did not confirm this in FRR source. The captures here
come from the corrected recipe. `provenance_test.go` checks that each node's
interface capture in the `bcast`, `p2p`, and `mtu` scenarios names only that
node's interfaces and router ID.

## The noNbrId placeholder

FRR prints `noNbrId` for a neighbor in `NSM_Attempt` with no router ID
(`ospf_vty.c`, lines 5259 to 5261 of the tag). The `nbma/` early dump holds
one such record: `Attempt/DROther` on r1 e1, peer address 10.0.1.2, no peer
captured. `TestImportNoNbrIDFromLabStaysUnmapped` checks that it stays
unmapped. We observed it once. The window is timing-dependent, so a rerun may
not show it. The importer refuses the placeholder on any neighbor state other
than `Attempt`, which is the state the source prints it for.

The other branch, where the placeholder's address resolves to a captured peer,
is tested by editing a copy of the `bcast` capture. That copy is a labeled
mutation (`TestImportNoNbrIDKeepsIdentityWhenAddressResolves`), not lab output.

## Reproducing

Requires unprivileged user namespaces, `iproute2`, `util-linux` (`nsenter`,
`unshare`), `coreutils` (`timeout`), `python3`, `rpm2cpio`, and `cpio`. Extract
both RPMs into one root, then run one scenario per invocation. `ospfd` also
links against shared libraries from other packages; `readelf -d` on the
extracted binary lists them.
`SCRATCH` must name a writable directory; the run writes under `$SCRATCH/run`.
Replace `/path/to` with the directory that holds the two RPMs:

    mkdir -p "$SCRATCH/frr-root"
    (cd "$SCRATCH/frr-root" && rpm2cpio /path/to/frr-10.7.0-1.fc44.x86_64.rpm | cpio -idm && rpm2cpio /path/to/libyang-3.13.5-2.fc44.x86_64.rpm | cpio -idm)
    SCRATCH="$SCRATCH" unshare -Urnm bash testdata/frr/10.7.0/lab/run5.sh bcast

Modes are `bcast`, `p2p`, `mtu`, `empty`, `nbma`, `noinst`, `area`, and `secondary`. Each run takes
about 100 seconds. Output goes to `$SCRATCH/run/<mode>`. Copy the files you keep into
`testdata/frr/10.7.0/<mode>/` by hand; the tests read those names. The helper
script that copied them here is not in the repo. The
`lab/etc/group` and `lab/etc/passwd` files are a minimal set, so the host's
account files are never copied into the repository. `lab/tcpvty2.py` reads the
vty over loopback from inside each namespace.
