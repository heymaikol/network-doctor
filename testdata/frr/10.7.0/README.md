# FRR 10.7.0 OSPFv2 captures

These are recorded outputs of `show ip ospf ... json` from FRRouting 10.7.0,
taken from a two-router lab on one Linux host. They are the main input the
`internal/frrospf` tests read. Some tests also edit a copy of a capture, add a
record by hand, or seed the fuzz target with hand-written shapes. Each such case
says so. Nothing here came from a production network, and no authentication
material is present. `zebra-rib/` is the exception: the operator recorded it, and its
README says what it holds.

## Provenance

- Binaries: `frr-10.7.0-1.fc44.x86_64.rpm`, sha256
  `7280fea0a256346eeb513e65fb32ecbac06daade46b7134b5d97d38667657b3a`.
  Dependency `libyang-3.13.5-2.fc44.x86_64.rpm`, sha256
  `4dc594162c3af6e6c3de5586d42bc33887cc7d5f625b1f05fa8b6457709962fb`.
  Both were extracted with `rpm2cpio`. FRR was not installed on the host.
- Source line references in the tests use the `frr-10.7.0` tag.
- Each scenario's `ospfd-version.txt` holds the `ospfd --version` output from
  the run, where the scenario has one. `zebra-rib/steady/` has none.
- `<node>-<command>.collected_at` is the UTC time taken with `date -u` just
  before the vty helper connects. The helper then waits about two seconds
  before it sends the command, so the stamp is a few seconds early.

## Framing

The vty echoes the command on the first line and ends with the prompt `rN> `
on the last line. Lines end in CRLF. The `.raw` files are the exact bytes read
from the vty, and `.gitattributes` marks them `-text` so git does not rewrite
the line endings. The tests unframe them by dropping the echo and the prompt
and converting CRLF to LF. A fixture whose echo does not match the declared
command fails the test. `zebra-rib/` is the exception: its tests check the framing as
written and do not convert CRLF.

## Scenarios

Each scenario was run with `lab/run5.sh`, one scenario per `unshare`
invocation. The `passive1/`, `cost50/`, `mixp2p/`, `secp1/`, `secp2/`, and
`down1/` directories came from one queue that ran them one after another, and
the `.collected_at` stamps show that order. Earlier runs that overlapped were
discarded, and none of their captures is committed. The `lsdb/` scenarios and
the `ecmp/` bracket were run with `lab/lsdb.sh` instead. `lsdb/` is described in
`lsdb/README.md`, and `ecmp/` is described in the ECMP section below.
`zebra-rib/` is described in its own README, not here.

Each run writes more captures than the committed directories keep. The
committed set for the scenarios added in PR 6 is the interface, neighbor-detail,
and route output of each node, plus the configuration, `ospfd-version.txt`, and
`r2-e2-mtu.txt`. The `vrf all` and `vrf nosuch` dumps of those runs are not
committed.

| Directory | What it shows |
| --- | --- |
| `bcast/` | Broadcast adjacency. r1 e1 10.0.1.1/24, router ID 1.1.1.1; r2 e2 10.0.1.2/24, router ID 2.2.2.2. Passive `stub1` on r1; `stub2` on r2 is an active OSPF interface with no peer. `vrf all` output from r1 is kept as a shape the neighbor command must refuse. |
| `p2p/` | Point-to-point variant of the same topology. |
| `mtu/` | r2 e2 MTU 1400 against 1500. The adjacency stays below Full. `r2-e2-mtu.txt` records the MTU read back after the change. |
| `empty/` | r1 alone, with no peer daemon. Valid empty neighbor list. |
| `nbma/` | r1 e1 set to `ip ospf network non-broadcast` with a static `neighbor 10.0.1.2`. The peer is absent. `r1-early-*` is a detail dump taken 15 seconds after start and holds the `noNbrId` record. The later dump, at the end of the settle window, is an empty neighbor list. |
| `noinst/` | r2 runs ospfd with no `router ospf` stanza. Its `show ip ospf interface json` and `show ip ospf neighbor detail json` return `{}`. The process-state command, `show ip ospf json`, was not captured here. |
| `area/` | r2 puts e2 in area 0.0.0.1 while r1 keeps e1 in 0.0.0.0, on one subnet. No adjacency forms, so both neighbor lists are empty. Each interface capture reports the area its side is in. |
| `lsdb/` | Two routers with an OSPF LSDB bracket. Scenarios `steady`, `flap`, and `kill9`. See `lsdb/README.md`. |
| `ecmp/` | Two routers over three links, with r1 e5 at cost 50. Both LSDB brackets, taken once each router had three Full neighbors and the expected equal-cost next hops. See the ECMP section below. |
| `secondary/` | r1 adds 10.0.2.1/24 to e1 in area 0.0.0.1, beside the primary 10.0.1.1/24 in area 0.0.0.0. The adjacency with r2 is Full in area 0.0.0.0. The interface record for e1 shows only the secondary: `ipAddress` 10.0.2.1, `area` 0.0.0.1, `nbrCount` 0. See the section below. |
| `passive1/` | r1 e1 set to `ip ospf passive`, with no address on the command. r2 e2 is active on the same subnet. No neighbor forms on either side. r1's e1 record holds `timerPassiveIface` true and no hello timer. r2's holds a hello timer. |
| `cost50/` | r1 e1 set to `ip ospf cost 50` against r2 e2 at the default cost 10. The adjacency is Full on both ends, and each side installs the other's stub network. |
| `mixp2p/` | r1 e1 set to `ip ospf network point-to-point`, while r2 e2 stays broadcast. The adjacency is Full on both ends. Neither OSPF route table holds the calculated route to the other's stub network. See the section below. |
| `secp1/` | `secondary/` with `ip ospf passive 10.0.1.1` on e1, so the primary address is passive. No neighbor forms. The e1 record holds `timerPassiveIface` true and `timerHelloInMsecs` together. |
| `secp2/` | `secondary/` with `ip ospf passive 10.0.2.1` on e1, so the secondary address is passive. The Full adjacency on the primary is kept. The e1 record holds `timerPassiveIface` true and `timerHelloInMsecs` together, and its `bdrAddress` 10.0.1.1 lies outside 10.0.2.0/24. |
| `down1/` | The broadcast adjacency of `bcast/`, then `ip link set e1 down` on r1 and a 5-second wait before the dump. r1 e1 is absent from the all-interface listing. See the section below. |
| `zebra-rib/` | The steady run's zebra RIB capture (R) between E and D, with the ospfd A, B, E, and D captures of the same bracket, from two isolated routers the operator recorded on 2026-10-12 UTC. The files were copied from the operator's original run. See `zebra-rib/README.md`. |

## Area and secondary-address captures

`area/` and `secondary/` are genuine FRR 10.7.0 output from the same lab, run with `lab/run5.sh area` and `lab/run5.sh secondary`.

The interface `area` field is `ospf_area_desc_string(oi->area)` in `ospfd/ospf_vty.c`, which prints `A.B.C.D`, `A.B.C.D [Stub]`, `A.B.C.D [NSSA]`, or `(incomplete)`. For an OSPF interface that is not up, the printer returns early after writing `ospfRunning` false, so `ipAddress`, `area`, and the other numbered-interface keys are not printed. The source therefore predicts such a record. The `down1/` run did not show one: r1 e1 was absent from the all-interface listing, which skips an interface with no OSPF instance (`ospf_oi_count` zero), and why the count was zero is not established. The importer writes a plain dotted area as `ospf.effective_area`. A qualified area, `(incomplete)`, or a missing area is noted and no area is written for that interface.

FRR prints one OSPF interface record per interface name. An interface that holds several OSPF interfaces, such as a secondary address in another area, shows only the last one it visits, because each loop iteration overwrites the same JSON keys. `secondary/` shows this: e1 holds two OSPF interfaces, and the record names only the secondary, while the Full adjacency on the primary is in area 0.0.0.0. So an area read from an interface name is not an inventory of that interface's areas, and it can differ from the area of an adjacency on it.

The importer withholds the area of e1 in `secondary/`. The Full adjacency's neighbor record names local address 10.0.1.1, which the e1 record does not give, so that record's area is not known to be the adjacency's, and the reason appears in the capture's notes. A link declared over e1 then reads as incomplete, not as a failed adjacency.

The declared links that the topology tests add to these captures are not FRR output. They are synthetic intended-plane rows written by the test, and each such test says so.

## Interface-fact captures (PR 6)

`passive1/`, `cost50/`, `mixp2p/`, `secp1/`, `secp2/`, and `down1/` were run with the modes of the same names in `lab/run5.sh`. Each scenario's `r1-ospfd.conf` and `r2-ospfd.conf` hold the configuration it ran with. Each `.raw` file is FRR output read from the vty, and nothing in these directories was edited or synthesized.

- `passive1/`: r1 e1 is passive, and r2 e2 is active on the same subnet. Neither side forms a neighbor, and both neighbor lists are empty. r1's e1 record holds `timerPassiveIface` true with no hello timer. r2's e2 record holds a hello timer. This shows FRR's passive status for the interface. It does not show how the status was set.
- `cost50/`: r1 e1 costs 50 and r2 e2 costs 10. The adjacency is Full on both ends, and each router's OSPF route table holds the other's stub network.
- `mixp2p/`: r1 e1 is point-to-point and r2 e2 is broadcast. The adjacency is Full on both ends (`Full/-` on r1 and `Full/Backup` on r2). Each router's `show ip ospf route json` lacks the calculated route to the other's stub network: r1 has no `10.10.2.0/24` and r2 has no `10.10.1.0/24`. The captures show only that those calculated entries are absent from the captured OSPF route tables. They show no kernel FIB failure and no loss of connectivity, and they do not show why the entries are absent.
- `secp1/` and `secp2/`: the primary address and the secondary address share the name e1, and the one e1 record holds `timerPassiveIface` true and `timerHelloInMsecs` together. In `secp1/` no neighbor forms, since the primary is passive. In `secp2/` the Full adjacency on the primary is kept, and the record's `bdrAddress` 10.0.1.1 lies outside the secondary subnet 10.0.2.0/24. Both records show that one name can mix two OSPF interfaces. Neither shows a fault.
- `down1/`: the broadcast adjacency of `bcast/`, then `ip link set e1 down` on r1 and a 5-second wait. r1 e1 is absent from the all-interface listing, as described in the area section above. The run does not show the `ospfRunning` false record that the source predicts for a down interface with an OSPF instance.

A secondary-address case with the two addresses added in the reverse order was not run. The effect of the order in which FRR visits addresses on the record it prints last is therefore not observed.

## ECMP bracket

`ecmp/` is the only committed capture with more than one next hop for a route.
It was taken by `lab/lsdb.sh ecmp` on 2026-10-12 UTC. The topology is three
links in area 0.0.0.0. r1 e1 10.0.1.1/24 connects to r2 e2 10.0.1.2/24, r1 e3
10.0.3.1/24 to r2 e4 10.0.3.2/24, and r1 e5 10.0.5.1/24 to r2 e6 10.0.5.2/24.
Each link costs 10 except r1 e5, which is set to `ip ospf cost 50`. stub1
10.10.1.0/24 is on r1, and stub2 10.10.2.0/24 is on r2. The router IDs are
1.1.1.1 for r1 and 2.2.2.2 for r2.

The driver waits until each router has three Full neighbors and the expected
next-hop counts, then takes the captures in the order A, B, E, D on each node.
The A-to-D window is about 9.4 seconds on both nodes. That is above the 5000 ms
bound, which comes from the default holdtime of 5000 ms and an SPF delay of 0.

The routes the captures hold:

- r1 `10.10.2.0/24` has two next hops, 10.0.1.2 via e1 and 10.0.3.2 via e3. Both
  are advertised by 2.2.2.2, and each route costs 20. The path through e5 would
  cost 60 (50 on e5 plus 10 for stub2). That is arithmetic from the configured
  costs, not a captured value, and the table does not hold that path.
- r2 `10.10.1.0/24` has three next hops, 10.0.1.1 via e2, 10.0.3.1 via e4, and
  10.0.5.1 via e6. All three are advertised by 1.1.1.1.
- r1 `10.0.5.0/24` is reached through e1 and e3 at cost 20, not directly through
  e5 at cost 50. The direct link loses to the cheaper path through r2.

`ospfd-version.txt` is the output of `ospfd --version`. `r1-ospfd.conf` and
`r2-ospfd.conf` are the configurations that ran. The `.raw` files are FRR output
read from the vty, with nothing edited.

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

Modes are `bcast`, `p2p`, `mtu`, `empty`, `nbma`, `noinst`, `area`, `secondary`, `secp1`, `secp2`, `passive1`, `cost50`, `mixp2p`, and `down1`. Each run takes
about 100 seconds. Run them one at a time, as the committed PR 6 captures were run. Output goes to `$SCRATCH/run/<mode>`. A run that fails exits nonzero and never prints `DONE`. A capture that fails is kept as `<name>.raw.failed` with no `.collected_at` marker, so the tests never read it as a capture. Copy the files you keep into
`testdata/frr/10.7.0/<mode>/` by hand; the tests read those names. The helper
script that copied them here is not in the repo. The
`lab/etc/group` and `lab/etc/passwd` files are a minimal set, so the host's
account files are never copied into the repository. `lab/tcpvty2.py` reads the
vty over loopback from inside each namespace.

The LSDB brackets run with `lab/lsdb.sh`, which takes `steady`, `flap`, `kill9`,
or `ecmp` as its mode, with the same `SCRATCH` and `unshare -Urnm` setup:

    SCRATCH="$SCRATCH" unshare -Urnm bash testdata/frr/10.7.0/lab/lsdb.sh ecmp

The mode writes to `$SCRATCH/run/lsdb-<mode>`. The `ecmp` mode also writes
`ospfd-version.txt`, which `lsdb.sh` writes for no other mode. Setting
`ZEBRA_VTY_PORT` to zebra's vty port adds the optional zebra RIB capture to every
mode, with `zebra-version.txt` beside it. `lsdb/README.md` describes it. The steady
run's zebra RIB capture is described in `zebra-rib/README.md`.

The BGP lab is `lab/bgp.sh`. It takes no mode. It needs `BGPD_VTY_PORT`, the TCP
port for bgpd's vty, which must not be 2604 (ospfd), 2601 (zebra's default vty),
or 179 (BGP itself):

    SCRATCH="$SCRATCH" BGPD_VTY_PORT=<port> unshare -Urnm bash testdata/frr/10.7.0/lab/bgp.sh

It writes to `$SCRATCH/run/bgp`, which must not exist. The script never removes
anything, so after a failed run, remove that directory by hand before running
again. The kept files are the `show ip bgp summary json` and `show ip bgp json`
captures of r1 and r2, each with a `.collected_at` stamp, the bgpd and zebra
version records, the four daemon configs, and the daemon logs. A capture that
fails keeps `.raw.failed` and no stamp. The first successful run's captures are preserved in `bgp/steady/`.

The first operator run completed on 2026-10-13 UTC using FRR 10.7.0. It
reported convergence after approximately 6 seconds and finished with DONE.
The four original VTY transcripts, timestamps, configurations, daemon version
records, and SHA256SUMS are preserved in `bgp/steady/`.

This proves the reported peer and route states in an isolated lab only. The
captures are not simultaneous and do not prove kernel FIB installation.
The script's content checker is intentionally narrow; it is not a general
BGP decoder.

The BGP withdrawal lab is `lab/bgp-withdraw.sh`. It takes no mode and the same
`BGPD_VTY_PORT`, and runs three routers: r1 peers with r2 and r3, and r2
withdraws prefixes in two steps by deleting the stub addresses its `network`
statements import. It captures r1's summary and table before the first step and
after each one, and each capture passes only when both sessions are Established
and each prefix lists the expected `peerId` set, or is absent:

    SCRATCH="$SCRATCH" BGPD_VTY_PORT=<port> unshare -Urnm bash testdata/frr/10.7.0/lab/bgp-withdraw.sh

It writes to `$SCRATCH/run/bgp-withdraw`, which must not exist, and never removes
anything. The 2026-10-16 UTC run settled each phase in about 7 seconds and
finished with DONE. Its captures are preserved in `bgp/withdraw/`. Running the
lab needs the extracted FRR root and unprivileged user namespaces, so CI does
not run it; the tests read the preserved captures.

The BGP session-loss lab is `lab/bgp-session.sh`. It takes the same
`BGPD_VTY_PORT` and the same three routers as the withdrawal lab, plus `ARM`,
which selects how r1 loses its session with r2: `plain` kills r2's bgpd with
SIGKILL under FRR defaults, `gr` does the same after r2 configures graceful
restart with a 30 second restart time, and `admin` has r1 shut the session
administratively with r2 configured as in `gr`. Each phase captures r1's
summary, table, and `show ip bgp neighbors 10.0.1.2 json`, and r1's kernel
IPv4 routes as `ip -j` prints them, which are lab context only:

    SCRATCH="$SCRATCH" BGPD_VTY_PORT=<port> ARM=plain unshare -Urnm bash testdata/frr/10.7.0/lab/bgp-session.sh

It writes to `$SCRATCH/run/bgp-session-$ARM`, which must not exist, and never
removes anything. A capture passes only when the session states, the `peerId`
set of each prefix, the stable attributes of every path not from r2, the stale
keys, and, where checked, the remote graceful-restart mode match the phase. Fields
FRR may change when another path goes, such as `bestpath`, are never matched.
Each arm's 2026-10-16 UTC run finished with DONE, and its captures are preserved
in `bgp/session/`. CI does not run the lab; the tests read the preserved captures.
