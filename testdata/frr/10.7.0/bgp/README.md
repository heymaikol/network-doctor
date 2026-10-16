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
