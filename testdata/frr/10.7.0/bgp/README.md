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
