# Phase 1 producer validation

Status: implementation and evidence prepared for independent ChatGPT review.
The producer choice was approved after reviewing `729b168`. This phase builds
and tests that producer; it does not implement an importer or forwarding ratings.
The base remains main `ff3b1fbbad25aa5d3b0c66f01e725eeeaf4e71ed`.

[Implementation, format and reproduction](../../../../../contrib/frr-correlation/v1/README.md)
and [JSON Schema](../../../../../contrib/frr-correlation/v1/schema.json) describe
the versioned interface and the exact verified subset.

## Build proof

- FRR 10.7.0 source commit: `87fe21fda92ce9e2ba3eaf2b0a327bf71ee183ef`.
- Authoritative build ID:
  `b5207a87e19c585481294b77604ca6bd639d38679b85da2fe10c42d46cddb507`.
- Instrumentation implementation SHA256:
  `acb2d79e9d980085b3d574567fae2c072998dd5cfc15a6cbf4e478674a0f6013`.
- The pinned Fedora base, complete package lock and configuration are recorded
  in `build.json` and `provenance.json`. The committed Containerfile recreated
  the complete package database successfully. Build network access was disabled.
- Two fresh builds in different directories produced identical `build.json`
  files and identical bytes for all eight staged artifacts: bgpd, zebra,
  staticd, mgmtd, vtysh, libfrr, libmgmt_be_nb and libyang. The full build logs,
  source/flag manifests, and both checksum lists are under `validation/`.
- The actual compiled wire codec passed valid round-trip, every truncation
  boundary, oversized count, invalid magic, zero identity and invalid-leg tests.
  Upstream stream-bound checks log expected diagnostic backtraces during those
  negative tests. Both build processes exited 0 and printed `BUILD_DONE`.
- Four concurrent threads wrote 4000 events through the actual libfrr writer.
  The verified stream has 4002 records including start/end, 4000 unique IDs,
  contiguous sequences, nondecreasing monotonic times and a complete trailer.
  `validation/writer-verification.json` pins the tested library hash and result.

The local builder OCI archive is preserved in workspace scratch with its
checksum recorded in provenance when available. No image was published and no
system FRR was installed or replaced. Runtime host/library hashes are recorded
separately from compiler inputs. The hashes establish preservation and build
reproducibility, not hostile-host attestation.

## Genuine live cases

Both accepted runs used the exact final artifact set, exited 0, printed `DONE`,
and ran in disposable rootless user/mount/network namespaces. `proof/` and
`restart/` retain their original complete recursive manifests. Every copied
byte was checked against the source run. No existing investigation fixture was
reformatted, overwritten, or removed.

The three-router topology reuses the committed withdrawal setup. r1 is AS
65001. r2 and r3 are AS 65002. They both advertise `10.10.2.0/24`; r3 sets its
next hop for that prefix to `10.0.1.2`, making AS path and next-hop address
identical while peer identities differ. r2 alone advertises `10.10.9.0/24`.
r1 installs static `198.51.100.0/24` via gateway `10.10.9.2`. A static route in
table 100 deliberately exercises an unsupported context.

| Case | Direct producer evidence | Independent comparison |
| --- | --- | --- |
| Single peer | A BGP path snapshot identifies its peer/session; its serialized announcement is copied onto a specific Zebra entry/generation and then an acknowledged, accepted dataplane operation. | BGP, Zebra and kernel observations contain `10.10.9.0/24` before withdrawal. |
| Shared forwarding leg | The received Zebra entry retains two distinct path and peer references; the acknowledged operation references that exact entry/generation. No peer is chosen as sole owner. | BGP lists both peers with equal AS path/next hop; Zebra reports one FIB next hop plus one duplicate. |
| Static via BGP | The static consuming entry's actual resolution ID names the selected BGP resolver entry/generation. The static operation copies that resolution reference and receives its own kernel ACK and accepted result. Its origin remains static. | Zebra reports the recursive gateway and resolver leg; NHT names BGP prefix `10.10.9.0/24`; the kernel contains the flattened static route. |
| Withdrawal | Explicit `no network 10.10.9.0/24` is recorded, followed by route-selection/removal and operation history. Old installation claims remain historical, rather than being presented as current. | BGP loses the resolver prefix; Zebra/kernel lose both the resolver and dependent static route. |
| Session loss | r2 bgpd is killed. Later received entries retain only r3's contributing path and its correct session identity. | r2 leaves Established, r3 stays Established, the shared prefix retains r3's path, and the connected r1 prefix remains. |
| Unsupported table | Table 100 route/operation records remain observable but receive explicit refusals and no installation/attribution claim. | The independent all-table kernel capture records that context. |
| Real crash/restart | r1 bgpd is killed and restarted. Its second epoch differs, and the first has no complete trailer. Packaging refuses the history, with no claims. | The restarted BGP table is captured independently; its presence does not repair the interrupted identity history. |

`edge-summary.json` selects representative recorded IDs and their source
records, including the two-peer installation and the static-to-BGP chain.
The complete `proof-bundle.json` contains 12 path-to-route edges, seven verified
resolution edges and six acknowledged historical installation/update edges.
These counts describe records, not six delivered packets or six current routes.

## Exactly what is proven

The positive records establish these links in the instrumented FRR execution:

1. Peer/session/path object identity to an exported BGP snapshot revision.
2. That snapshot's membership in a specific serialized BGP announcement.
3. The announcement's explicit references on the received Zebra route entry.
4. A specific selected entry/generation, including replacement/removal sequence.
5. That generation and its route-owned resolution IDs copied into a dataplane
   operation, the corresponding kernel request/ACK, and an accepted result.
6. The actual consuming-route/leg to selected resolving-route/generation choice,
   including a static route's dependency on a BGP route.
7. Retention of every contributing BGP path when the forwarding leg is shared.

The independent CLI/kernel captures are checked for agreement. They are never
used to create these links by matching prefixes, AS paths or gateways.

The following stronger links remain unproven or unsupported:

- An atomic current FIB-row snapshot tied across all daemon generations.
  Version 1 exports closed historical ledgers and always sets
  `snapshot_complete=false`.
- Full attribution of every observed route. Unsupported contexts and missing
  ACKs/results are retained as refusals. This run has 16 queued shutdown
  operations without a recorded main-thread result. They receive no credit;
  `attribution_complete=false` makes that distinction explicit.
- Arbitrary per-kernel-leg attribution for distinct-next-hop or weighted ECMP,
  unverified recursion classes, active add-path IDs, stale/GR retention,
  cross-VRF/table lookups, VPN/EVPN/MPLS/SRv6, backup paths or other protocols.
- Replay across daemon crashes or restarts. Epoch mixing is refused rather
  than guessed. A later restarted table cannot authenticate an earlier entry.
- Packet delivery, hardware offload, continuing installation after capture,
  convergence, or the existence/behavior of an unseen replacement path.

Those limits are part of the review gate. In particular, a future current-state
importer must not silently turn this historical format into a complete atomic
snapshot or a forwarding rating.

## Negative tests and validation

`test_bundle.py` has 21 tests using genuine source logs. Mutations are confined
to temporary test copies and are explicitly not live fixtures. They cover:

- Missing path records even after sequence renumbering; contradictory
  contributors, generations and operation-to-resolution references.
- Missing/unsuccessful ACKs, stale results, malformed boolean error codes,
  unknown origin labels and unverified operations.
- Unsupported build/schema/OS/kernel, mixed namespaces, real interrupted
  restart epochs, truncation, duplicate JSON keys and event gaps.
- The genuine shared-leg/static chains, independent before/after observations,
  unsupported table 100, deterministic packaging and complete manifests.
- Formal JSON Schema validation of both accepted and refused output, using
  the validator version locked in the builder.

The complete producer suite runs without network access in the recreated locked
builder. On a host without the optional schema validator, that one test skips;
the authoritative builder run must have zero skips. The C wire and concurrent
writer tests exercise the compiled extension, separately from Python validation.

Repository validation uses:

```sh
TMPDIR=<workspace-scratch> ./scripts/check --race
python3 -B -I -m unittest discover -s contrib/frr-correlation/v1 -p 'test_*.py' -v
bash -n contrib/frr-correlation/v1/build.sh
bash -n contrib/frr-correlation/v1/lab.sh
```

See `validation/results.json` for final exit statuses and limitations.
The Go checks protect unchanged application behavior and legacy reports;
Go's race detector does not validate C code. No C ThreadSanitizer claim is made.
Native non-Linux execution, field deployment, packet delivery and forwarding
ratings were not tested or enabled.

Stop for independent ChatGPT review of Phase 1. Do not merge PR #407, close
issue #390, implement the Network Doctor importer, or enable ratings on the
strength of these historical records alone.
