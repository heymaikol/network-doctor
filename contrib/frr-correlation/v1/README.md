# netdoc-frr-correlation/v1

Phase 1 implementation of the producer selected after review of PR #407 head
`729b1687d53aab0397ec95a457c3b019f4c0991b`. Independent review of this
implementation and its evidence is still required. No Network Doctor importer,
forwarding rating, general Zebra RIB import, merge, release or deployment is
included. Application behavior and existing reports are unchanged.

This directory is a lab-only FRR extension and producer-side packager. It does
not parse CLI output to manufacture identity relationships. The original
[investigation](../../../testdata/frr/10.7.0/bgp/correlation-investigation/README.md)
remains the historical design baseline, with its bytes and manifests preserved.

## Verified subset

The accepted producer is the exact `verified-build.json` artifact set, built
from FRR 10.7.0 commit `87fe21fda92ce9e2ba3eaf2b0a327bf71ee183ef`, on Linux
x86_64 with the recorded kernel release. That file pins executable/library
hashes, source archive, instrumentation hash, complete builder package lock,
configuration and compiler flags. Another build, kernel, OS, architecture or
schema is refused by the packager, even if it calls itself FRR 10.7.0. The filesystem must support Linux no-replace
rename; unsupported operations fail closed without an overwrite fallback.

Verified attribution covers default VRF, table 254, IPv4 unicast, ordinary eBGP
paths, single-next-hop static routes resolving through BGP, and multiple eBGP
paths with identical next-hop semantics sharing one forwarding leg. Every
contributor is retained. Distinct-next-hop ECMP, active add-path IDs, stale
paths/GR retention, iBGP/confederations, table maps, weights, labels, SRv6,
on-link overrides, backup nexthops, other tables/VRFs, and other recursive
classes are outside this subset. Unsupported records remain visible with
refusals. Recognizing `ospf` as an origin label does not enable OSPF claims.

## Actual ownership boundaries

`frr.patch` adds narrowly scoped fields/hooks to the pinned upstream tree.
The `.inc` files are included in their owning FRR translation units; they
are not linked into Network Doctor.

1. A BGP peer and path receive independent monotonically allocated object IDs.
   Each Established transition receives a new session ID. Every exported path
   snapshot has a new revision. IDs include a random daemon-instance epoch;
   addresses, prefixes, AS paths and memory addresses are not identities.
2. `bgp_zebra_announce_parse_nexthop` records each actual contributing
   `bgp_path_info`, before the valid-next-hop count advances. The announcement
   carries the entire contributor set in a private, bounded ZAPI extension:
   flag `0x0800`, magic/version `0x4e444301`, network-order integers and a
   36-character epoch. Both daemons must be the pinned build. No upstream
   protocol interoperability is claimed for this private extension.
3. Zebra copies that payload onto the received route entry, separately from
   shared next-hop groups. Each entry has its own ID and decision generation.
   Resolution recomputation starts a new generation. A destination object has
   its own ID and monotonically recorded selection/replacement/removal sequence.
4. At the successful `nexthop_active` lookup, the exporter records the actual
   consuming route/generation, leg, selected resolving route/generation,
   gateway, lookup flags, VRF/table and interface context. It assigns a
   resolution ID and retains that reference on the consuming route. It does
   not reconstruct the choice with a second lookup. These references are
   route-owned, so next-hop-group deduplication cannot substitute another
   route's resolution.
5. The immutable dataplane context copies route/generation, operation ID and
   all resolution references. The extension requests positive `NLM_F_ACK`
   responses for traced route messages. `netlink_send` and `netlink_ack` are
   recorded at the exact context/sequence association, including raw errors.
6. The main-thread result records whether that exact entry/generation and
   dataplane sequence still match and, for installation/update, remain selected
   and not removed. A later destination-level notification is not used as a
   substitute. Successful kernel ACK plus successful, accepted result is
   necessary for installation credit; silence, missing results and stale
   generations receive none.

Repeated source nexthops can be sorted or deduplicated by FRR. Version 1
preserves the route's complete contributor set and source ordinals, rather
than assigning an arbitrary peer to a deduplicated kernel leg. It does not
provide a general per-leg ownership algorithm for different next hops.

## Format and completeness

`schema.json` is the versioned JSON Schema, draft 2020-12. `bundle.py` consumes
only the extension's JSONL streams and the pinned build manifest. It checks
explicit IDs, revisions, session state, namespaces, contexts, complete
contributor sets, resolution references, netlink sequences and results.
Cross-record comparisons validate an explicit reference; equal CLI fields
never create a reference.

| Collection | Meaning |
| --- | --- |
| `producer` | Exact accepted build identity and artifact hashes. |
| `capture` | Closed source histories, boot/namespace identity, gap status, pending operations, and attribution completeness. |
| `sources` | Raw file names, SHA256, daemon epochs, record counts and monotonic boundaries. |
| `bgp_paths` | Peer/session/path IDs and snapshot revisions with actual source attributes. |
| `routes` | Received entries and their generations, origin labels and serialized contributor references. |
| `resolutions` | Actual successful resolution decisions, each with a distinct identity. |
| `fib_entries` | Historical accepted dataplane installation/update results. |
| `claims` | Explicit `path_submitted_as_route`, `route_leg_resolved_by_route`, and `route_installed_as_fib` edges, with source-record references. |
| `refusals` | Unsupported contexts, missing acknowledgments/results, stale results and unmapped origins. |

UTC and monotonic timestamps are unsigned integer nanoseconds. Consumers must
preserve integers exactly, rather than round them through IEEE double precision.
A source-record reference is `daemon-epoch:sequence`; object IDs are
`daemon-epoch/kind/counter`. Paths also require their snapshot revision.

The writer serializes concurrent records, bounds each line to 65535 bytes and
each stream to 64 MiB / one million records. One mutex owns emission, trailer,
flush, close, and publication. The private `emit_locked` helper does not acquire
that mutex again. Shutdown is idempotent and closes its descriptor exactly once,
including Linux close errors. Captures remain `.jsonl.partial` until both flushes
and close succeed; no truncation rollback is needed. Partial streams are refused
even when they contain an otherwise valid complete trailer. Late emission never
appends after the trailer: it marks failure and revokes the published filename
back to `.partial`. Both publication and revocation use Linux
`renameat2(..., RENAME_NOREPLACE)`: existing regular files and symlinks are
never replaced, and there is no fallback to an overwriting operation. A kernel
or filesystem rejecting the operation leaves a refused partial publication.
Failed revocation also creates an exclusive `.jsonl.failed` marker; the packager
refuses any such marker even while the original final stream remains visible.
Existing failure markers and their symlink targets are never overwritten.
`ndoc_enabled` stays true after shutdown so hooks cannot
silently discard late events. One directory descriptor is retained until process
exit for revocation. Initialization runs once. Workers can already exist; the enabled state is
published after the start record under the same mutex.

Consume only after all producers have exited and the collection directory has
stopped changing. A failed late-event move leaves a failure marker and is refused.
If the filesystem prevents both that move and marker creation, diagnostics
invalidate the collection operationally; the packager cannot infer that
unrecorded storage failure from an isolated copied JSONL file. Retain diagnostics.
This is a trusted local writable-filesystem lab subset, not a guarantee against
storage failure, malicious capture copying, or power loss. Write/clock/flush/close
failures leave no acceptable published stream. A crash has no complete trailer. The packager
requires exactly one closed epoch of each daemon in the same boot/namespace;
it refuses restart histories rather than splicing epochs together.

`capture.complete=true` means the two bounded logging histories closed without
gaps. It does not mean every route has an attributable installation. Unknown
records and pending operations remain listed, and `attribution_complete` is
false when refusals exist. Shutdown can leave queued operations without a
main-thread result. Those operations get no installation claim.

`snapshot_complete` is always false. Claims are historical and cite the exact
operation result. Version 1 does not assert an atomic current FIB snapshot or
a simultaneous cross-daemon generation fence. A current-state consumer must
refuse that stronger claim. Kernel dumps are independent comparisons, not
operation acknowledgments or implicit path-to-FIB links.

The named FRR origin mapping recognizes `bgp`, `ospf`, `connected`, `static`
and `local`. Only BGP and OSPF are protocol origins in Network Doctor's current
model. Unknown strings and numeric kernel labels never default to static.
Build and capture hashes preserve provenance; they do not authenticate a
malicious producer. The operator must trust the verified executable and source
files. The lab records actual runtime dependency hashes separately.

## Reproduce

Use a fresh workspace directory. The build never installs FRR on the host.
Rootless Podman can keep its `--root`, `--runroot`, and storage entirely in
scratch directories. The Containerfile pins the Fedora base digest and every
installed package. It excludes RPM public-key pseudo-packages from install
arguments, then requires the entire resulting package database, including key
records, to match the lock.

Download the source archive from
`https://codeload.github.com/FRRouting/frr/tar.gz/87fe21fda92ce9e2ba3eaf2b0a327bf71ee183ef`.
Its SHA256 must be
`bf601f8f35b03a49a5a45981721394f00d3b9eac0c5bd77577732c4c4ffffa67`.
Build the Containerfile, mount this directory read-only at `/producer`, mount
scratch at `/work`, and run with `--network=none`:

```sh
bash /producer/build.sh /work/build-a /work/frr-source.tar.gz
bash /producer/build.sh /work/build-b /work/frr-source.tar.gz
cmp /work/build-a/build.json /work/build-b/build.json
```

Each output must be a new directory. The recipe verifies inputs, applies the
patch with zero fuzz, fixes locale/date/path mappings, builds five FRR executables
and libraries, exercises the real wire codec, stages `frr-root/`, and writes
`build.json` plus `SHA256SUMS`. The current two accepted clean builds produced identical
bytes for all eight staged artifacts. Their build logs and manifests are
preserved with the evidence. An exact package version that disappears from
repositories causes a failure; newer packages are not substituted silently.

For a live run, link `SCRATCH/frr-root` to the isolated build's `frr-root`, then
run from the repository root with fresh scratch directories:

```sh
SCRATCH=<scratch> BGPD_VTY_PORT=2605 ZEBRA_VTY_PORT=2611 \
  timeout 600 unshare -Urnm bash contrib/frr-correlation/v1/lab.sh
SCRATCH=<another-scratch> BGPD_VTY_PORT=2605 ZEBRA_VTY_PORT=2611 MODE=restart \
  timeout 600 unshare -Urnm bash contrib/frr-correlation/v1/lab.sh
```

The existing withdrawal-lab setup is reused. Network and mount mutations occur
only in disposable namespaces. No host interface, route, configuration or
installed FRR is replaced. Output is `SCRATCH/run/bgp-withdraw`. Accept a run
only with exit 0, `DONE`, and a complete recursive manifest. The restart run
itself succeeds while its producer bundle is deliberately refused:

```sh
python3 -I contrib/frr-correlation/v1/bundle.py <proof>/identity/r1 \
  --build contrib/frr-correlation/v1/verified-build.json --output bundle.json
```

Output must not already exist. Exclusive creation refuses existing files and
symlinks, including an output path that aliases source evidence.

A refused bundle has `capture.complete=false`, no claims, a refusal reason,
and process exit 2. The supported bundle validates with `schema.json` and is
deterministic from preserved raw sources. No command consumes it in Network
Doctor.

## Proof and remaining gate

See [the validation report](../../../testdata/frr/10.7.0/bgp/correlation-v1-noreplace/README.md)
for live runs, exact proven/unproven edges, independent observations, checksums,
negative tests, concurrency test, and reproducibility results. Approval of
the producer choice did not approve this implementation. Stop for independent
ChatGPT review before an importer or forwarding semantics is implemented.

Run the producer/schema tests in the locked builder, from this directory:

```sh
python3 -B -m unittest -v test_bundle
```

For writer/shutdown faults, from an accepted build's pinned FRR source directory:

```sh
gcc -UNDEBUG -DHAVE_CONFIG_H -I. -Ilib /producer/writer_test.c \
  -Llib/.libs -lfrr -ljson-c -pthread -o /work/writer-test
LD_LIBRARY_PATH="$PWD/lib/.libs" python3 -I /producer/test_writer.py /work/writer-test
```

The C test includes the actual current writer source for syscall fault injection;
these synthetic events never substitute for live daemon identity evidence.

The [current Sonar review](../../../testdata/frr/10.7.0/bgp/correlation-review-7df7be1/README.md)
is pinned to PR head `7df7be1`, including the high input-path finding's actual
flow, supported CLI threat model, and unsupported agent/server reuse. Earlier
triage is historical evidence. No remote finding or security rule is suppressed.
