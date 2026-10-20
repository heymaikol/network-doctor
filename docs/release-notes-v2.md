# Network Doctor v2.0.0 release notes

> **Planned release, not yet published.** v2.0.0 has no tag and no release
> yet. These notes describe what is merged to `main` since v1.19.4. The v2
> Go module path arrives with a separate change that has not merged, so the
> path shown in the upgrade section does not resolve yet.

Network Doctor v2.0.0 adds offline routing analysis. You record a topology,
or capture FRR output, and `netdoc` explains how traffic should leave the
network, where the recorded evidence disagrees, and what a failure would
change. It also corrects several diagnostic results. Some of those corrections
change a verdict or cause you saw in v1.19.4, so read the compatibility section
before you compare old and new results.

## Major capabilities

- **Route path explanation** for one destination, from a topology file you
  record, with asymmetry and configuration-drift findings.
- **Failure simulation** over recorded tables: a router, an interface, an OSPF
  adjacency, or one next hop.
- **FRR import** for OSPF and BGP captures, offline, with findings that name
  the evidence they rest on.
- **Route context for two-sided diagnosis**, from topology files for each side.
- **Diagnostic corrections** to DNS, proxy, SSH alias, and command-line
  handling.

Nothing in these features contacts a router or scans the network. They read
files you provide.

## Routing and topology intelligence

Each feature below reads evidence you supply. The tool does not discover your
network or its complete topology. Missing evidence is reported as unknown, not
as a failure.

### Route path explanation

`--explain` takes a topology file and an IP address and reports two paths. The
expected path comes from the control plane, and the forwarding path comes from
the FIB. Where the two disagree, the explanation says so.

```sh
netdoc --explain topology.json 10.20.40.8
netdoc --explain --json topology.json 10.20.40.8
```

See [Route path explanation](reference.md#route-path-explanation).

### Asymmetry

When the topology file names `source.address`, the explanation also walks the
return route. It reports whether the return retraces the forward route. It
separates benign asymmetry, which is not a fault by itself, from asymmetry with
a concern attached. Missing return evidence is reported as unknown, never as
asymmetry. See [Asymmetry](reference.md#asymmetry).

### Configuration drift

When the file records intended routes, the explanation compares intent with the
FIB at each node where intent decides. Findings range from `benign` to
`redundancy_lost` and `reachability_lost`, and an incomplete table yields
`unknown`, not a loss. Drift appears in the explanation output only, and it
does not change the exit code. See [Drift](reference.md#drift).

### Failure simulation

Add a failure flag to `--explain` to ask what would change if a recorded
element went away:

```sh
netdoc --explain topology.json 10.20.40.8 --fail r2
netdoc --explain topology.json 10.20.40.8 --fail r1:eth1
netdoc --explain topology.json 10.20.40.8 --fail-ospf r1:eth1:r2
netdoc --explain topology.json 10.20.40.8 --fail-next-hop r1:10.0.1.2
```

Each affected destination gets one impact: `none`, `redundancy_lost`,
`reachability_lost`, or `unknown`. The simulation removes the failed element
from the recorded forwarding. It recomputes no route, runs no SPF, and predicts
no convergence time. For a router or interface failure, a destination that a
routing protocol could re-route is reported as `unknown` rather than as lost.

A `tunnels` entry in the topology file names the underlay that carries a
tunnel. With it, an underlay failure is reported against that tunnel. Without
it, the tunnel reads as a direct link, so an underlay failure cannot be seen.
See [Failure simulation](reference.md#failure-simulation).

### FRR OSPF import

`--import-frr-ospf` reads OSPF output that FRR printed earlier. A manifest
names each capture. The import reports adjacency states, areas, router IDs, and
interface facts, and it checks neighbors against what the other end reports.
It runs no probe and contacts no router.

```sh
netdoc --import-frr-ospf manifest.json
netdoc --import-frr-ospf manifest.json --write-topology topology.json
```

`--write-topology` writes a file only when every capture and record is accepted.
That file is the input `--explain` reads. See
[FRR OSPF import](reference.md#frr-ospf-import).

### FRR BGP import

`--import-frr-bgp` reads BGP summary and route captures from FRR. It reports
each router's sessions, with each state as FRR printed it, and the prefixes
learned from each peer. Two simulations apply to the imported table only:

```sh
netdoc --import-frr-bgp manifest.json --withdraw-bgp r1:192.0.2.2:198.51.100.0/24
netdoc --import-frr-bgp manifest.json --fail-bgp-session r1:192.0.2.2
```

Each simulation rates the affected prefixes from that table. The forwarding
impact stays `unknown`, because the import reads no RIB, FIB, or topology. See
[FRR BGP summary import](reference.md#frr-bgp-summary-import),
[simulated prefix withdrawal](reference.md#simulated-prefix-withdrawal),
and [simulated BGP session loss](reference.md#simulated-bgp-session-loss).

### Route context for two-sided diagnosis

`--route-a` and `--route-b` add a topology file's routing context to an offline
`--two-sided` reading. The context is used only when the file belongs to that
side's own run. It never changes where the failure is placed. See
[Route context from topology files](reference.md#route-context-from-topology-files).

## Existing diagnostic improvements

- **DNS keeps the answer that arrived.** When a lookup loses the query for one
  address family after the other family answered, the answer is kept instead of
  failing the whole lookup. This applies to the system resolver (#365) and to the public
  second-opinion resolver (#394).
- **LAN map names from SSH config.** An address in a `Match` block no longer
  takes the `Host` alias before it, so the names the LAN view shows from
  `~/.ssh/config` stay correct. A later `Host` block is still read (#345).
- **`--` ends option parsing.** Arguments after `--` are read as operands, not
  options. A flag-like argument after the marker is refused as an extra argument
  instead of being applied (f0f220f).
- **Watch reuses passing checks.** In `--watch` without `--profile`, and in the
  TUI, a passing check can reuse its measurement from an earlier pass for up to a
  minute, so a stable pass runs only the checks it cannot reuse. On Linux, a
  route, address, link, policy-rule, or nexthop change refuses reuse, and any
  other platform relies on the minute alone. A pass that reused a check and then
  finds a changed status, cause, or route is discarded, and the next pass
  measures every check. After a failing pass, every check runs. With `--profile`, every
  pass runs every check. The TUI labels each reused check with the time it was
  measured. See [Usage details](reference.md#usage-details).
- **Tunnel underlay reasons name the unknown segment.** When an underlay walk
  is unknown rather than cut, the tunnel's reason names that segment, instead of
  saying the underlay meets the failure (#397).
- **IPv6 failure simulation is tested.** The simulation's IPv6 behavior, including
  link-local next hops, has its own test coverage (#398). This adds tests, not
  new behavior.

## Compatibility and behavior changes

### Unchanged

- **Command-line flags.** No v1.19.4 flag was removed or renamed. The new flags
  are listed under `netdoc --help`.
- **Probe IDs.** `netdoc --list-checks` prints the same IDs as v1.19.4, so
  `--check` and `--skip` lists keep working.
- **Snapshots.** The snapshot schema is still `netdoc.snapshot.v1`. A snapshot
  written by v1.19.4 reads in v2.0.0.
- **JSON reports.** The published report schema is unchanged, and existing field
  names are the same.
- **Exit codes.** `0`, `1`, and `2` keep their meanings. Drift and failure
  simulation findings in `--explain` output do not change the exit code, which
  stays `0`. Input the command refuses exits `2`.
- **Go version.** The module still requires Go 1.27.0.

### Verdict-affecting changes

These change a check's status or cause, so a script or a saved comparison can
see a different result for the same network:

- **DNS.** A DNS row can now pass where v1.19.4 reported a failed lookup, when
  one address family's query was lost and the other family answered (#365, #394).
- **Environment proxy.** The `Internet (env proxy)` row decides from the HTTPS
  proxy, `HTTPS_PROXY` or else `ALL_PROXY`. An `HTTP_PROXY` value alone no longer
  makes the row test that proxy. The row reports N/A, and its detail says a
  proxy applies to plain HTTP (#339).
- **SOCKS5 host unreachable.** A SOCKS5 "host unreachable" reply, code 4, is now
  reported as destination unreachable, even for hostname requests. Before, a
  hostname request reported it as a proxy-side DNS failure. The proxy may have
  resolved the name and then failed to reach the host (1e5e850).

The changes above affect verdicts and causes. They do not affect command-line
syntax or the snapshot and report formats.

### Output values

- **Watch JSON.** With `--watch --json`, a reused check reports `ms` as `0`,
  because it was not measured on that pass. A script that reads `ms` as the
  check's own duration sees `0` for those rows. The stream has no reuse marker
  yet, so the value is the only sign. The one-shot report is unchanged.

## Installation and upgrade

### Upgrading from v1.19.4

Existing installs keep working. Homebrew, Scoop, COPR, the `.deb`, `.rpm`, and
`.apk` packages, and prebuilt binaries keep their current install and upgrade
paths. The v1 `go install` path keeps installing v1 releases. See
[Installation details](installation.md).

Snapshots from v1.19.4 remain readable. If you script against a verdict, check
the verdict-affecting changes above before you treat a new result as a
regression.

### Go module path

Go requires a module at major version 2 or later to carry the major version in
its module path. Once the v2 change merges, the module path is
`github.com/heymaikol/network-doctor/v2`. The path without `/v2` stays
associated with v1 releases, so the v1 command keeps installing v1:

```sh
go install github.com/heymaikol/network-doctor/cmd/netdoc@latest
```

The v2 command is:

```sh
go install github.com/heymaikol/network-doctor/v2/cmd/netdoc@latest
```

This v2 command cannot resolve until v2.0.0 is published. Until then, Go
reports `no matching versions for query "latest"`. Use the v1 command above
until the v2 release exists. The v2 path arrives with a separate change that
has not merged.

## Supported platforms

Network Doctor runs on Linux, macOS, and Windows. The probes, the diagnosis
engine, and the TUI are the same Go code on each platform. Platform details
that the OS does not provide, such as the default gateway or the Wi-Fi SSID,
come back empty rather than failing a probe. The offline routing commands read
files and open no sockets. The simulator's network-namespace tests run on
Linux. `netdoc-sim` and Challenge Mode need Linux namespaces. macOS and Windows run them in the published
container image.

See [Platform support](reference.md#platform-support) for the full
statement.

## Known limitations

- **Topology completeness is not guaranteed.** The explanation is only as
  complete as the file. A link or route that the file does not record is not
  considered.
- **Failure simulation uses recorded evidence.** It does not predict routing
  protocol convergence, timing, or the tables after a failure.
- **BGP forwarding attribution is incomplete where evidence is missing.** The
  BGP simulations change the imported table only, and the forwarding impact
  stays unknown.
- **Missing evidence is unknown.** It never counts as a failure.
- **Tunnel attribution needs an explicit record.** Without a `tunnels` entry,
  the tunnel is read as a direct link.
- **The tool does not contact routers for FRR output.** You capture the output,
  and `netdoc` reads it.

Work that is not in this release:

- Route-policy changes in failure simulation
  ([#388](https://github.com/heymaikol/network-doctor/issues/388)).
- Tunnel records with provenance
  ([#389](https://github.com/heymaikol/network-doctor/issues/389)).
- Correlating BGP session and withdrawal loss with the forwarding that gets
  selected ([#390](https://github.com/heymaikol/network-doctor/issues/390)).
- Multi-source blast-radius reports
  ([#391](https://github.com/heymaikol/network-doctor/issues/391)).
- The network-wide topology and routing roadmap
  ([#272](https://github.com/heymaikol/network-doctor/issues/272)).

Some field-validation scenarios are still open, so this release does not claim
that every planned field scenario has been run.
