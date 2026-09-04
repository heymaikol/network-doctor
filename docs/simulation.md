# Network simulation (`netdoc-sim`)

`netdoc-sim` builds a throwaway virtual network from a YAML scenario, breaks it
on purpose, runs the real netdoc binary inside it, and reports whether netdoc's
diagnosis matched the injected fault.

It is permanent development and regression-testing infrastructure. It ships as
its own executable in the Linux packages, so [Challenge
Mode](#challenge-mode), the one part meant to be played with rather than
scripted, is there without a Go toolchain. That is a second binary, not a
second product: `internal/simulation` is imported by `cmd/netdoc-sim` alone,
none of it links into `netdoc`, and the maintenance scope below is unchanged by
being installable.

This file covers setup, requirements, and how a run is built. The rest of the
authoritative reference is split by topic, all version-controlled beside the
code it documents:

- **[Scenario authoring](simulation-scenarios.md)**: the YAML schema, service
  and fault semantics, adding or changing a scenario, and the published
  [JSON Schema](../schema/simulation-scenario-v1.schema.json) editors validate
  scenario files against.
- **[Hunts and triage](simulation-hunts.md)**: deterministic campaigns,
  generated bug hunts, and nightly triage automation.
- **[Challenge Mode](simulation-challenge.md)**: commands, the daily
  challenge, starter packs, the challenge contract, and scoring.

For narrative walkthroughs and orientation instead of the reference, see the
wiki's [Simulator
Overview](https://github.com/heymaikol/network-doctor/wiki/Simulator-Overview),
[Challenge Mode](https://github.com/heymaikol/network-doctor/wiki/Challenge-Mode),
and [Hunts and Triage](https://github.com/heymaikol/network-doctor/wiki/Hunts-and-Triage)
guides.

## Getting it

Every Linux package ships `netdoc-sim` beside `netdoc`, from the same release
and at the same version; see [Install](../README.md#linux). Nothing else to
fetch:

```sh
netdoc-sim help
netdoc-sim capabilities
netdoc-sim scenarios
netdoc-sim validate broken-dns
netdoc-sim run broken-dns
```

Linux only. The binary is not in the macOS or Windows downloads, because the
backend is Linux namespaces and there is no other one; see
[Limitations](#limitations). On macOS and Windows, run the published image
through a Linux container runtime instead; see [Running it in a
container](#running-it-in-a-container).

Contributors building from a clone still want the pair, so a run grades the
netdoc that was just changed rather than the installed one, which is what step 2
of [Which netdoc gets run](#which-netdoc-gets-run) picks up:

```sh
CGO_ENABLED=0 go build -o netdoc .
CGO_ENABLED=0 go build -o netdoc-sim ./cmd/netdoc-sim
./netdoc-sim run broken-dns
```

Use the commands themselves for current inventory and flag details.

`netdoc-sim scenarios` is the complete list of built-in scenarios. A scenario
argument may also be a path to a YAML file.

## Purpose and maintenance scope

netdoc must distinguish DNS, routing, transport, proxy, TLS, and service
failures. A simulation makes the fault known by construction, so netdoc's
machine-readable diagnosis can be graded instead of eyeballed. No model decides
whether it was right.

The simulator, including campaigns, hunts, and triage, is maintained for bug,
safety, correctness, determinism, compatibility, and regression work. Add a
fault model or scenario only for a real bug, diagnostic blind spot, reproducible
field condition, regression, or identified missing network behavior relevant to
Network Doctor. General simulator expansion is not a project goal.

## Requirements and safety

The backend is Linux-only. It needs unprivileged user namespaces and the `ip`,
`nsenter`, `nft`, and `tc` tools; `netdoc-sim capabilities` reports the current
host's support and the privileged operations a run would perform. Seeded netem
loss or jitter additionally needs iproute2 6.6 or newer.

### Which netdoc gets run

Every command that runs netdoc picks the binary once, in the launcher, where
`$PATH` and the working directory still mean what the user meant by them, and
forwards the resolved absolute path into the namespaces. The order is:

1. `-netdoc` when given. A path (`./netdoc`, `/opt/builds/netdoc`) names that
   file; a bare name (`netdoc`) is looked up on `$PATH`, exactly as a shell
   would, resolved against the working directory. An explicit binary that does
   not exist or cannot be executed is an error, and nothing falls back to a
   different netdoc.
2. A `netdoc` sitting next to the `netdoc-sim` binary, which is what makes
   `./netdoc-sim run healthy` use the `./netdoc` built beside it. A file with
   the right name this OS will not execute is skipped rather than preferred.
3. A `netdoc` on `$PATH`.

Two traps: `go run ./cmd/netdoc-sim` puts the binary in a build cache, so step
2 finds nothing there, so build `netdoc-sim` or pass `-netdoc`. And build netdoc
with `CGO_ENABLED=0`, or a cgo build may resolve through the host's system
resolver rather than the node's private `/etc/resolv.conf`, testing the host
instead of the simulation.

A run needs no root, sudo, or setuid helper. The launcher re-executes a director
inside a new user, network, and mount namespace, with the caller's uid mapped to
root only there. The director can create bridges, veth pairs, routes, nftables
rules, qdiscs, and low-port listeners inside its owned namespaces, but the
kernel gives it no authority over the host network.

The simulator registers nothing under `/run/netns` or `/etc/netns`. Node
processes carry `PDEATHSIG=SIGKILL`; when the owning process exits, the kernel
reclaims their namespaces and network objects. `-keep` deliberately keeps that
process tree alive for inspection until interrupted or released with
`netdoc-sim cleanup`.

Use these before debugging backend operations:

```sh
./netdoc-sim run broken-dns -dry-run # print generated commands, execute none
./netdoc-sim run broken-dns -v       # log commands as they run
./netdoc-sim run broken-dns -keep    # retain the isolated network
./netdoc-sim list
./netdoc-sim inspect <id>
./netdoc-sim cleanup <id>            # or: ./netdoc-sim cleanup -all
```

The generated `ip`, `nft`, `tc`, and `nsenter` commands are safe because the
director executes them after isolation. Do not copy them into a host shell as a
substitute for running the simulator. Scenario values never become shell
strings; the backend constructs argument slices from validated logical names
and addresses.

## Running it in a container

**Challenge Mode uses the real Linux namespace simulator inside a Linux
container. macOS and Windows do not emulate the simulator themselves.** The
image is packaging, not a port: it carries the same `netdoc-sim` the Linux
packages carry, and that binary builds its network out of the same unprivileged
user, network and mount namespaces described above. There is one backend, and
this is it running on the Linux kernel your container runtime already provides.

The portability boundary is therefore the runtime, not the simulator. Docker
Desktop, Podman Desktop, Rancher Desktop or `podman machine` on macOS and
Windows, Docker or Podman on Linux. Anything that runs a Linux container will
do, and nothing else is needed. No clone, no Go toolchain, no knowledge of
namespaces.

```text
macOS / Windows / Linux host
  └── Docker / Podman                 Linux kernel, container runtime's own
        └── netdoc-sim                the released binary, unmodified
              └── user + net + mount namespaces   the same backend as native
                    └── netdoc        /usr/bin/netdoc from this same image
```

### Running it

```sh
docker run --rm -it --cap-add SYS_ADMIN ghcr.io/heymaikol/netdoc-sim:latest challenge
```

`podman run` takes the same line, and does not need the capability at all:

```sh
podman run --rm -it ghcr.io/heymaikol/netdoc-sim:latest challenge
```

The entrypoint is `netdoc-sim`, so everything after the image name is an
ordinary `netdoc-sim` command line and nothing re-parses it:

```sh
IMAGE=ghcr.io/heymaikol/netdoc-sim:latest
docker run --rm -it --cap-add SYS_ADMIN $IMAGE challenge -difficulty hard
docker run --rm -it --cap-add SYS_ADMIN $IMAGE challenge -id V4-005CCD
docker run --rm --cap-add SYS_ADMIN $IMAGE challenge -id V4-005CCD -answer tcp_port_blocked -json
docker run --rm --cap-add SYS_ADMIN $IMAGE run broken-dns -json
docker run --rm --cap-add SYS_ADMIN $IMAGE capabilities
docker run --rm $IMAGE scenarios
```

`-it` is for the parts where a person is asked something: the challenge shell,
and the answer menu. Drop it for automation and pass `-answer` or `-give-up`,
which is what `-json` requires anyway, since a piped stdin is consumed by the shell,
so a challenge run without a terminal and without a submission scores a give-up.
Exit codes and stdout are the ones documented for each command; `-json` on
stdout stays parseable because the session prints to stderr.

Tags are immutable per release, as in `ghcr.io/heymaikol/netdoc-sim:v1.11.3`, with
`latest` following the newest release the way the Homebrew formula and the Scoop
bucket do. Pin the version tag in anything automated.

The image is published for `linux/amd64` and `linux/arm64`. CI runs the full
container integration suite on native `amd64`, then builds and executes the
`arm64` image under QEMU to verify its version and supported `linux-netns`
capability report. The lightweight smoke leaves the namespace scenarios to the
native suite, where they already exercise the backend in depth.

### What the container is allowed to do

The simulator needs **no capability at all**. It creates a user namespace and
becomes root inside it; on the host side of that namespace the kernel gives it
nothing, which is the same guarantee a native run has. `--cap-drop ALL` changes
nothing about a run, and a test in `container_test.go` proves it by taking every
capability away and running a full simulation.

`--cap-add SYS_ADMIN` is there for Docker's *seccomp* profile, not for the
simulation. That profile refuses `clone(CLONE_NEWUSER)`, `unshare`, `mount` and
`setns` unless the container was configured with `CAP_SYS_ADMIN`, so the flag
is what permits the syscalls, and the image runs as an unprivileged user
(`netdoc`, uid 1000) so that the capability is not what the work is done with.
Podman's default profile permits those syscalls already, which is why it needs
no flag.

If you would rather grant no capability, relax the filter directly instead:

```sh
docker run --rm -it --cap-drop ALL --security-opt seccomp=unconfined $IMAGE challenge
```

Both forms are tested. Pick by which you would rather widen: a capability the
process is not in a position to use, or the syscall filter.

**`--privileged` is not required, and neither is anything else on this list.**
The image needs no `NET_ADMIN` (all network configuration happens inside the
namespaces it creates), no host network, no host PID namespace, no bind mounts,
no Docker socket, and no access to any host path. `--cap-add NET_ADMIN` on its
own does not even work, which is the clearest statement of what the requirement
actually is. The simulated topology is built inside the container and disappears
with it; your machine's real interfaces, routes, resolver and firewall are never
touched, on any host OS.

Two hosts need more than the flags above, and both are host policy rather than
anything the image can carry:

- **Docker Engine on a distribution with AppArmor** (Ubuntu, Debian). The
  `docker-default` profile denies `mount`, which the backend needs inside its
  own mount namespace: add `--security-opt apparmor=unconfined`.
- **Ubuntu 24.04 and later**, which restrict unprivileged user namespaces
  outright. This is the same restriction native runs hit, and
  `netdoc-sim capabilities` names it; the repository's CI clears it with
  `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`.

A run that is refused the namespace says so and stops, rather than falling back
to anything:

```text
netdoc-sim: cannot create the user, network and mount namespaces a simulation
runs in: fork/exec /usr/bin/netdoc-sim: operation not permitted.
```

That message is the one to match against this section. Note that `netdoc-sim
capabilities` cannot predict it: it reports the host knobs it can read cheaply,
and a container's seccomp profile is not one of them.

### What is in the image

Alpine, both release binaries at one version, and the tools two different
parties need: `ip`, `nsenter`, `tc` and `nft` for the backend, and `ping`,
`dig`, `curl`, `ss`, `traceroute` and `nc` for the person in the challenge
shell. `netdoc` and `netdoc-sim` sit together in `/usr/bin`, which is what makes
[step 2 of Which netdoc gets run](#which-netdoc-gets-run) select the image's own
netdoc, and every challenge result records that absolute path and the version that
binary printed, so a result names the build that produced it:

```json
"netdoc": {"path": "/usr/bin/netdoc", "version": "netdoc v1.11.3"}
```

The image sets `NETDOC_SIM_CHALLENGE_COMMAND` so the replay line and the share
block invite readers with a `docker run` command rather than with a `netdoc-sim`
they may not have. It changes nothing about the puzzle or the scoring; override
it with `-e NETDOC_SIM_CHALLENGE_COMMAND=...` for another runtime.

A `-daily` played in the image can still put its share block on the host
clipboard, and needs no mount, socket or extra capability to do it: the request
is an OSC 52 escape written to the terminal `-it` already attached, and the
terminal is on the host. A runtime or terminal that does not carry it through
simply leaves the printed block to be copied by hand.

Nothing survives a container: a challenge keeps no simulation, writes no state,
and an interrupted or failed run leaves neither processes nor namespaces behind
even in a container that is reused for another run.

### Building and testing it locally

```sh
docker build --build-arg VERSION=dev -t netdoc-sim:test .
NETDOC_CONTAINER_IMAGE=netdoc-sim:test go test -tags container -count=1 -v .
```

The tests run the built image: both binaries at the tag's version, a real
namespace-backed scenario, a real challenge that stays deterministic across
runs, exit-code propagation, cleanup after an interrupted run in a reused
container, and both privilege claims above, including the negative one, which
denies `clone(CLONE_NEWUSER)` through a seccomp profile and requires the
controlled failure rather than a silent fallback. They skip without an image or
an engine unless `NETDOC_REQUIRE_CONTAINER=1` is set, which is what CI sets.

Native Linux stays exactly as it was. The container supplements it: contributors
and anyone on Linux should keep running `./netdoc-sim` directly, which is faster,
needs no runtime, and is what the namespace integration suite exercises.

## How a run is built

```text
launcher                         host namespaces, no privileges
  └── director                   new user + network + mount namespace
        ├── bridge × segment
        ├── node holder × node   private network + mount namespace
        │     └── test services
        └── nsenter … netdoc     unmodified binary under test
```

Each logical segment is one bridge. A node interface is a veth peer attached to
that bridge; a router is an ordinary node attached to multiple segments. Each
node gets a private generated `/etc/resolv.conf`. `netdoc` runs unmodified in
the selected client node, so the simulator does not reimplement probes or
verdict logic.

Route and neighbor evidence comes from the kernel after the real probes run,
not from repeating the YAML. Generated device names are mapped back to logical
segment names in reports. IPv4 and IPv6 can share one logical interface, while
family-specific routes and reachability remain separate evidence.

Per-family internet reachability is observed the same way: after the probes,
the node holder tries controlled endpoints from inside its own namespace until
one answers. It reads no diagnosis, verdict, or scenario expectation, so this
evidence can contradict netdoc, which is the point of having it. It is a
point-in-time observation of the state the run finished in, so under a timed
fault it describes that instant, not the whole run.

It lands in `family_reachability`, separately from the controlled-target
records below, and carries one of three states per family: `reachable`, `unreachable`,
or `unavailable`. A family the client carries no address for is `unavailable`:
nothing was dialed, so no target or path is named, and untested is not the same
as unreachable. Both families always get a record, so a family with no record
means the measurement never ran; readers treat that as unknown rather than as
an absent family. `unavailable` is also a word netdoc never uses, which is what
keeps the two sides distinguishable in a report.

Multipath scenarios also probe literal test targets when the address and TCP
service are both simulator-owned, providing an independent alternate-path
control. Those records land in `controlled_targets`, use the kernel-selected
route, and are dials the simulator performed itself; single-path, hostname, and
arbitrary external targets are not simulator reachability evidence, and
netdoc's `target_tcp` verdict is never one of these records. Route selection
alone still does not prove reachability.

Both are evidence in the one direction that keeps the simulator honest:
observations independent of the diagnosis establish truth, and the diagnosis is
graded against that truth. Nothing derived from netdoc's report is stored as
simulator evidence, which is why no evidence field carries a diagnosis verdict.

## Probe endpoint drift

**Check this section before changing fixed probe endpoints in
`internal/diagnostic/checks.go` or `internal/diagnostic/encrypteddns.go`.**

The simulation has no internet. Scenarios claim netdoc's compiled-in public
addresses as node aliases and serve its fixed probe names from simulator DNS.
If an internet, captive-portal, default public-DNS, or probe-host constant
changes, update the corresponding `aliases`, DNS records, and expectations
under `internal/simulation/scenarios/`, and the internet endpoint list in
`internal/simulation/runner.go` that the simulator dials for its own
reachability evidence. The captive-portal check has two endpoints, so that
includes the paths and clean responses `serveHTTP` answers in
`internal/simulation/services.go`, which are kept in step with
`portalEndpoints` by hand.

`healthy` is the canary. It expects the fixed internet, public-DNS, and
encrypted-DNS probes to pass; endpoint drift makes it fail with a
`false_positive` suggestion naming the stale probe. That failure is
intentional. Update the affected scenarios and rerun:

```sh
./netdoc-sim run healthy
```

Do not make the control tolerant. A second manually maintained endpoint table
would drift for the same reason, so the authoritative values remain in the
production probe files and the scenario files that claim them.

## Scenario authoring

Moved to [`docs/simulation-scenarios.md`](simulation-scenarios.md#scenario-authoring):
the four-part schema, the YAML shape, routed/dual-stack examples, service and
fault semantics, and adding or changing a scenario.

## Deterministic campaigns and reproduction

Moved to [`docs/simulation-hunts.md`](simulation-hunts.md#deterministic-campaigns-and-reproduction):
seeded fault campaigns and how to reproduce one exactly.

## Deterministic bug hunts

Moved to [`docs/simulation-hunts.md`](simulation-hunts.md#deterministic-bug-hunts):
generated mutation cases, what a hunt false negative means, and generator
versioning. Nightly triage automation is there too, under [Triage and nightly
automation](simulation-hunts.md#triage-and-nightly-automation).

## Challenge Mode

Moved to [`docs/simulation-challenge.md`](simulation-challenge.md): commands,
the daily challenge, starter packs, [the challenge
contract](simulation-challenge.md#the-challenge-contract), scoring, and
[adding a new playable
diagnosis](simulation-challenge.md#adding-a-new-playable-diagnosis).

```sh
netdoc-sim challenge -id V4-8F42C1   # a specific puzzle, playable by anyone
```

### The challenge contract

Moved to [`docs/simulation-challenge.md#the-challenge-contract`](simulation-challenge.md#the-challenge-contract).

### Adding a new playable diagnosis

Moved to [`docs/simulation-challenge.md#adding-a-new-playable-diagnosis`](simulation-challenge.md#adding-a-new-playable-diagnosis).

## Tests and CI

The rootless simulator tests and CLI dispatch tests need no namespaces:

```sh
go test ./internal/simulation ./cmd/netdoc-sim
go test -tags integration ./internal/diagnostic ./internal/simulation
```

The end-to-end suite builds real namespaces and skips when the backend is not
available. `-v` is what makes that skip and its reason visible, and `-count=1`
keeps a cached result from standing in for a run:

```sh
go test -tags netns_integration -count=1 -v ./internal/simulation
```

Set `NETDOC_SIM_REQUIRE_NETNS=1` only on a machine or CI job that is required to
exercise the backend; it turns an unavailable backend from a skip into a
failure. The tests themselves remain rootless. CI's throwaway Linux runner
adjusts its host AppArmor setting before this command; `netdoc-sim` never makes
that change or escalates privileges.

Changes to the `Dockerfile` or to the image's release job additionally need the
artifact tested, on an engine, rather than the file reviewed:

```sh
docker build --build-arg VERSION=dev -t netdoc-sim:test .
NETDOC_CONTAINER_IMAGE=netdoc-sim:test go test -tags container -count=1 -v .
```

See the repository's [Tests section](../README.md#tests) for the complete
validation gate. A documentation-only change does not require running namespace
integration tests unless it exposes a reason to verify namespace behavior.

## Limitations

- Linux is the only maintained backend. The container image is packaging around
  that backend, not a second one: it needs a Linux container runtime, and gives
  macOS and Windows no simulator of their own.
- Topology is static unicast IPv4/IPv6 over simulator-owned bridges: no NAT,
  address autoconfiguration, dynamic routing, tunnels, ECMP, or VLAN model.
- Simulator services are deliberately narrow probe fixtures, not general DNS,
  HTTP, proxy, TLS, QUIC, encrypted-DNS, or TCP implementations.
- Timed faults reproduce requested content and ordering, not hard real-time
  application.
- Campaigns are sequential fault-injection runs, not network-performance or
  statistical-significance tooling.
