# Scenario authoring reference

Authoritative reference for `netdoc-sim` scenario YAML: the schema, service
and fault semantics, and how to add or change one. See
[docs/simulation.md](simulation.md) for setup and the guide index.

## Scenario authoring

Built-ins live in `internal/simulation/scenarios/` and are embedded by
`internal/simulation/library.go`. Start from the closest existing scenario;
the YAML itself is the authoritative example for specialized features such as
routed and dual-stack networks, proxies, TLS, timed faults, and campaigns.

A scenario has four operational parts:

- `topology`: logical segments, nodes, interfaces, routes, resolvers, aliases,
  and bounded test services;
- `faults`: impairments applied before or during the diagnostic;
- `tests`: one or more real netdoc invocations in the client node;
- `expect`: the verdict and probe results that should follow.

This fragment shows the common shape without duplicating a complete scenario:

```yaml
name: broken-dns-with-working-ip-connectivity
topology:
  nodes:
    - {name: client, role: client, address: 10.77.0.10, resolver: 10.77.0.1}
    - {name: resolver, address: 10.77.0.1, services: [{type: dns}]}
faults:
  - {type: drop, node: resolver, direction: inbound, protocol: udp, port: 53}
tests:
  - {node: client, target: example.test:80}
expect:
  verdict: dns
  summary: Cannot resolve example.test: DNS failure.
  checks:
    - {id: dns, status: FAIL, fix: "name resolution failing: check /etc/resolv.conf / DNS"}
```

Use
[`broken-dns.yaml`](../internal/simulation/scenarios/broken-dns.yaml) as the
complete, validated single-segment example.

### Editor and tooling schema

A machine-readable [JSON
Schema](../schema/simulation-scenario-v1.schema.json) for scenario YAML is
published at `schema/simulation-scenario-v1.schema.json`, in Draft 2020-12.
Point an editor at it for field names, property completion, and enum
completion while authoring. It describes the v1 scenario input the parser
already accepts rather than proposing a replacement for it, so no existing
scenario needs changing to satisfy it.

What it catches is what a schema can see without a topology: misspelled and
unknown keys, which every object rejects because the parser decodes with
`KnownFields(true)`; wrong types; the fields a scenario cannot omit; and the
closed vocabularies, meaning service and fault types, node roles, proxy
schemes, certificate modes, DNS and link outcomes, and the expected probe ids,
statuses, verdicts, causes and address-family states.

`netdoc-sim validate` remains authoritative for semantic and cross-reference
validation. The schema describes the structural v1 input the parser accepts
before defaults and normalization, and it is designed not to reject a
structurally valid file merely to make the format cleaner: known zero, empty,
and default compatibility cases the parser accepts (`port: 0`, `status: 0`,
`portal: false`, an empty string or list) validate here too. The
cross-reference and topology-aware rules stay in Go: that exactly one node is a
client, that referenced names exist and are unique, that an address sits inside
its segment, that a gateway is on-link, that durations and percentages parse,
that scheduled offsets increase, and that a service or fault carries only the
options its type supports. Schema-valid does not imply semantically valid; a
file that passes the schema can still be rejected by `netdoc-sim validate`.

Network Doctor validates every built-in scenario against the file and compares
each frozen vocabulary and every `yaml:` field against the Go source, so the
published schema cannot fall behind the parser.

### Deterministic NXDOMAIN scenario

The built-in `dns-nxdomain` scenario represents an office printer whose
hostname, `printer.office.test`, has no DNS record while the interface, direct
internet path, QUIC, public DNS and encrypted DNS remain healthy. It is the
deterministic regression fixture for an isolated missing-name diagnosis:

```text
printer.office.test has no A/AAAA records according to either system or public DNS. (The general internet is reachable.)
Fix: check the hostname or publish the missing DNS record
```

Build and run the scenario from a clone with:

```sh
CGO_ENABLED=0 go build -o netdoc .
CGO_ENABLED=0 go build -o netdoc-sim ./cmd/netdoc-sim
./netdoc-sim run dns-nxdomain -repeat 3
```

The run provisions the network, executes the real
`netdoc printer.office.test` diagnostic in its client node, and cleans up. Add
`-keep` to retain it for inspection; the report prints its simulation id, and
`./netdoc-sim cleanup <id>` releases it.

The original `topology.subnet`, node `address`, and node `gateway` fields are
single-segment compatibility shorthand. Routed scenarios use named `segments`,
node `interfaces`, and validated `routes`; see
[`healthy-routed-network.yaml`](../internal/simulation/scenarios/healthy-routed-network.yaml).
[`two-path-healthy.yaml`](../internal/simulation/scenarios/two-path-healthy.yaml)
is the focused hunt control for two IPv4 defaults: ordinary traffic selects the
lower-metric preferred router, while a controlled literal target independently
proves the higher-metric alternate path.
[`two-router-healthy.yaml`](../internal/simulation/scenarios/two-router-healthy.yaml)
is the control for the single-default route faults. Its client LAN carries two
routers with different jobs: one holds the default out to the internet, the
other a specific route to the target's subnet. That is what makes "the
default points at the wrong on-link router" and "the specific route is missing"
expressible at all, and distinguishable from each other. Its second client test
is a controlled literal behind the internet router, reached over its own
specific route: that endpoint keeps answering when the default is repointed,
which is how a wrong default route is told apart from the network beyond the
gateway simply being down.
Dual-stack scenarios use `ipv4` and `ipv6` on the same segment and interface;
see
[`dual-stack-healthy.yaml`](../internal/simulation/scenarios/dual-stack-healthy.yaml).

Addresses are parsed and rendered canonically with `net/netip`. Routes accept a
prefix or `default`, never free-form `ip` syntax. Scenario authors cannot
provide kernel interface names, commands, executable paths, arbitrary proxy
URLs or environment variables, certificate keys or paths, qdisc handles, or
raw firewall expressions. The schema accepts logical intent and trusted code
derives the operating-system arguments.

### Services and faults

Do not maintain a second inventory here. The current service and fault types,
their fields, and validation limits are defined in
`internal/simulation/scenario.go` and `internal/simulation/timeline.go`; shipped
examples are discoverable with:

```sh
rg -n 'type:' internal/simulation/scenarios
rg -l 'campaign:' internal/simulation/scenarios
```

Some semantics are easy to get wrong even after reading a scenario:

- A `drop` with `direction: outbound` acts like a local firewall and can return
  an immediate refusal. `direction: inbound` silently discards arrival at the
  destination, so the sender waits for its timeout. Use inbound drops for a
  black-holed remote resolver or service.
- A `pmtu_blackhole` narrows one router interface and drops the ICMP
  fragmentation-needed replies that router would send about it. Both halves are
  required and neither is useful alone: narrowing a hop that still reports the
  smaller MTU is discovered and worked around, and narrowing an endpoint makes
  the local kernel refuse the send instead of losing the packet silently. It is
  rejected on a node that is not a router for that reason. Both endpoints must
  keep the default MTU, so the narrow hop has to be transit between two
  routers; `pmtu-blackhole.yaml` is the worked example.
- Public-looking aliases, including documentation-prefix IPv6 addresses, exist
  only in the private namespace. They do not create host or public routes.
- `socks5` resolves on the client before CONNECT; `socks5h` sends the hostname
  to the proxy's resolver. The paired SOCKS scenarios prove the location with
  DNS and CONNECT evidence rather than inferring it from success.
- A test's `proxy` block decides which variable netdoc is handed the proxy
  through, and the two fixtures are not interchangeable: a `socks5`/`socks5h`
  scheme arrives as `ALL_PROXY` and needs a `socks5` service, while `http`
  arrives as `HTTPS_PROXY` and needs an `http_connect` service. The
  `http_connect` fixture tunnels one authority per connection and answers
  anything else with a status code, so a scenario cannot mistake a refused
  request for a working one; `proxy-only-network.yaml` is the worked example,
  and it blocks direct egress rather than only pointing netdoc at the proxy.
  [`proxy-only-network-broken-dns.yaml`](../internal/simulation/scenarios/proxy-only-network-broken-dns.yaml)
  is the same network with the client's resolver taken away too. Its port 53
  drops are scoped to the client and to the configured resolver address on
  purpose: a CONNECT proxy resolves the tunnel authority in its own namespace,
  so a drop that also caught the proxy's lookups would take the proxy down
  along with the client and stop testing anything.
- TLS, QUIC, and encrypted-DNS fixtures generate private keys and certificates
  in memory. Only public CA certificates are written inside the mode-`0700` run
  workspace; trusted code points the netdoc process at the selected TLS CA and
  at the isolated fixed-endpoint trust directory the QUIC and encrypted-DNS
  fixtures share, without modifying a host trust store.
- The `encrypted_dns` fixture answers netdoc's encrypted-DNS row over both
  transports from one static zone (RFC 8484 DoH on its port and RFC 7858 DoT
  on 853) and accepts the plain TCP connect the direct-egress row makes, which
  is why the simulated internet serves it on 443 instead of a `tcp` sink. A node
  that claims `1.1.1.1` without it makes every scenario report a blocked
  encrypted resolver; a library test enforces that pairing.
- Plain DNS and encrypted DNS are separate capabilities, and the scenarios that
  say so have to break one without touching the other.
  [`encrypted-dns-blocked.yaml`](../internal/simulation/scenarios/encrypted-dns-blocked.yaml)
  drops TCP/443 and TCP/853 to `1.1.1.1` only, so port 53 keeps resolving and
  direct egress keeps its `8.8.8.8` fallback;
  [`plain-dns-blocked.yaml`](../internal/simulation/scenarios/plain-dns-blocked.yaml)
  drops port 53 on both transports and leaves the encrypted ports alone. Each
  one asserts the working rows beside the broken one, since an encrypted-DNS
  result collected on a dead network is evidence about the network.
- An `http` service with `portal: true` intercepts netdoc's connectivity checks
  the way a captive portal does: `/generate_204` and `/connecttest.txt` both
  answer `302` to a fixed sign-in URL instead of what they document, and every
  other path it serves is untouched. A plain `http` service answers both of
  those paths cleanly, so which node a connectivity name resolves to is what
  decides whether that provider is intercepted.
  [`captive-portal.yaml`](../internal/simulation/scenarios/captive-portal.yaml)
  is the worked example, and it leaves DNS, TCP/443, QUIC and the target
  healthy on purpose. That is what makes it a test of precedence: the portal
  verdict has to outrank the rows that all report success, and the direct-egress
  row has to stay FAIL rather than be downgraded by them, since behind a portal
  it is the portal answering. Both connectivity names resolve to the portal
  node there, because netdoc needs two independently operated endpoints
  intercepted on one pass before it will name a portal.
- [`selective-http-interception.yaml`](../internal/simulation/scenarios/selective-http-interception.yaml)
  is the negative case on the same topology: the two connectivity names resolve
  to different nodes, one intercepting and one plain, so exactly one provider is
  redirected. One provider treated differently is a fact about that provider, so
  the run has to warn on the direct-egress row and never reach the
  captive-portal verdict. It is also the drift canary for the second endpoint:
  if netdoc's expected clean payload changes, the untouched provider stops
  reading as clean here.
- An `http` service may set `date_offset` to a signed Go duration such as `72h`
  or `-30m`. Its `Date` header is the server's current wall clock plus that
  offset. Omitting the field leaves the standard HTTP server date unchanged.
- A `tcp` service with `banner` writes that fixed, newline-terminated greeting
  and then drains the connection until the client closes it. Banners are
  limited to 1024 bytes, and active connections close with the service.

### Timed faults

The `scheduled_netem`, `scheduled_dns`, and `scheduled_link` examples in the
scenario directory change the network while netdoc is running. T0 is the
instant just before the first netdoc process starts, and one timeline spans all
tests in that scenario.

The complete requested timeline is resolved and validated before a namespace
exists. Timing is best-effort: normal scheduling may delay application, so the
report records requested and actual offsets and marks events that were applied,
failed, or skipped. The requested timeline and its fingerprint are
deterministic; wall-clock application is not a hard real-time guarantee.

The runner cancels and joins the scheduler before evidence collection and
cleanup. Keep that lifecycle when extending timed behavior so no event can
reach a topology being dismantled. `internal/simulation/timeline_test.go` owns
the detailed ordering, cancellation, and shutdown contract.

### Expectations and reports

Expectations match netdoc's stable machine-readable contract: probe id,
`PASS`/`WARN`/`FAIL`/`SKIP`/`N/A` status, verdict, and optional structured cause
or address-family state. An optional expectation-level `summary` pins the exact
final user-facing diagnosis, and an optional check-level `fix` pins that row's
exact user-facing remedy. Omit either field when the scenario does not claim its
wording. A test may override the scenario-level expectation when several
network phases are exercised in one file.

Naming `ipv4` or `ipv6` on an expected check asserts that netdoc published that
family's verdict, so a run that omitted the family fails the expectation rather
than passing it by default. Leave the field out for families the scenario makes
no claim about: netdoc omits a family it never dialed, and the report keeps it
omitted rather than reporting an empty verdict.

Unknown YAML keys, probe ids, statuses, causes, node references, addresses, and
unsupported combinations fail validation before setup:

```sh
./netdoc-sim validate path/to/scenario.yaml
./netdoc-sim run path/to/scenario.yaml -dry-run
./netdoc-sim run path/to/scenario.yaml -json
```

Text and JSON reports carry comparison results, suggestions, cleanup state,
and evidence observed from services and the kernel. Use `-json` for automation;
the report types in `internal/simulation/report.go`, campaign/hunt report code,
and their tests are authoritative for fields and stable suggestion codes.
Empty evidence collections remain `[]`, and logical evidence never exposes
generated kernel device names.

## Adding or changing a scenario

1. Copy the closest YAML under `internal/simulation/scenarios/` and change only
   the topology, fault, test, and expectation needed for the behavior.
2. Validate the file by path. If it is built in, also rebuild and validate its
   filename stem through the embedded library.
3. Run the scenario with `-dry-run`, then normally on a supported Linux host.
   Use `-json` to inspect structured evidence rather than matching report prose.
4. Add or adjust the smallest unit test for new parsing, scheduling,
   comparison, or evidence logic. Add a focused `netns_integration` test when
   the behavior must be proved through real namespaces.
5. If diagnostic endpoints changed, update every affected alias/zone and run
   the `healthy` canary; see [Probe endpoint drift](simulation.md#probe-endpoint-drift).

Keep ordinary tests deterministic, rootless, and offline. Real-socket tests
retain the `integration` tag and loopback-only scope; real namespace tests
retain the `netns_integration` tag.
