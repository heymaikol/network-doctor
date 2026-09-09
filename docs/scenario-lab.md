# Deterministic Scenario Lab

The Scenario Lab checks bounded diagnostic properties against a small network model.
It runs offline, without sockets, DNS, interfaces, subprocesses, namespaces,
privileges, or a separately installed `netdoc`. It complements the existing
[Linux namespace simulator](simulation.md), which exercises actual network
mechanics and probe implementations.

```sh
go run ./cmd/netdoc-sim lab list
go run ./cmd/netdoc-sim lab describe mtu-blackhole
go run ./cmd/netdoc-sim lab run mtu-blackhole
go run ./cmd/netdoc-sim lab run vpn-dns-leak --trace
go run ./cmd/netdoc-sim lab run asymmetric-routing
go run ./cmd/netdoc-sim lab run --all
go run ./cmd/netdoc-sim lab run --all --json
```

`lab` is an additive command. The existing `list` command still lists retained
namespaces, and `run NAME` still runs a namespace scenario. Flags accept either
one or two leading hyphens, before or after the scenario name. `lab run -h`
uses the standard Go flag formatting.

Exit codes retain the simulator convention: 0 means semantic validation
passed, 1 means it failed, 2 means invalid arguments, and 3 means the model
could not run. The current 22-case corpus passes semantic validation, so
`lab run --all` exits 0. A test that successfully reproduces a known failure
does not make that scenario pass. The CLI prints every failure normally.

The JSON output is an experimental dump of internal lab types, with no new
published schema or compatibility promise. Embedded snapshots retain the
existing `.ndoc` schema. Their fixed `2000-01-01` timestamp and `model` platform
identify synthetic observations; they are not field captures. The lab does not
write anything to `testdata/field` or claim real-network provenance.

## Generated reasoning campaigns

The [diagnostic reasoning fuzzer](reasoning-fuzzer.md) builds deterministic
worlds, checks evidence-based properties, and minimizes reproducible failures.
Run `go run ./cmd/netdoc-sim lab fuzz --seed 847293 --cases 10000`.
It reuses this lab and does not change the authored corpus or infer expected
diagnoses from simulator truth.

## Architecture and boundaries

The repository already has these layers:

| Owner | Existing responsibility | Lab reuse |
| --- | --- | --- |
| `cmd/netdoc-sim` | Namespace, campaign, hunt, challenge dispatch | Additive `lab` command and text/JSON rendering |
| `internal/simulation` | Scenario validation, topology/services/faults, independent truth | Existing `Scenario`, `Topology`, `Node`, `Interface`, `Route`, `Service`, `Fault`, cloning and validation |
| `internal/diagnostic` | Probe graph, execution, reconciliation, diagnosis and confidence | `ProbePlan`, `RunAll`, `Finalize`, `Interpret`, `BuildSnapshot`, `ReplaySnapshot` |
| `internal/snapshot` | Portable typed observations and schema validation | Canonical encode/decode on every run |
| `internal/compare` | Snapshot/path differences and two-sided reading | Unmodified `Snapshots` and `TwoSidedSnapshots` |
| `internal/fieldcase` | Reviewed independent truth around stored evidence | Same separation principle; no schema changes or synthetic field entries |

```text
LabScenario: healthy topology + ordered LabFault mutations + LabView(s)
    |
    +--> private validated labNetwork
    |       longest-prefix routing, source/next-hop choice, return routing
    |       packet delivery/loss/size, DNS records, service behavior
    |           |
    |           +--> simulator-only exchange traces and full paths
    |           |
    |           +--> modeled probe observations
    |                   |
    |             production ProbePlan + RunAll
    |                   |
    |             production Finalize + Interpret + confidence
    |                   |
    |             BuildSnapshot -> encode/decode -> ReplaySnapshot
    |                   |
    |             optional production two-sided/path comparison
    |
    +--> independent expected properties -> semantic/provenance validator
```

`ProbePlan` returns the production graph's
IDs, labels, dependencies, and reference marks with all `Run` functions nil,
constructed without `defaultOps`. The lab supplies every probe body or rejects
the graph. A future probe cannot accidentally run a real network operation.
`ProbeResult.SetProtocolTimeout` also exposes the existing HTTP timeout fact,
so the model adapter can supply the same private bit as the live HTTP probe.
`SetFailureCause` supplies the cause and its observed address family together.
Both setters only assign existing fields; production probe bodies are unchanged.
No simulator state, fault switch, diagnosis rule, confidence rule, or threshold
was added to production networking code.

The lab substitutes **probe bodies**, not diagnoses. Its adapters translate
routed exchanges into `ProbeResult` observations. The real dependency executor
still skips failed prerequisites; the real reconciliation pass still compares
DNS, downgrades egress, and qualifies target-family evidence. The production
interpreter computes all findings, causal evidence, confidence, and prose.
Every run checks that the full diagnosis survives snapshot encode/decode and
replay, ignoring the snapshot's historical diagnosis.

This is a reasoning test boundary. It does not prove the actual DNS wire parser,
TLS implementation, Happy Eyeballs timing, socket queue accounting, kernel route
adapter, or timeout implementation. Existing native, integration, namespace,
and field replay tests cover those boundaries. In particular, model durations
are a fixed logical tick, not measurements suitable for latency conclusions.

## Authoring and semantics

Author scenarios through `LabScenario` in
[`lab_corpus.go`](../internal/simulation/lab_corpus.go). The lab deliberately
uses a strongly structured internal API instead of extending the frozen YAML
schema with an unproven second backend contract. The current lab supports a
validated subset of existing service and fault semantics; it does not claim
to execute every namespace YAML scenario.

A definition contains a fault-free `Network`, one or two `Views`, optional
logical tunnel segments, and ordered `Faults`. Views choose a node, target,
optional source segment, and optional configured proxy. Nodes can have several
interfaces and route alternatives. Resolver and proxy roles come from their
services; routers alone can forward transit traffic.

Each `LabFault` carries an independent ID, layer, scope and localization intent,
and exactly one mutation:

- an existing network `Fault` for drop, packet loss, link-down, default-route
  removal/replacement, or PMTU black hole;
- replacement of a named service, for DNS answer changes, missing names,
  certificate behavior, or HTTP interception;
- a resolver selection on a named node;
- a route replacement/addition on a named node;
- a named HTTP service that stops responding after connections are accepted.

The base and final state are separately validated. Fault application uses a
private deep copy, declaration order, and explicit mutation contents. Unknown
objects, invalid address families, off-link gateways, overlapping segments,
and unsupported models fail before execution. Scheduled DNS, netem delays or
jitter, clock offsets, TCP reset services, invalid reference certificates and
malformed wire responses are refused rather than
silently treated as healthy. Fault IDs and expectations never influence an
exchange outcome.

Network semantics are intentionally bounded:

- Routes select the longest matching prefix, then lowest metric, then first
  declaration. Connected routes win equal-prefix ties. A selected source
  segment constrains egress to that interface in this model. This is an
  explicit model of source-bound paths, not emulation of OS policy rules.
- Every exchange walks actual interfaces and next hops. A missing neighbor,
  non-forwarding transit node, or routing loop cannot deliver traffic. Replies
  take an independent route to the selected source address. No public-looking
  address is reachable unless an in-model node owns it.
- Service-port filters are checked on forward packets. Reply packets target a
  fixed synthetic ephemeral port. A local outbound TCP drop produces a local
  refusal; inbound/transit drops produce silence. This follows the existing
  simulator's distinction without depending on host errno values.
- Packet loss uses a deterministic hash of the seed, probe/source identity and logical packet key,
  not a shared random stream or goroutine arrival order. It models packet
  delivery, not realistic retransmission timing or measured loss rates.
- DNS answers come from the queried service's own ordered records. A missing
  name is NXDOMAIN, a missing/unreachable resolver cannot answer, and distinct
  resolvers can disagree. A valid AAAA-only answer on an IPv4-only client is
  distinct from an impossible A record carrying IPv6 bytes, which validation
  rejects. The lab rejects more than 16 addresses per name rather than
  approximating the native scheduler's attempt ceiling. No host resolver, hosts
  file or proxy environment is consulted.
- A globally addressed family with failed reference connections warns, matching
  the live egress probe. Unconfigured families are omitted by the model. The
  ordinary single-interface corpus uses explicit source binding; VPN views
  permit both modeled interfaces.
- TCP connects require a listening service and a working round trip. The
  adapter tries each family independently, stops at its first successful
  address, and uses IPv6 to break equal logical target latency ties. It records
  both families and individual attempt causes.
- HTTP responses, including 3xx and 5xx, are evidence of delivery. Both
  connectivity controls must be intercepted before the adapter records portal
  evidence. TLS certificate conditions are static intent with a trusted
  synthetic issuer; no wall clock, host trust store or real cryptography is
  involved. A TLS success and missing HTTP response remain separate facts.
- PMTU faults constrain one router's egress and suppress feedback. A small
  connection handshake passes while a full-sized payload cannot be
  acknowledged. The real diagnosis requires the bulk warning plus a protocol
  timeout; the injected MTU and failing router are never given to it. The lab
  does not emulate ICMP discovery, MSS adaptation, or a retransmission stack.

`LabReport.Truth` contains injected intent. `LabObservation.Trace` contains
simulator-only forward/return paths, packet size, outcome and matched network
fault indices. Service replacements and route mutations are inspectable in
the truth and normalized topology, even when a prerequisite masks them.
A configured fault is not evidence that the diagnostic observed it.

`Measured` holds raw probe measurements. `Snapshot` holds the reconciled
production evidence and diagnosis. For example, reference TCP may measure FAIL
but reconcile to WARN after another direct public destination works. The raw
IPv6 target failure can also be qualified away when that family fails for the
reference destinations. The original attempts remain visible.

## Semantic validation

Expectations use verdicts, required and allowed finding IDs, forbidden claims,
probe states/causes/family results, confidence bounds, and required typed causal
evidence. They do not compare diagnosis sentences or fixes. The allowed set
permits legitimate ambiguity without accepting arbitrary findings.

The validator also checks that findings have measured support on their focus row and that every
cited observation exists on its claimed row. It verifies counterfactual
evidence, addresses, routes, missing-observation reasons, and confidence bounds.
A skipped row cannot serve as a successful control. Unknown evidence kinds or
observations cannot silently pass. The negative tests tamper with diagnoses
while retaining the original observations. Counterfactual labels and outcomes
must agree with their cited measurements. Every built-in required finding has
independent observation anchors and confidence bounds. Healthy views require
measured successful control and application rows.

This is a bounded property oracle, not a general proof of every possible causal
claim. It does not parse summary prose or establish the logical validity of every
possible `ruled_out` candidate merely from the existence of its cited observation.
New cause families need independently reviewed expectations.

Known corpus failures are listed as exact validation problems in
`LabScenario.KnownIssues`. Corpus tests require precisely those failures and
no others, so a fix requires review of the now-stale entry. `RunLab` never reads
that list, and the CLI never suppresses its failures.

## Diagnostic findings corrected

The initial corpus exposed two production reasoning issues:

1. **Target-silence confidence.** Healthy DNS and reference egress do not
   distinguish filtering, target-specific routing, lost replies or server
   silence. `target_unreachable` now has `low` causal confidence, as does the
   equivalent local-device silence finding. Explicit refusal and measured
   family/address contrasts retain their stronger, narrower claims.
2. **Two-sided endpoint exclusion.** Matching a hostname does not establish
   that the two views contacted the same server. Both one-sided summaries now
   describe where failure was observed and leave endpoint-specific causes open.
   This also applies when failures are shared on some rows but differ on others.
   Even a common contacted address cannot exclude backend selection, endpoint
   policy or changes between captures.

The `unrelated-dns-failure` expectation changed from `unknown` to side `a`:
`side` identifies the observed failing vantage, not the location of the cause.
The original expectation conflated those claims. Side A's refusal is still
observable with disjoint DNS; endpoint exclusion is the unsupported conclusion.
Independent production tests cover DNS overlap, missing address evidence,
common contacted addresses, IP literals, both argument orders and shared rows.
No confidence bound was relaxed, and the obsolete known-issue entries were removed.

## Blind spots and useful additional evidence

| Indistinguishable conditions | Missing observable | Possible follow-up and value |
| --- | --- | --- |
| Resolver down vs a filter on the resolver path | Where the query was lost | Resolver-side receipt or a second vantage; useful for support, not established by another local timeout |
| DNS hijack vs intentional split DNS | Authenticity and intended answers | Trusted resolver/policy or DNSSEC validation; worthwhile only with a clear trust model |
| Intentional single stack vs broken unused IPv6 | Intended family availability | Configuration intent plus controlled family tests; do not weaken current single-stack tolerance |
| Silent target filter vs server black hole vs broken return path | Inbound receipt and return-hop evidence | Remote packet/connection observations; valuable for localization, ordinary route lookup is outbound only |
| Mandatory proxy vs merely available alternative | Administrative egress policy | Explicit policy input; avoid inferring intent from proxy success |
| Captive portal vs transparent HTTP filter | Authenticated interception identity | Browser/sign-in or policy information; current corroborated interception claim remains useful |
| Certificate misconfiguration vs TLS interceptor | Expected peer identity/trust baseline | Certificate comparison from an independent path; useful with consent and a defined identity baseline |
| PMTU black hole vs peer that stops accepting data | Delivery/ACK location and effective path MTU | Controlled MSS/MTU experiment or cooperating peer; worth exploring, no exact-hop claim today |
| VPN DNS leak vs healthy split DNS | Intended DNS privacy/routing policy | Configured policy plus resolver route; paths already exist but policy is absent |
| Different servers behind one name vs one shared endpoint | Common tested address | Compare existing selected/attempted addresses, then optionally pin a common address; high value with no initial new probe |

Healthy VPN and DNS-leak cases intentionally remain `ok`: route differences
are observable, but policy violations are not inferred from them. The lab
retains those cases as explicit blind-spot controls rather than inventing a
new diagnosis vocabulary.

## Tests

```sh
go test ./internal/simulation -run '^TestLab' -count=1
go test ./internal/diagnostic -run '^TestProbePlan' -count=1
go test ./cmd/netdoc-sim -run '^TestLab' -count=1
go test -race ./internal/simulation ./cmd/netdoc-sim -run '^TestLab' -count=1
```

Tests cover every built-in scenario, canonical replay, independent concurrent
runs, an identical-evidence DNS leak/split-DNS control, cancellation, structure validation, address/family constraints, source and
route preference, return paths, the MTU boundary, deterministic packet loss,
immutable fault composition, prerequisite masking and unsupported claims. Ten
pairwise combinations of five independent faults check evidence provenance and
expected cause families. They are a bounded sample, not a Cartesian product. Their verdicts and required findings are declared independently
from prerequisite masking; the test does not copy the actual verdict into its oracle.

Offline guards pin the lab's permitted imports and diagnostic calls, reject
live simulator entrypoints and wall-clock calls, assert nil probe bodies in the
plan, and run the CLI with namespace seams stubbed and hostile proxy environment
variables. On Linux/amd64, `TestLabKernelIsolation` also runs the entire corpus
under a process-wide seccomp filter that kills sockets, file opens and process
execution. Negative socket/file controls verify the filter, and the protected
run must emit byte-identical JSON. The child starts with fixed `GOMAXPROCS` and
`MALLOC_ARENA_MAX` so Go CPU polling and glibc's lazy allocator sizing do not
open CPU topology files after filtering; these are unrelated to network evidence.
Native-probe conformance tests cover healthy, failed-family, DNS timeout and
portal observation classification. Real-socket tests remain in their existing
integration lanes.

## Corpus results

All 22 scenarios execute, replay and satisfy their semantic expectations.
These are model results,
not measurements from a real broken network.

| Scenario | Injected fault or configuration | Expected semantics | Observed result | Validation |
| --- | --- | --- | --- | --- |
| `healthy-ipv4` | Healthy topology | ok | ok | PASS |
| `healthy-dual-stack` | Healthy topology | ok; both families reachable | ok; both families reachable | PASS |
| `dns-resolver-unreachable` | resolver-drop | dns: system_dns_failure | dns: system_dns_failure | PASS |
| `dns-hijack` | rewrite-answer | degraded: dns_disagreement; confidence <= medium | degraded: dns_disagreement | PASS |
| `ipv6-unavailable` | drop-ipv6 | degraded: direct_egress_degraded; configured IPv6 failure observed | degraded: direct_egress_degraded | PASS |
| `reference-egress-unreachable` | reference-drop | degraded: reference_egress_unreachable | degraded: reference_egress_unreachable | PASS |
| `tcp-port-blocked` | target-port-drop | service: target_unreachable; confidence <= low | service: target_unreachable; confidence low | PASS |
| `proxy-required` | client-direct-policy | network: proxy_only_network | network: proxy_only_network | PASS |
| `captive-portal` | portal-interception | network: captive_portal | network: captive_portal | PASS |
| `tls-certificate-mismatch` | wrong-certificate | service: tls_hostname_mismatch | service: tls_hostname_mismatch | PASS |
| `mtu-blackhole` | narrow-silent-hop | network: probable_path_mtu_problem; confidence <= medium | network: probable_path_mtu_problem | PASS |
| `vpn-split-tunnel` | Intentional specific route over VPN | ok | ok | PASS |
| `vpn-dns-leak` | dns-outside-tunnel | ok | ok | PASS |
| `asymmetric-routing` | wrong-return-gateway | client target_unreachable; confidence <= low<br>remote ok<br>side a | client target_unreachable; confidence low<br>remote ok<br>side a | PASS |
| `remote-side-broken` | remote-target-drop | client ok<br>remote service: tcp_connection_refused<br>side b | client ok<br>remote service: tcp_connection_refused<br>side b | PASS |
| `unrelated-dns-answers` | split-dns-answer | client degraded: dns_disagreement<br>remote ok<br>side none | client degraded: dns_disagreement<br>remote ok<br>side none | PASS |
| `unrelated-dns-failure` | split-dns-answer, decoy-listener-moved | client service: tcp_connection_refused, dns_disagreement<br>remote ok<br>side a; endpoint cause open | client service: tcp_connection_refused, dns_disagreement<br>remote ok<br>side a; endpoint cause open | PASS |
| `dns-nxdomain` | missing-name-system-dns, missing-name-public-dns | dns: dns_name_not_found | dns: dns_name_not_found | PASS |
| `connection-refused` | No listener on requested port 8443 | service: tcp_connection_refused | service: tcp_connection_refused | PASS |
| `lan-target-dead-uplink` | uplink-down | degraded: direct_egress_blocked; egress row FAIL, not relaxed; confidence <= medium | degraded: direct_egress_blocked; egress row FAIL | PASS |
| `shared-space-target-dead-uplink` | uplink-down | degraded: direct_egress_blocked; not reference_egress_unreachable; egress row FAIL | degraded: direct_egress_blocked; egress row FAIL | PASS |
| `tls-http-no-response` | silent-application | service: https_no_response | service: https_no_response | PASS |

## Adversarial audit notes

The audit reproduced and corrected lost global-family egress warnings, DNS
case/root-dot lookup errors, stale default-route replacement metadata, invented
portal evidence from a silent HTTP service, and encrypted DNS success based
only on an open listener. It also corrected the portal redirect identity and
main-table representation. The unrelated-DNS failure now declares the moved
listener as a separate mutation instead of hiding it in the base topology.
Loss sampling now includes probe/source identity so distinct operations do not
share an entire loss sequence just because their packet sizes match.
Completed reports now own their truth and expectations: later edits to an
authored scenario cannot rewrite a report or invalidate its trace indices.

The validator previously accepted a TLS finding supported only by healthy DNS
and an inverted DNS counterfactual outcome. Focus-row support, independent
anchors, counterfactual validation, primary-finding consistency, confidence
vocabulary and measured-status checks now reject those counterexamples.

Fault order is part of the model. Independent, disjoint mutations commute;
all ten tested pairs must preserve raw and reconciled observations when reversed.
Competing service/resolver/route replacements are last-writer-wins. Packet
impairments are checked in declaration order and the first terminal impairment
wins, like an ordered filter chain. Overlapping impairments can therefore change
the reported local refusal versus silence; both injected intents remain in truth.
Raw matched-fault indices refer to that order and are not compared across a
reversal. No order-independent claim is made for conflicting replacements.

The native `TestTargetSilenceConfidence` and
`TestEndpointAlternativesSurviveTwoSidedPlacement` tests pin the corrected
production behavior without importing Scenario Lab. The original characterization
tests reproduced both defects before the production fixes.

The observation boundary remains intentionally limited: it does not execute
all live protocol bodies. Native conformance tests are a bounded cross-check,
not equivalence proof for the complete probe implementation. Route observations
carry source/interface/next-hop state but omit route-reason and competing-route
explanation. Interface MTU is fixed at 1500, full-sized forward flights are
synthetic 1500-byte packets, and replies model small acknowledgments rather than
server-side bulk traffic. These assumptions cannot validate native MSS behavior,
reverse-direction bulk MTU faults or OS-specific source-selection policy.
