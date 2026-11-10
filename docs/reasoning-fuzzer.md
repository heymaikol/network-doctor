# Diagnostic reasoning fuzzer

Scenario Lab can construct deterministic network worlds, run the production
reasoning pipeline, check semantic properties, and reduce counterexamples.
This is an offline semantic campaign, not Go byte fuzzing and not a namespace
campaign. It does not predict the diagnosis that a random topology should get.

```sh
go run ./cmd/netdoc-sim lab fuzz --seed 847293 --cases 10000
go run ./cmd/netdoc-sim lab fuzz --seed 847293 --case 4187
go run ./cmd/netdoc-sim lab fuzz --seed 847293 --cases 10000 --workers 4 --json > campaign.json
go run ./cmd/netdoc-sim lab fuzz --property counterfactual-indistinguishability --cases 10000
go run ./cmd/netdoc-sim lab fuzz -h
```

`--case` selects one zero-based case directly, without generating its predecessors.
`--max-faults` defaults to 4, accepts 0 through 12, and bounds composition.
`--two-sided=true` permits random two-vantage worlds; false generates only
single-vantage worlds. Paired counterfactual worlds each use one vantage.
`--stop-on-first` stops at the lowest failing case. `--property` selects one
stable property name from the table below. Standard Go flag help lists defaults.
Flags precede positional arguments. Replay is a separate subcommand:

```sh
# Extract one concrete minimized counterexample, without changing any corpus.
jq '.Failures[0]' campaign.json > failure.json
go run ./cmd/netdoc-sim lab fuzz replay failure.json
```

Replay validates the artifact, reruns its minimized worlds, checks the stored
property and violation code, and prints fresh production snapshots containing
observations and diagnoses. Stored failure descriptions are not trusted results.
Exit 1 means a violation was found or reproduced; 0 means none was found or the
stored violation no longer reproduces. Invalid arguments/artifacts exit 2;
execution errors exit 3. Execution errors include a case number in campaigns.
A model execution or snapshot encoding error stops the campaign rather than
being misclassified as a reasoning violation.

## Execution boundary

`GenerateLabFuzz` builds `LabScenario` values from the existing `labBase`,
`labAddVPN`, server, service and fault primitives. `EvaluateLabFuzz` calls
`RunLab`, which supplies modeled probe bodies to production `ProbePlan` and
`RunAll`. Production reconciliation, `Interpret`, confidence, snapshot
encoding/decoding, `ReplaySnapshot`, path comparison and two-sided comparison
remain in charge of their existing behavior.

Generated worlds carry placeholder authored expectations solely to satisfy the
existing LabScenario authoring API. Their verdict and finding mismatch messages
are not fuzz failures. `ValidateLabEvidence` reuses the existing generic
provenance checks without an authored expected verdict, finding allowlist or
confidence table. The authored corpus still uses `ValidateLabDiagnosis` with
all its original expectations.

Neither generation nor the property framework imports a diagnosis decision
table. Fault placement and service configuration determine packet outcomes;
they do not select expected findings. The only named diagnostic claims read by
the counterfactual confidence check are the two existing claims that mean
unlocalized target silence. It never requires either claim to be produced.

## Generator and reproducibility

The experimental identifier is `reasoning-v1`. Its PRNG is explicit SplitMix64:
unsigned 64-bit wraparound, increment `0x9e3779b97f4a7c15`, xor shifts 30, 27,
and 31, and multipliers `0xbf58476d1ce4e5b9` and `0x94d049bb133111eb`.
The initial per-case state is `seed XOR (case * 0xd1342543de82ef95)`, modulo
2^64. Bounded draws use unsigned remainder; selection uses Fisher-Yates over
a declaration-ordered pool. No Go random library contract is involved.
A PRNG vector and a SHA-256 vector for one complete generated case pin this
implementation. Deliberate construction changes need a version review.

Reproduction requires the version, seed, case number, max-faults and two-sided
option. Text failures print all those options. A stored artifact contains the
original and minimized concrete worlds, so replay does not call the generator.
This is an internal experimental JSON format, not a permanent public schema.
Unknown versions are refused. Future generator versions should retain the old
artifact validator/model support when feasible, or explicitly migrate artifacts;
concrete worlds do not promise to freeze future simulator semantics.

Construction varies:

- IPv4, dual stack, and IPv6-only IP-literal targets. IPv6-only worlds omit
  IPv4 interfaces/routes and extra IPv4-only endpoints; they do not pretend the
  lab's fixed IPv4 public DNS resolver works over IPv6.
- One to three target endpoints, independently selected nonempty DNS answer
  subsets, optional AAAA answers, common/overlapping/disjoint answers, and
  ordinary or VPN-like source paths. Reference-service records remain modeled.
- Resolver timeouts or NXDOMAIN; independent reference failures; target silence,
  refusal through a moved listener, family failure, and return-path failure.
- Valid, mismatched or expired target certificates; accepted connections with
  no HTTP response; interception of reference HTTP controls; size-dependent
  loss at a gateway; deterministic packet loss; link-down and missing defaults.
- One or two vantage points, with independent or shared failures and masking
  through the actual production prerequisite graph.

Faults are chosen without replacement from valid mutations. Their order is
intentional. The base and the composed world are validated before execution.
A dedicated paired stratum replaces the fault set with target TCP/443 filtering
in one world and filtering for that same address/port at the gateway in the
other. Other topology, service and answer-set variation remains. Not every
pair is indistinguishable: VPN paths may avoid the gateway, DNS may select
another address, or prerequisites may mask the fault. Those pairs are inapplicable,
not failures.

Generation and reduction are bounded. Artifacts are limited to 4 MiB, two worlds,
24 nodes, 100 routes and 12 faults per world, with per-node/service limits.
Existing model validation checks names, address families, service references,
routes, gateways and supported mutations. No generated or replayed world uses
host sockets, DNS, routing, environment variables, subprocesses or wall time.
The existing logical duration and synthetic snapshot timestamp remain fixed.
The CLI measures elapsed time only for throughput, outside the semantic report.

## Properties and independent oracles

A `LabFuzzProperty` has a stable name, applicability predicate and evaluator.
Evaluators return a semantic violation code and human-readable evidence.
The same applicability predicate and code are used during reduction.

| Property | Applicability and guarantee | Independent basis |
| --- | --- | --- |
| `determinism` | Every valid case. Repeat each world and require the complete report to match, including raw observations, reconciled snapshots, findings/confidence, traces and comparisons. | Equality under identical inputs; no predicted diagnosis. |
| `replay-equivalence` | Every valid case. RunLab compares native interpretation with canonical snapshot replay; additionally poison the historical diagnosis and require replay to remain identical. | Existing production replay contract; historical diagnosis is not input evidence. |
| `unsupported-claim-safety` | Every valid case. Findings must cite existing, measured facts, have support on their focus row, use valid confidence vocabulary, and provide supported counterfactual outcomes. A finding about a failed target or QUIC row whose every attempt was in an address family the egress row could not reach may cite the egress row only for what it measured in each family, unless an attempt on the row was refused. | Generic evidence provenance, using the existing validator with authored expectations disabled. |
| `ground-truth-isolation` | Every valid case. Rename scenario/faults and change descriptions, layers, scopes, localization labels, blind-spot annotations and expectation metadata; production inputs and interpretation must remain equal. | These fields describe simulator truth or expectations, not measurements. |
| `unobservable-perturbation` | Generated worlds. Add a disconnected, nonforwarding node with an unrelated HTTP service on its own segment. Inputs must be unchanged; only after establishing equality compare interpretation. | The new component has no connection to an observed path. An input change is a model/boundary violation, distinct from an equal-input interpretation violation. |
| `two-sided-symmetry` | Two-vantage cases. Swap arguments and compare exchanged vantage metadata/status rows, placement, finding identity, ambiguity, evidence sets, alternatives and caveats. | Exchanging the names of observations cannot change their logical relationship. |
| `fault-commutativity` | At least two service replacements, all naming different services, and no other mutations. Reverse order and require equal raw and reconciled inputs. | Replacements write disjoint service objects. Ordered packet impairments and competing replacements are deliberately excluded. |
| `observational-equivalence` | Valid paired worlds with equal raw/reconciled checks, target and options, and an actually observed target timeout affected by the distinguishing fault in each world. Interpretation must match. | Distinct simulator causes with identical complete production inputs. |
| `counterfactual-indistinguishability` | The same witnessed, evidence-equal pairs. If a finding means unlocalized target silence, it cannot have medium/high causal confidence. | Endpoint policy and transit filtering remain equally compatible with the evidence. This checks the documented meaning of causal confidence for silence, not a second confidence engine. |

Symmetry ignores summary prose and ordering of evidence/candidate sets. The
comparison API represents alternatives and caveats as sentences, so their
existing controlled vocabulary is compared after swapping `side A`/`side B`
tokens and sorting. A wording-only change can require review of this projection;
this is not a general natural-language equivalence checker. Violation codes
separate changed placement, evidence, rows, alternatives, caveats and metadata.

Confidence sanity and counterfactual indistinguishability are one evaluation,
not two inflated counts of the same assertion. A measured refusal, failed
certificate identity, or family/address contrast may retain high confidence
because those narrower observations hold in both worlds. The property does
not flag high confidence merely because two physical causes exist somewhere
in the model. It currently investigates one cause relation, endpoint versus
transit filtering, rather than claiming coverage of every cause family.

Explicit evidence monotonicity was considered but no general ordering is
asserted. Adding an address, resolver result or successful control can alter
prerequisites, reconciliation, the primary finding and what a localization
means. Those changes are not simple evidence supersets. Duplicate evidence
would also not establish a new causal distinction. A future monotonicity
property needs a separately justified relation that preserves the claim and
adds a genuine discriminating observation. Arbitrary increasing-confidence
or increasing-localization assertions would introduce a false oracle.

The provenance validator does not prove every named `ruled_out` candidate is
logically excluded merely because its cited measurement exists. The fuzzer
also does not parse summaries for every possible unsupported endpoint, route,
resolver, local or remote exclusion. The evidence-equal silence pair and the
existing endpoint-alternative production regression tests cover narrower,
reviewable claims. These are explicit limits, not an all-claims safety proof.

## Deterministic reduction and failure identity

The reducer tries fault chunks, individual faults, views, routes, nodes,
interfaces, aliases, services, DNS records, segments and tunnel markers.
It also attempts coordinated family removal, route metric canonicalization,
MTU canonicalization to 1280, and DNS answer removal within service mutations.
Edits are tried in a fixed order; accepted edits restart the pass. Completion
means no listed edit preserves the violation, not a proof of global minimality.

Every accepted edit must compile as a valid model, leave the property applicable,
and reproduce its original property/code. Paired reductions apply the same base
edit to both worlds. Validation preserves the one distinguishing fault at the
target versus gateway; applicability requires evidence equality and an actual
matched target timeout in each. Removing the differing cause cannot turn a
paired failure into a generic single-world failure.

The reducer does not fabricate or delete individual recorded probe rows. The
production graph determines observations from each reduced world. It also does
not perform arbitrary IP renaming or repair a rejected topology to force an edit
through. Validation rejection simply moves to the next candidate.

Tests include a deliberately synthetic reducer predicate requiring one named
service. It shrinks 6 nodes and 8 routes to 2 nodes and no routes, with 14 accepted
edits. This is a runnable reducer test, not a real reasoning discovery and not a
regression artifact. Another test reduces paired worlds while preserving the
independent fault locations and observed equality relation.

Failure identity is property name, semantic violation code, and necessary world
relation. Provenance codes retain the affected finding/check/observation;
symmetry codes retain the changed semantic field. The coordinator retains the
earliest case for each identity and minimizes that representative. It counts
all violating evaluations and failing cases, plus distinct original world/identity
combinations using SHA-256, without retaining all large reports. It does not pin
diagnostic summary wording or claim that every physical root cause with the
same semantic violation deserves a separate bug.

## Concurrency and performance

Workers execute bounded batches of independent case numbers. A coordinator reads
results in case order, chooses failures and performs minimization. The first
failure and retained representatives cannot depend on scheduling. Stop-on-first
counts only the prefix through that failure, even if later workers in its batch
already finished. Ordinary runs retain summaries and minimized representatives,
not every successful report. There is no immutable-state cache beyond existing
model construction: measured throughput was sufficient for a 100,000-case run.

Reported throughput includes generation, all applicable evaluations and any
minimization. `Seconds` and `CasesPerSecond` in CLI JSON are intentionally not
deterministic. `LabFuzzSummary`, case construction, selection, counters and
artifacts are deterministic. Compare summaries without those two timing fields.

## Retaining a discovery

No fuzz command writes into the repository or promotes a scenario automatically.
Save the extracted artifact and reproduce it before changing production code.
For each candidate, inspect the fresh snapshots and both simulator worlds, try
to falsify the property's assumptions, then classify it as simulator, property,
production diagnostic, comparison, calibration, or unclear.

For a verified discovery, add its minimized concrete artifact under a reviewed
`testdata/lab-fuzz` directory together with a characterization test calling
`DecodeLabFuzzArtifact` and `ReplayLabFuzzArtifact`. Record the independent
witness, classification and exact violation. Create that corpus only when there
is a real discovery. A characterization may deliberately expect reproduction
of an unfixed defect, but the CLI must continue to report it as a failure.
Alternatively translate `Minimized.Worlds` into a `LabScenario` in `lab_corpus.go`
and independently author its semantic expectations. Do not copy the production
verdict into an expected verdict to make it pass. Synthetic snapshots must not
be represented as real field captures in `testdata/field`.

After a separately reviewed production fix, change the characterization to
require that the violation no longer reproduces and retain the evidence. There
is no automatic promotion subcommand because promotion needs that independent
judgment, not just JSON conversion.

## Validation and limitations

Tests cover PRNG/generator vectors, seed variation, validity and bounds,
independent ownership, applicability, negative claim detection, paired witnesses,
reducer fixed points, deterministic parallel selection and deduplication,
artifact replay/strict rejection, cancellation and CLI behavior. The import guard
covers all new `lab*.go` files. Linux/amd64 seccomp tests execute both the authored
corpus and a generated campaign with socket, file-open and process syscalls
forbidden, and compare complete serialized semantic reports. Race testing runs
the same core paths. Loopback integration tests remain in the integration lane.

The existing [Scenario Lab model limitations](scenario-lab.md) still apply:
this does not prove native protocol bodies, OS source selection, real TLS clocks,
retransmission timing, actual PMTU behavior, or unmodeled policy. IPv6-only runs
use IP literals, which can intentionally fail certificate identity checks; they
are not a promise of healthy DNS-based IPv6-only browsing. Fault composition
and paired observation equality expose modeled reasoning combinations, not a
statistical distribution of real incidents.

See the [recorded campaign and validation results](reasoning-fuzzer-campaign.md).
