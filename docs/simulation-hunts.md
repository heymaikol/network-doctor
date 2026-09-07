# Hunts and triage reference

Authoritative reference for reproducible fault campaigns, generated bug
hunts, and nightly triage automation. See
[docs/simulation.md](simulation.md) for setup and the guide index, and the
wiki's [Hunts and Triage](https://github.com/heymaikol/network-doctor/wiki/Hunts-and-Triage)
guide for an orientation to what these are for.

## Deterministic campaigns and reproduction

A campaign resolves bounded ranges in a scenario and runs each iteration
sequentially through a fresh ordinary simulation lifecycle. If `--seed` is
omitted, the CLI chooses and prints one. Each iteration seed is derived
independently from the root seed, scenario name, and iteration number; it does
not depend on earlier PRNG state. Compilation fixes the complete fault schedule
before setup, and reports store the seed, schedule, and digest.

```sh
./netdoc-sim campaign unstable-connectivity --runs 6 --seed 12345
./netdoc-sim campaign unstable-connectivity --seed 12345 --iteration 3
./netdoc-sim campaign unstable-connectivity --seed 12345 --iteration 3 --runs 5
./netdoc-sim campaign flapping-connectivity --runs 6 --seed 12345
./netdoc-sim campaign dns-timeout-boundary --runs 6 --seed 12345 -timeout 1s
```

The same scenario, seed, iteration, and simulator version reproduce the same
injected schedule. `--iteration N --runs K` repeats that one schedule, which is
the meaningful way to look for diagnosis divergence. A timed transition can
still land on a probe boundary differently; in that case the deterministic
artifact is the requested schedule and timeline fingerprint, not a promise
that OS scheduling or netdoc's answer is identical.

Campaign scenario definitions document the variables they exercise. In
particular, `dns-timeout-boundary` draws its delay only during campaign
compilation, so `netdoc-sim run dns-timeout-boundary` is not the boundary test.
Use the campaign command and pin the printed seed and iteration to reproduce a
failure.

## Deterministic bug hunts

`netdoc-sim hunt` mutates a known-good control scenario. Case N is derived from
the hunt seed, base scenario, case number, fault ceiling, generator version,
and lane, so an exact reproduction names all six without first running cases 0
through N-1. The accepted bases and mutation registry live in
`internal/simulation/hunt_generate.go`.

```sh
./netdoc-sim hunt healthy --lane bug-oracle --seed 20260101 --cases 20
./netdoc-sim hunt healthy --lane stress --seed 20260101 --cases 20
./netdoc-sim hunt healthy --lane all --seed 20260101 --case 4 --max-faults 2 --generator-version v3 --json
./netdoc-sim hunt healthy --lane all --seed 20260101 --case 4 --max-faults 2 --generator-version v3 --dry-run --json
```

The current generator has two explicit lanes. `bug-oracle` is the default and
contains only operators whose expected diagnosis is checked against independent
simulator evidence. `stress` contains useful robustness, unusual topology,
interaction, parser, and execution mutations that currently lack a direct
diagnosis-defect oracle. Stress cases can still expose bugs; the distinction is
whether Hunt can automatically decide that Network Doctor's diagnosis is wrong.

`--cases N` means the first N accepted case identities in the global candidate
sequence. Generators v6 and v7 include the lane and case coordinate in that identity,
so a lane with only a few parameterless mutation combinations can still use the
requested execution budget. Generators v3 through v5 retain semantic duplicate
suppression exactly as published, and their accepted case numbers can have
gaps. `--shard i/N` is a zero-based filter over the accepted global cases: case
C belongs to shard i when `C % N == i`. Every shard walks the same cheap
deterministic candidate sequence and only creates namespaces for its own cases.
It does not draw a new stream or renumber cases.

`--case` and `--shard` are mutually exclusive. Exact reproduction remains the
unsharded command printed in findings, including `--case`, `--seed`,
`--max-faults`, `--generator-version`, and `--lane`, so a case number and
fingerprint mean the same thing before and after sharding. `--fail-fast` stops
only the current shard; independent processes do not cancel or coordinate one
another.

Run and merge all four shards locally like this:

```sh
for shard in 0 1 2 3; do
  ./netdoc-sim hunt healthy --seed 20260101 --cases 60 \
    --lane bug-oracle --shard "$shard/4" --max-faults 3 --generator-version v7 --json > "shard-$shard.json"
done
./netdoc-sim hunt merge shard-3.json shard-1.json shard-0.json shard-2.json > hunt.json
```

`hunt merge` accepts shard files in any order and writes the ordinary canonical
hunt JSON shape in global case order. It rejects duplicate or missing shards,
duplicate or missing global cases, and incompatible base, seed, generator,
lane, case-count, fault-ceiling, shard-count, dry-run, or fail-fast settings. It
regenerates the expected manifests, so file names are never treated as
metadata. An empty shard is valid when no accepted global case belongs to it.

Shard reports record top-level `generator_version`, `lane`, `max_faults`,
optional `fail_fast` and `dry_run`, and `shard` with `index` and `count`.
`requested_cases` remains the logical global case total while generated and
executed counters describe that shard. A merged report omits `shard` because it
represents the logical hunt, not one execution partition.

`--max-faults` belongs in a reproduction command rather than being left to the
flag default. It is one of the inputs the case is drawn from: the first number
taken from the case seed is how many mutations to apply, bounded by the ceiling,
so the same base, seed and case under a different ceiling is a different
network. The manifest records it, every finding's reproduction carries it, and
the command a filed issue prints names it.

`--generator-version` selects one retained generator from the registry. It
defaults to `HuntGeneratorVersion` for a new hunt, but every printed single-case
reproduction names the resolved version. A saved artifact is replayed with its
recorded version and never with the replaying binary's default.

Every current case report includes generator version, lane, root and case seeds,
the fault ceiling, materialized mutations, and a case fingerprint. Findings use
semantic diagnosis fingerprints, excluding prose and incidental timing, paths,
process ids, and kernel names. Keep the lane, seed, case, fault ceiling,
generator version, and reproduction command with any failure report.

Artifacts from generators v3 through v5 predate lane metadata. A missing lane
on those artifacts is deliberately interpreted as their original `all`
operator universe, and reproduction commands print `--lane all`. Generator v6 and v7
artifacts must record `bug-oracle` or `stress`; a missing lane is rejected rather
than inheriting the current default.

### A hunt makes no reproducibility claim

Each case runs netdoc exactly once, and the hunt therefore never reports a
diagnosis as unstable. Neither comparison available to it is between two runs
of the same experiment:

- Two runs inside one live topology are not independent. The second inherits
  the neighbour, route and resolver caches the first warmed, so a verdict that
  changed between them says the first probe paid for a cold path, not that
  netdoc drifted. `two-path-ipv6-healthy` documents exactly this: its first
  test exists to warm both forwarding paths, and a repeated run of it reports
  `ok` where the cold one reported `degraded`.
- Two different cases are two different networks. The observed-truth vocabulary
  deliberately records that a path was impaired without recording by how much,
  so a 79 ms path and a 730 ms one share a truth fingerprint while netdoc
  correctly describes them differently. An accusation built on that equivalence
  is a false positive, and because it needs sibling cases to exist at all, no
  single-case replay could ever reproduce it.

Determinism is campaign mode's question. `--iteration N --runs K` repeats one
fixed schedule through a whole fresh topology per run, which is the comparison
this one cannot make, and it already reports divergence as `nondeterministic`.

### Route findings need routing evidence

`alternate_route_available` and `wrong_default_route_evidence` are coverage-gap
findings about a path the diagnosis did not describe. They are not direct
diagnosis-defect contracts, so their operators remain in the stress lane. Both
findings are gated twice.
A warning on the egress row is not a routing fact, so the client's own dial has
to have found an address family with nothing answering; latency, a cold first
packet, or one address of several failing all raise that row while the path is
fine, and on a two-test scenario the control keeps passing regardless. And a
diagnosis that already named a route cause has told the user which route failed,
so what is left is a wish about how much route detail to print, not a gap in
what was communicated.

A generated mutation records intent; it is not automatically observed truth.
`observed_faults` contains a mutation only when service, event, kernel-fault, or
independent reachability evidence from the executed simulation supports it.
Persistent netem mutations require matching kernel qdisc state on the intended
logical node and segment. A path-MTU black hole requires both halves of the
size asymmetry read back off the kernel: the forwarding hop really carrying the
narrowed MTU, and the client still carrying more. A path that narrowed
everywhere carries small packets by agreement, and a hop that was never
narrowed carries everything, so neither half alone is the fault. Timed DNS,
netem, and link mutations require the specific impairment event to have applied
successfully; initialization, restoration, failed, and skipped events do not
qualify. These timed entries
prove successful simulator state changes, not that netdoc sampled the affected
window or observed an end-to-end consequence.

### Bug-oracle and stress operators

The mutation registry carries one `findingContract` decision per operator and
derives lane membership from it. An operator qualifies for `bug-oracle` only
when the mutation establishes a scoped network truth, independent simulator
evidence records that truth, the expected diagnostic meaning is defined, and
an analyzer comparison can emit a concrete diagnosis finding when the report
disagrees. A crash, timeout, setup failure, generic invariant, or Challenge Mode
answer does not satisfy that diagnosis contract.

The current bug-oracle operators are:

- `dns.servfail`, `dns.drop`, and `timeline.dns_outage`
- `service.tcp_reset`, `service.tls_expired`, and
  `service.tls_hostname_mismatch`
- `proxy.connect_refused` and `quic.udp_443_block`
- `family.ipv4_drop`, `family.ipv6_drop`,
  `routing.no_default_route`, and `routing.preferred_path_failure`

The current stress operators are:

- `netem.loss`, `netem.latency`, `netem.jitter`, and
  `timeline.netem_spike`
- `encrypted_dns.doh_invalid`, `http.status_503`, and
  `link.transient_down`
- `routing.wrong_default_route` and `routing.missing_subnet_route`
- `service.connection_refused`, `service.tcp_port_blocked`, and
  `pmtu.blackhole`

The registry test checks that every operator makes an explicit decision, every
bug-oracle contract maps to analyzer code, and both exact lane memberships stay
intentional. Adding a safe diagnosis oracle for a stress operator is separate
work from this classification.

### What a hunt false negative means

A hunt false negative means the simulator independently established a network
condition whose diagnostic meaning Network Doctor failed to recognize. It does
not mean a mutation expected probe X to fail and probe X did not fail.

The oracle in `internal/simulation/hunt_oracle.go` is that contract in code. It
runs on a vocabulary of `NetworkCondition` values, domain facts such as IPv4
internet reachability lost, a target serving an expired TLS certificate, a proxy
refusing its CONNECT destination, QUIC datagrams dropped on UDP/443, a client
left with no default route for a family it can no longer reach, and it keeps
two halves apart:

- **observed**: reads simulator evidence and derived simulator truth only, never
  `report.tests`. A mutation that was generated or applied establishes nothing;
  only the certificate a client actually refused, the CONNECT a proxy actually
  declined, the kernel counter that actually matched a packet, or the client's
  own dial of a controlled endpoint does.
- **recognized**: reads one diagnosis only, never simulator evidence.

Recognition is expressed over netdoc's cause vocabulary and its structured
`address_families` verdicts, not over probe ids, so a probe that is renamed,
split, or merged without changing what the user is told leaves the oracle
correct. One exception is annotated in the table: `timeout` is not unique in
netdoc's cause vocabulary, so the QUIC entry scopes it to the QUIC row.

Recognition is deliberately specific. An expired certificate reported as a
generic handshake failure, a refused destination reported as an unreachable
proxy, a deleted default route reported only as an unreachable internet, and any
unrelated failing row are all misses, because each sends the user somewhere
else. A cause on a passing row is context, not recognition.

Reconciliation runs on the final client diagnosis and only on stable paths.
Unknown or unavailable families, persistent netem, and actual timed path
impairments are not treated as a final-state diagnosis oracle. The opposite
direction, where the simulator reached a family the diagnosis calls unreachable, is
reported as `family_reachability_mismatch` with category
`diagnostic_contradiction` rather than as a false negative.

Two stress operators deliberately imply no failure condition because netdoc
reports no failure for either by design and the `http-error` control pins that
down: an HTTP error status is a working service answering, and an invalid DoH
response while DoT still resolves is encrypted DNS working. Other stress
operators establish useful topology or execution facts but do not yet have an
unambiguous analyzer comparison from those facts to an expected diagnosis.

`pmtu.blackhole` narrows the forwarding hop the client's own route to the
briefed endpoint leads to, and only that hop: the path-MTU probe writes to that
endpoint, so a narrowed interface anywhere else leaves the write untouched. It
needs a router with exactly one interface off the client's link, so which way
that router forwards is read rather than guessed, and that interface must carry
no IPv6, because `minIPv6MTU` is the floor IPv6 requires of a link and a hop
that cannot be narrowed below it black-holes no IPv6 sender.

`routing.preferred_path_failure` uses `two-path-healthy` and
`two-path-ipv6-healthy`. It lowers the preferred router's upstream interface,
beyond the client-visible gateway, so the lower-metric client route remains
selected. Observation requires the selected preferred family path to be
unreachable and the controlled target on the distinct higher-metric alternate
path to remain reachable; successful link-down application alone is
insufficient.

From v7 it is oracle-backed, and its condition wants the same three halves the
per-mutation observation does, read without the manifest: two defaults with a
strict preference between them in the client's own kernel table, that family
unreachable from the client's own dial, and a controlled target answering over
one of the other defaults. The third clause is what separates the condition
from a network that is simply down, since two dead paths would otherwise wear
the name of one. Neither `preferred_route_failed` nor `selected_path_failed` names a causal
route fault: both are selection context. The oracle reports an independently
established preferred-route fault as unrecognized, and Challenge Mode scores
preferred-route and wrong-default-route conditions as `ChallengeUnrecognized`.
The simulator's private alternate-path measurement cannot count as a diagnosis
made by Network Doctor.

### How much ground a hunt covered

A clean hunt result answers one question, whether any case disagreed with
Network Doctor. It does not answer the other one: how much of its own universe
the run actually stood on. Five hundred cases against `healthy` in the
bug-oracle lane build six distinct networks and then rebuild those six another
four hundred and ninety-four times, because the three operators that base can
host take no parameters. Case counts measure execution. Coverage measures
ground.

Every hunt result carries a `coverage` block, and every triage baseline carries
the same block for its hunt. It is derived from the case results and from the
base scenario's own library definition, so it changes nothing about findings,
leaves `result: clean` alone, and a merged hunt recomputes exactly what the
unsharded hunt would have reported rather than summing partial views.

Per operator, in registry order, three claims in descending strength:

- **applicable**: the base scenario can host it. A fact about the scenario, and
  reported for operators the run never drew, since that absence is the point.
- **generated**: the generator drew it into at least one case.
- **observed**: independent simulator evidence confirmed its effect in at least
  one executed case, which is `ObservedFaults` and never mutation intent.

Per oracle condition, in oracle order:

- **reachable**: an applicable operator declares it as its finding contract, or
  a case established it. Faults reach conditions they never declared, so this
  is a floor: deleting a default route also takes IPv4 off the internet, and
  only the second half of the test sees that.
- **established**: the simulator's own evidence put the condition on the
  network with the oracle in a position to compare.
- **recognized**: the diagnosis then named it. The difference between the two
  is exactly the false negatives the run reported for that condition.

And a handful of aggregate numbers: how many distinct combinations of operators
the run built, how many distinct fully parameterized experiments those became,
the case number of the last one that introduced a combination no earlier case
had, and how many executed cases the condition oracle could compare at all.
That last one matters most in the stress lane, where persistent shaping and
timed path transitions are deliberately not final-state comparisons: a
twenty-case stress hunt whose oracle could compare four of them proves less than
its case count suggests.

Two more describe the shape of the faults themselves:

- **mutation cardinality** counts the cases carrying one fault, two, and so on.
  `--max-faults` says what the run asked for; this says what the base could
  deliver, and they come apart wherever the applicable operators share conflict
  tags. `two-path-ipv6-healthy` in the bug-oracle lane hosted four operators of
  which three are resolver faults, so under v6 a ceiling of three still built
  nothing larger than a two-fault network; the operator v7 promoted is what
  gave that base a third fault to build with. Reading it against the sum of
  the observed operator counts also gives the masking: faults written into the
  scenario that no independent evidence caught happening, because an earlier
  fault took the path the later one needed.
- **multi-fault cases** counts the cases whose evidence independently confirmed
  two or more faults on the same network. It is what `--max-faults` actually
  buys, and the only number that says so. Counting established conditions
  instead would not: a deleted default route establishes both the missing route
  and an unreachable IPv4 on its own, so a hunt that never once put two faults
  together can still look like it tested precedence everywhere.
  `healthy-routed-network` in the bug-oracle lane is exactly that hunt, and only
  this row says so.

The gaps list is the derived reading, and it is a statement about the hunt, not
an accusation against Network Doctor. `operator_not_generated` means the base
could host a fault the budget never drew. `operator_not_observed` means the
generator drew one and nothing independently confirmed it reached the wire.
`condition_not_established` means an operator promised a condition and no case
put it on the network. A dry run files none of the last two, because a run that
executed nothing observed nothing.

What coverage deliberately does not claim: that the reachable-condition set is
complete, since side-effect reachability is only visible once something
establishes it; that a distinct experiment is a distinct outcome, since two
parameterizations of the same operator can produce the same network behaviour;
and that full coverage means correctness, since the oracle can only compare the
conditions it has rules for.

### Generator versions

The mutation registry is versioned because changing an operator universe, lane
rule, or case identity changes which network an existing case number names.
`HuntGeneratorVersion` is the current one and `huntGeneratorVersions` lists
every version this build can still materialize. Each operator carries the
version it first appeared in, and new operators are appended rather than
interleaved.

Generator v6 introduced the lane split. It filters the authoritative registry
by `findingContract` before applicability and random permutation, and records
the resolved lane in every current manifest and result. That changes selection,
so reusing v5 would have silently repointed published case coordinates. V6 also
includes lane and case number in case identity so a small oracle-backed operator
universe can consume the requested case budget without a generator defect.

Generator v7 promoted `routing.preferred_path_failure` into the bug-oracle
lane. That changes which universe a permutation is drawn from on the two
multipath bases, so doing it in place would have repointed published v6 cases
there. The operator records the version its contract starts at instead, and
every earlier generator keeps seeing it in the stress lane with no contract at
all. `TestVersion6LaneMembershipSurvivesTheVersion7Promotion` pins both
memberships, and `TestShardPreservesGlobalCaseReproductionIdentity` holds the
same case's v6 and v7 fingerprints side by side. The promotion is also what
gives `two-path-ipv6-healthy` an oracle condition at all: every other operator
that base can host shares one non-condition contract.

Generators v3 through v5 remain the unchanged all-operator selection path and
retain their original semantic case fingerprints. Their manifests omit lane,
as they always did. Case seeds are not versioned: every version derives the
same seed from the hunt seed, base, and case number, then differs only under its
recorded generator rules. `TestHuntGeneratorVersion3Reproduction` pins an older
generator against a fixed manifest. New hunts default to v7 and `bug-oracle`;
use `--generator-version` and `--lane` to select retained historical behavior
explicitly.

### Route tables, and telling absences apart

Three families are about a route that is not there, and none of them can be
established from reachability. `RouteEvidence` answers "where does this
destination go"; `RouteTableEvidence` is the different reading of "what routes
exist at all", taken with `ip route show` from inside the node at the end of
the run and recorded for every family the node has an address in. An empty
`routes` list is therefore the positive statement that the table was read and
held nothing, which is what `routing.no_default_route` needs, and a record
being absent means nobody looked, which never establishes anything.

`routing.wrong_default_route` needs one thing more, because a default that goes
nowhere and a network that is broken past the gateway look identical from the
client: the control endpoint behind the original next hop, reached over its own
specific route, has to still answer. That is what says the old gateway still
forwards and only the choice of default changed.

Two more families are about a port rather than a route, and they are each
other's negative. `ControlledTargetEvidence` now carries the outcome of the
simulator's own dial rather than only whether it worked, because a reset and a
timeout are different faults with different fixes and the dialing end is the
only place the difference is visible. `service.connection_refused` requires the
dial to have been refused and no drop counter to have matched; `service.tcp_port_blocked` requires the opposite of both. Neither can be established by
a dial that merely failed, and a run cannot satisfy both.

## Triage and nightly automation

`netdoc-sim triage` hunts the fixed baselines, re-runs each candidate's exact
case, and requires both its case fingerprint and finding fingerprint to match.
An unreproduced candidate is reported but never filed. The baseline list and
fixed regression seeds are authoritative in `internal/simulation/triage.go`.

The baseline set is chosen so that every operator in the registry is applicable
to at least one of them, which `TestEveryHuntOperatorReachesABaseline` holds it
to. A single-path base cannot host a route-choice fault, so the multi-path bases
are what let the routing families run at all; without them those operators exist
but the nightly hunt can never generate one, and the family is unfalsifiable
however good its oracle is. Their second test is also the control that the route
coverage findings are built from.

```sh
./netdoc-sim triage --lane bug-oracle             # observe; file nothing
./netdoc-sim triage --lane bug-oracle --scenarios healthy --cases 5
./netdoc-sim triage --json
./netdoc-sim triage --create                      # create issues through gh
./netdoc-sim triage --lane bug-oracle --hunt-results merged-hunts/bug-oracle
```

`--hunt-results` requires one canonical merged report for every selected
baseline and validates its content rather than its file name. It replaces only
the initial full hunts. Candidate findings are still re-run as exact cases in
fresh namespaces before they can be filed, using the generator version recorded
in each candidate's reproduction metadata. Triage also requires reports to
match the selected lane and replays each candidate with its recorded lane.
Artifacts with a missing or unknown generator version are rejected instead of
being assigned the current default. Missing lane metadata is accepted only for
generators v3 through v5 and resolves explicitly to `all`.

`--create` is the only mode that writes to GitHub. It uses the configured `gh`
client and suppresses duplicates by a stable identity derived from the
reproduction coordinates, exact case fingerprint, and finding fingerprint. It
treats a failed hunt, reproduction, parse, or `gh` call as an error rather than
as a clean result.

`.github/workflows/hunt.yml` is authoritative for the nightly schedule, runner,
permissions, case count, and issue-creation opt-in. Scheduled issue creation
requires the `NETDOC_HUNT_CREATE` repository variable; manual dispatch requires
its `create` input. Observation-only runs withhold `GH_TOKEN`, even though the
job declares the permission needed by an opted-in run. Keep the workflow's
explicit Bash/`pipefail` behavior and seeded-netem-compatible runner when
changing it. One job resolves the exploration seed as the UTC date in
`YYYYMMDD` form, then every baseline and every shard in both lanes receives that
exact numeric value. The nightly bug-oracle lane runs 60 cases per baseline over
four shards at `--max-faults 3`. The stress lane runs 30 cases per baseline over
two shards at `--max-faults 2`.
Both lanes are merged and uploaded separately, while automated finding triage
consumes only the bug-oracle reports. This keeps the majority of requested
nightly case capacity on oracle-backed mutation selection without deleting
stress exploration. Triage rejects a merged report whose fault ceiling is not
the one it was asked for, so the ceiling the bug-oracle lane hunts at and the
ceiling triage passes are one number in two places, and a test holds them to
each other.

Both budgets are set by measured coverage rather than by preference. Across the
eight baselines, the bug-oracle lane can build 121 distinct operator
combinations at `--max-faults 2` and 182 at `--max-faults 3`; 60 cases per
baseline reach 113 and 152 of them respectively, and starve no baseline-operator
slot at either ceiling. Five hundred cases per baseline reach the whole
universe, so the remainder costs several times the runtime. The stress lane
starves five slots at 20 cases per baseline and none at 30, which is why 30 is
the floor there. Raising either budget further buys distinct parameterizations
rather than distinct kinds of network, and the `coverage` block on each report
is what makes that visible on any given night. Each report and case manifest
records the lane and seed, so a later replay uses artifact metadata rather than
current defaults or the replay date.

The ceilings differ because their value does. Sixty-one of the bug-oracle
lane's 182 combinations need a third fault, and they are where two oracle
conditions sit on one network at the same time: whether the diagnosis still
names an expired certificate while the default route is gone, or a blocked QUIC
path while a family is down. Two faults can put two oracle conditions on one
network eleven ways in total; three faults can do it forty-eight.
Measured live on `tls-valid`, sixty cases at the three-fault ceiling established
73 oracle conditions against 51, and put two independently observed faults on
one network in 28 cases against 16, for 18 percent more wall clock. Across five
baselines the same comparison is 352 conditions against 235 and 132 multi-fault
cases against 71, for 12 percent more wall clock. A third fault does get masked,
more often than a second: a resolver fault takes the name a certificate or a
QUIC endpoint needed, and the fault behind it never reaches the wire, which is
why 24 percent of generated faults went unobserved against 16. That is the cost,
and the coverage block reports it rather than hiding it.

The stress lane has no oracle conditions to interact and a combination space
more than twice as large, so a third fault there only spends the budget on
faults nothing compares. At 30 cases it reaches 150 combinations of a 354-set
universe against 116 of a 210-set one, misses 103 of the two-fault combinations
it would otherwise have drawn, and starves an operator slot the 30-case budget
was chosen to reach. Measured live over two baselines at 30 cases each, it also
drops the oracle-comparable cases from 18 to 13, and no stress case established
an oracle condition at either ceiling.

The fixed-seed stress regression remains separate in
`.github/workflows/ci.yml`.
`TestGeneratedStressHuntPMTUBlackholeCaseReachesThePathMTUProbe` runs one routed
stress case at seed `20260102`, case `20`, and checks that its known generated
path-MTU fault still reaches the intended probe. It is small and stable while
the larger nightly workflow explores a new date seed.
