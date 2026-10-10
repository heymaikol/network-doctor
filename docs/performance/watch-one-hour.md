# Watch one-hour benchmark

This report measures what incremental Watch saves over fresh passes across one
simulated hour, first with nothing changing on the network and then with an
outage, a route change and an invalidation. It is evidence for issue #259. It
does not claim the full hour runs faster on a real host. Every number below
comes from the commands in [Reproducing](#reproducing) on the host in
[Environment](#environment).

## Summary

- Stable hour, incremental against fresh: 61 full passes instead of 721. TLS
  ClientHellos, handshakes, target HTTP requests and plain-endpoint dials each
  fall by about 92%. Target TCP dials do not fall, because the target and path
  MTU rows run on every pass in both arms.
- Per hour, incremental uses about 69% less CPU (user plus system) and about 62%
  fewer allocations than fresh. Wall time per scheduled pass falls about 44%.
  Ranges and repeat-run spread are in [Repeated runs and variability](#repeated-runs-and-variability).
- Session bookkeeping allocates more than fresh. With reuse disabled (the forced
  arm), the session makes about 12% more allocations than fresh. The network
  counts match fresh in that arm, so the extra allocations come from the
  session itself. Its CPU difference from fresh is inside the run-to-run spread.
- Outage and route-change events each cost one discarded attempt or one whole
  measurement, as the single-event tests require. The events hour counts are in
  the results.

## Reproducing

Run every command from the repository root. All runs use the integration build
tag. They dial only loopback addresses and make no external DNS or public
reference requests.

```sh
# Real-socket hour, all arms, Go benchmark output.
go test -tags integration -run '^$' -bench '^BenchmarkRealWatchPasses$' \
  -benchtime=720x -count=3 -benchmem ./internal/diagnostic

# Lockstep hour: session and fresh oracle over one network, every pass compared.
go test -tags integration -run '^TestRealWatchOneHourMatchesFreshPasses$' -v ./internal/diagnostic

# Fake-probe orchestration cost, no network.
go test -run '^$' -bench 'BenchmarkWatch(StablePass|FullPass)$' -benchmem -count=10 ./internal/diagnostic
```

CPU and wall figures come from `watch_one_hour_cpu.py`. It builds the test
binary once, then runs each arm in its own process, so no arm shares a heap,
a warm cache or a GC state with another. Each repetition starts with a
different arm, so no arm always runs first or last:

```sh
python3 docs/performance/watch_one_hour_cpu.py 10
```

The only argument is the repetition count, from 1 to 100. The driver prints
its output directory first. That directory is a new temporary one, and it holds
the per-process Go benchmark output and `summary.tsv`. `summary.tsv` has the
median, minimum, maximum and coefficient of variation of each metric per arm.
The same table is printed to stdout.

The driver runs five arms: stable incremental, stable forced, stable fresh,
events incremental and events fresh. It omits events forced, so this report
makes no timing claim for that arm. The forced arm is the negative control for
reuse, and only the stable schedule uses it.

## Environment

- CPU: 13th Gen Intel Core i5-13400, 10 cores (6 performance, 4 efficiency), 16
  threads, one socket, one NUMA node. `GOMAXPROCS` is 16.
- Memory: 31 GiB.
- OS: Fedora 44, Linux 7.2.9-200.fc44.x86_64.
- Go: go1.27.0 linux/amd64.
- Frequency: `intel_pstate` in `active` mode with the `powersave` governor.
  Turbo state was not recorded.
- Load: 1-minute load average 1.7 to 2.4 while the runs were in progress.
  Other activity on the host was not stopped.
- Base commit: `a0af7ee1618055ae49c407bba25c801c91ed482f`. The head commit is
  the one that adds this report; see the pull request.

## Workload

One hour is 721 passes: an initial pass at t=0 and 720 scheduled passes at the
five-second Watch cadence, the last at t=3600s. Every total in this report
includes the initial pass. Divided per op in the benchmark output, the 720
scheduled passes are the denominator, so the initial pass appears in the
numerator only. `ns/op` and `-benchmem` figures are per scheduled pass for that
reason.

`go test` runs a benchmark function once with `b.N=1` before the `720x` run.
Only the final run's metrics are reported, so that extra call adds nothing to
the figures in this report.

A session runs a whole measurement at t=0 and whenever `watchMaxAge` (60 s) has
passed since the last whole one. A stable hour therefore has 61 full passes
(t=0, 60, ..., 3600) and 660 incremental passes. The stable-hour test asserts
those full and incremental counts, and the published total of 721.

The graph is the one the real-socket tests use. It has the target TCP connect,
path MTU, TLS, HTTPS, the plain HTTP row, and the system DNS and interface rows.
Of the rows in this graph, TLS, HTTPS and HTTP are in `watchReusable`. The
target runs on a loopback HTTPS server. The plain row runs on a loopback HTTP
server that listens on an OS-assigned port (`127.0.0.1:0`). The HTTP row asks
for port 80, and the fixture's dial rewrites that to the plain server's port,
so the fixture never binds port 80 and needs no extra privilege. Name
resolution and route lookups are stubbed. In the stable
hour the target and path MTU rows run on every pass in both arms, so they cost
a TCP connect per pass in both.

Two schedules:

- `stable`: nothing changes on the network.
- `events`: the target stops before pass 150 and restarts before pass 153, so
  passes 150 to 152 fail. Pass 250 moves every route answer to another
  interface with no event sent to the session. Pass 370 calls `Invalidate` on
  the session, which is the route-change notification the session gets.

Three arms per schedule:

- `incremental`: the production `WatchSession`, with the publish loop the
  headless command runs. A publish refused by the session runs the pass again
  at once.
- `forced`: the same session with `Force` before every pass. No row is reused,
  so this is the negative control for reuse. It isolates the session's own
  bookkeeping from the network savings.
- `fresh`: no session. Every pass runs every row. This is the baseline.

## Measurement boundaries

The timed region starts before the initial pass and ends after the last
scheduled pass. Listener setup, certificate generation and the first
`ResetTimer` are outside it. Each arm runs `Interpret` on every pass, as the
headless loop does on each published pass.

Counters are read before and after each pass. The fixture waits for every
client-side connection to be accepted and every handshake to finish before it
reads the server counters, so a pass's traffic is the difference between two
reads. A refused publish's traffic belongs to the pass that made it, because
each attempt touched the network.

CPU is the `getrusage(RUSAGE_SELF)` delta over the timed region of each
process, and includes the loopback servers, which run in the same process.
Allocation totals are `runtime.MemStats` deltas over the same region. A garbage
collection runs before the baseline is read.

Wall time includes the settle polling the fixture uses to wait for server
accepts, at 1 ms steps. The figure is the cost of a benchmark pass, not the
latency a user sees.

## Measured quantities

Status values follow the brief. **Measured**: taken directly from a counter or
the runtime. **Derived**: computed from measured values. **Unmeasured**: the
harness has no counter for it; any stub call count is noted, and it is not the
real quantity. **Not exercised**: the row is not in this graph, so there is no
figure at all.

| Quantity | Status | How |
| --- | --- | --- |
| Scheduled passes | measured | the pass loop's count, 720 plus the initial pass |
| Published passes | measured | `Publish` results per pass |
| Full passes | measured | `WatchPass.Fresh` per published pass |
| Incremental passes | derived | published minus full |
| Discarded attempts | derived | attempts beyond the first, per pass |
| Probe executions by ID | measured | wrapper around each probe's `Run`; reused rows never reach it |
| TCP dials, target and plain | measured | client dial calls per endpoint, failed ones included |
| TCP dials, total | derived | target plus plain |
| TCP accepts, target and plain | measured | server accept counters |
| TLS ClientHellos | measured | server count, read after the handshake is awaited |
| TLS handshakes completed | measured | server count of handshakes that finished |
| HTTP requests, target and plain | measured | server request counters |
| UDP connects | measured | client-side count of the UDP probe's connect; sends nothing, so it is not a QUIC handshake |
| Bytes read by the servers, target and plain | measured | application bytes the server reads; excludes TCP and IP headers and every byte the server writes |
| System DNS queries | unmeasured | the stub resolver was called 721 times in the stable hour; no DNS packet is sent |
| Route lookups | unmeasured | the stub route function was called 2163 times in the stable hour; no kernel route lookup is made |
| Allocations and allocated bytes | measured | `runtime.MemStats` deltas over the timed region |
| CPU user and system time | measured | `getrusage` deltas, one process per arm |
| Wall time per scheduled pass | derived | benchmark total divided by 720 |
| Public DNS queries | not exercised | the public DNS row is not in the graph |
| Encrypted DNS queries | not exercised | the encrypted DNS row is not in the graph |
| QUIC handshakes | not exercised | the QUIC row is not in the graph |
| Proxy, SSH and SMTP rows | not exercised | not in the graph |

## Results

Counts are identical in all 10 processes of each arm, with two exceptions:
bytes read by the servers and allocations. Those two vary slightly, so this
report gives the exact byte ranges and the allocation median. Timing figures are
medians of the 10-process run, with the range in brackets. Per-hour figures
include the initial pass.

### Network and pass counts per hour

| Quantity | Stable incremental | Stable fresh | Events incremental | Events fresh |
| --- | ---: | ---: | ---: | ---: |
| Published passes | 721 | 721 | 721 | 721 |
| Full passes | 61 | 721 | 65 | 721 |
| Incremental passes (derived) | 660 | 0 | 656 | 0 |
| Discarded attempts (derived) | 0 | 0 | 1 | 0 |
| target_tcp runs | 721 | 721 | 722 | 721 |
| path_mtu runs | 721 | 721 | 718 | 718 |
| tls runs | 61 | 721 | 62 | 718 |
| https runs | 61 | 721 | 62 | 718 |
| http runs | 61 | 721 | 65 | 721 |
| TCP dials, target | 1442 | 1442 | 1440 | 1439 |
| TCP dials, plain | 61 | 721 | 65 | 721 |
| TCP dials, total (derived) | 1503 | 2163 | 1505 | 2160 |
| TCP accepts, target | 1442 | 1442 | 1436 | 1436 |
| TCP accepts, plain | 61 | 721 | 65 | 721 |
| TLS ClientHellos | 61 | 721 | 62 | 718 |
| TLS handshakes | 61 | 721 | 62 | 718 |
| HTTP requests, target | 61 | 721 | 62 | 718 |
| HTTP requests, plain | 61 | 721 | 65 | 721 |
| UDP connects | 0 | 0 | 4 | 3 |
| System DNS stub calls (unmeasured) | 721 | 721 | 722 | 721 |
| Route lookup stub calls (unmeasured) | 2163 | 2163 | 2166 | 2163 |
| Bytes read, target (exact range, batch 2) | 17,829,590 to 17,829,605 | 19,024,277 to 19,024,541 | 17,757,664 to 17,757,679 | 18,944,576 to 18,945,374 |
| Bytes read, plain | 5,490 | 64,890 | 5,850 | 64,890 |

Derived, incremental against fresh:

- Stable: ClientHellos, handshakes, target requests and plain dials each fall
  by 91.5% (61 against 721). Plain bytes fall 91.5%. Target bytes fall about
  6.3%, because the path MTU and target TCP work is the same in both arms.
  Target TCP dials and accepts do not change (1442 each), so reuse saves no
  target TCP connects. Total TCP dials fall from 2163 to 1503, which is 30.5%.
- Events: the one discarded attempt is the outage onset, which publishes on its
  second attempt. Three passes fail, so the incremental arm makes three fewer
  ClientHellos than full passes (65 full, 62 ClientHellos). The four UDP connects
  in the incremental arm are the three failing passes and the discarded attempt.
  The fresh arm makes three UDP connects, one per failing pass.
- The forced arm (stable) makes 721 ClientHellos, the same as fresh, as expected
  for a negative control: reuse is off, so the network counts match fresh.

### Wall and CPU per hour

Medians of 10 processes, range in brackets. Allocation totals are medians.

| Quantity | Stable incremental | Stable forced | Stable fresh | Events incremental | Events fresh |
| --- | ---: | ---: | ---: | ---: | ---: |
| Wall per scheduled pass, ms (derived) | 2.83 [1.81, 3.10] | 5.50 [4.88, 5.75] | 5.06 [4.00, 5.31] | 2.79 [2.65, 3.08] | 4.94 [3.08, 5.46] |
| CPU user, s | 1.43 [0.56, 1.51] | 5.71 [4.84, 5.95] | 5.28 [4.07, 5.62] | 1.43 [1.35, 1.46] | 5.13 [2.86, 5.51] |
| CPU system, s | 0.73 [0.31, 0.79] | 1.82 [1.61, 1.93] | 1.72 [1.27, 1.80] | 0.73 [0.66, 0.77] | 1.68 [0.97, 1.80] |
| Allocations, median | 492,672 | 1,432,020 | 1,279,200 | 494,974 | 1,275,540 |
| Allocated bytes, MB, median | 106.7 | 300.1 | 277.8 | 107.3 | 276.9 |

Derived, incremental against fresh:

- Stable: wall per pass 44% lower. CPU user 73% lower, CPU system 58% lower,
  total CPU 69% lower. Allocations 62% lower.
- Events: wall per pass 44% lower. CPU user 72% lower, CPU system 57% lower,
  total CPU 68% lower. Allocations 61% lower.
- Forced against fresh (stable): wall per pass 9% higher, total CPU 8% higher,
  allocations 12% higher, allocated bytes 8% higher. Allocation counts vary by
  under 0.1% across processes, so the 12% is a stable difference. The CPU
  difference is inside the run-to-run spread for the forced arm.

## Repeated runs and variability

Two batches of 10 processes per arm were run with the same commands. Batch 1
used an earlier shell driver with the same commands. That driver is not in the
repository. Batch 2 used `watch_one_hour_cpu.py`. Medians from the two batches:

| Quantity (stable) | Batch 1 | Batch 2 |
| --- | ---: | ---: |
| Incremental wall per pass, ms | 2.87 | 2.83 |
| Fresh wall per pass, ms | 4.87 | 5.06 |
| Incremental CPU user, s | 1.44 | 1.43 |
| Fresh CPU user, s | 4.97 | 5.28 |
| Forced CPU user, s | 5.46 | 5.71 |

Counts matched across both batches, with the bytes and allocation exceptions
above. The two batches agree within 7% on incremental and fresh medians.

Spread within a batch:

- Incremental CPU and wall time are the least stable figures. In batch 2 the
  stable incremental arm has one low outlier (repetition 3: 0.56 s user, 1.81
  ms per pass). Its user time is about 60% below the arm's median. Its counts
  match the rest. The cause was not identified: frequency state and core type
  were not pinned. The outlier stays in the data and in the minimum, and the
  median is unaffected.
- Fresh events has a low outlier too (2.86 s user, 3.08 ms per pass), so the
  events fresh range is wide (CV 17%).
- Non-overlap: every stable incremental process used less CPU user time than
  every stable fresh process, and the stable wall ranges do not overlap. The
  events wall ranges overlap by under 0.01 ms, at 3.08 ms, where fresh had its
  low outlier.
- The forced arm and fresh overlap in CPU ranges, but the forced median is
  higher in both batches.

Fake-probe orchestration cost (no network, `BenchmarkWatch*`, 10 runs):

| Benchmark | Mean (µs/op) | Min | Max | B/op | allocs/op |
| --- | ---: | ---: | ---: | ---: | ---: |
| `BenchmarkWatchStablePass` | 258 | 205 | 292 | 49,413 | 402 |
| `BenchmarkWatchFullPass` | 125 | 109 | 132 | 27,611 | 217 |

These two are not like for like. `BenchmarkWatchStablePass` runs `Begin`, the
rows the session does not reuse, and `Publish`, on every iteration.
`BenchmarkWatchFullPass` calls `RunAll` over the whole graph with no session, so
it has no `Begin` or `Publish`. Fake probes do no I/O, so both figures measure
orchestration only. They do not measure the savings, which the real-socket arms
above report. In the `BenchmarkWatchStablePass` CPU profile, garbage collection
and runtime scheduling are the largest entries. Formatting (`fmt`) is 6.8%
cumulative, and its caller was not traced.

## Correctness checks

- Lockstep hour: `TestRealWatchOneHourMatchesFreshPasses` runs the session and
  the fresh oracle in step over one network for all 721 passes, and compares
  each pass's diagnosis with the oracle. It passed 10 times under `-count=10`,
  and once under `-race` with no data race reported.
- 60 s maximum age: the stable hour asserts the full-pass count (61) and the
  incremental count (660) that the schedule implies.
- Full confirmation: at the outage onset the published pass is attempt 2, so the
  reused HTTP row was discarded once and confirmed.
- Linux route-event invalidation: the route change at pass 250 is caught by the
  rows that read the route, which the session never saw as an event. The
  `Invalidate` call at pass 370 forces a whole measurement.
  `TestRealWatchRouteChangeRerunsReusedRows` covers the same path on real
  sockets. The netns test `TestRouteEventsReachTheSessionFromTheKernel`
  (`netns_integration` tag) covers the kernel route-event feed. It ran on this
  host with unprivileged user namespaces and passed, with the helper reporting
  `ROUTE EVENT SEEN`. The helper's own SKIP line in that run is expected, because
  the helper only runs inside its namespace.
- Windows suspend: not exercised on this host. `SystemUnbiasedClock` is a no-op
  on Linux. The logic is covered only by fake-clock unit tests:
  `TestWatchPassCurrentNeedsBothClocksAndNoSuspend` and
  `TestWatchUnbiasedCountRefusesSuspendThatMonotonicCounts`. The Windows
  real-clock test `TestWindowsWatchPassStaysCurrentOnRealClocks` runs only on
  Windows and was compiled here, not run.
- Slow-pass liveness: a pass longer than 60 s still publishes. Covered by
  `TestHeadlessSlowWatchPassesPrint`, `TestWatchAbsurdTimeoutDoesNotRefuseASlowPass`,
  `TestWatchSlowPassesUpToTheWindowPublishFirst` and `TestWatchTUISlowPassesPublish`,
  all added by #314.
- Forced retest: a retest or a forced pass measures every row.
  `TestWatchRetestRunsEveryRowThroughTheTUI`, `TestWatchForcedPassRunsEveryRow`
  and `TestHeadlessWatchSaveAcquiresEveryRowFresh` cover the TUI retest, the
  session's `Force`, and the headless save path.
- TUI and headless agreement: the two front ends apply the same publish rule.
  `TestWatchSessionRecordsOnlyPublishedPassesThroughTheTUI` and
  `TestHeadlessWatchPrintsOnlyPublishedPasses` each check it in one front end.
  No single test runs one graph through both front ends for Watch. The
  differential oracle in `internal/ui/differential_test.go` compares the probe
  DAG executors, not the Watch session.
- Incident provenance: `TestIncidentDoesNotReportReadingsLostWithTheSocketAsPathChanges`
  and `TestIncidentReportsAResolverTargetChangeAsEnvironmental` check that
  changes in the environment and changes in outcomes are reported separately.

## Negative control and mutations

The forced arm is the first control: it removes reuse and keeps the session.
Its network counts equal the fresh arm's, and its extra allocations are the
session's own bookkeeping.

Two mutations were applied to a clean `watch.go`, each run, then reverted with
`git checkout`:

- M1, reuse disabled (`reuse()` returns false): the stable hour fails
  (`TestRealWatchOneHourMatchesFreshPasses/stable`: published full passes 721,
  against 61 expected), and `TestRealWatchStableWindowsMatchFreshPasses` fails at
  its first step. The lockstep test catches the mutation.
- M2, `lastFull` guard removed from `Begin` (`|| !within(at, s.lastFull)`): every
  real-socket test still passes. The fixture never desynchronizes row sample
  times, so the guard never changes a decision there. The unit test
  `TestWatchWholeMeasurementStaysWithinMaxAgeAfterRowsDesync` (in `watch_test.go`)
  catches it. The real-socket hour does not protect the guard, and this report
  does not claim it does.

## Validation at head

Each command ran at the commit that adds this report. Results:

- `./scripts/check`: passed.
- `./scripts/check --race`: passed.
- `go test -tags integration -count=1 ./internal/diagnostic`: passed.
- Netns route-event test, `go test -tags 'linux netns_integration' -run TestRouteEvents ./internal/diagnostic`: passed.
- golangci-lint v2.14.0 (`go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.14.0 run ./...`): 0 issues.
- golangci-lint v2.14.0 with `--build-tags integration` on `./internal/diagnostic/...`: 8 issues, all in pre-existing integration test files (`checks_integration_test.go`, `localservices_integration_test.go`, `quic_integration_test.go`). The base commit gives the same 8. None are in files this change adds or edits.
- `GOOS=windows`, `GOOS=darwin` and `GOOS=freebsd` `go vet -tags integration ./internal/diagnostic`: clean.
- Tracked-text em dash test (`TestNoEmDashInTrackedTextFiles`) and the docs link test: passed after the new files were staged.
- The 14 correctness tests named above: all PASS with `-v`.
- `TestRealWatchOneHourMatchesFreshPasses`: 10 runs with `-count=10`, one `-race` run.

Netns and integration runs used unprivileged user namespaces on this host. No
run changed the host's routes, firewall or interfaces.

## Threats to validity

- Loopback has no real latency, loss or path MTU, so wire time is not
  represented. The network savings here are counts and CPU, not elapsed network
  time.
- CPU and allocation totals include the loopback servers, which run in the same
  process as the client. They are the cost on one host, not the client's cost
  alone. They are not split by side.
- The host runs `intel_pstate` with `powersave`. Clock speed moves within a run.
  Core placement (performance or efficiency) was not pinned. Both can move the
  CPU figures, as the batch 2 outlier shows. Medians are reported with ranges;
  differences inside the range are not claimed.
- The system ran other work during the runs. Load was 1.7 to 2.4.
- The events schedule is one outage, one route change and one `Invalidate`. A
  real hour can contain many more, and each costs a discarded attempt or a
  whole measurement.
- The benchmark never calls `FollowRouteEvents`, so the incremental arm gets no
  route events. That is the best case for savings. Without events, `watchMaxAge`
  is the only bound on staleness.
- `SystemUnbiasedClock` is a no-op on Linux, so the Windows suspend protection
  is not exercised here.
- The `lastFull` guard is not exercised by the real-socket hour (see M2).
- DNS and route lookups are stubbed. The stub call counts are not DNS queries or
  kernel route lookups.
- Single host, single kernel, single Go version.

## Differences from a real one-hour session

- A real session has a real target, a real resolver and a real route table. The
  fixture stubs DNS and routes and runs both endpoints on loopback.
- A real session does not run passes back to back. The headless loop waits five
  seconds after a pass ends, so a real hour holds at most 720 scheduled passes
  and usually fewer, because a slow pass pushes the next one back.
- A real session can receive route events, which refuse reuse at once. The
  benchmark sends only the single `Invalidate`.
- A real session runs public DNS, encrypted DNS, QUIC and proxy rows when the
  user asks for them. None are in this graph, so their cost is not in the
  savings.

## Baseline at a0af7ee

The earlier per-op benchmark had two faults, both fixed here:

- The initial full pass ran before `ResetTimer`, so incremental totals missed
  it. The 0.08333 requests per op was 60 of 720, not zero.
- The fresh arm had no initial pass, so the arms covered different passes.

Reconstructing the baseline with the initial pass added (per-op × 720, plus one
initial pass, which is three dials, one ClientHello, one request and two target
accepts) reproduces the hour totals exactly:

| Quantity | Baseline per op × 720 + initial | Hour total |
| --- | ---: | ---: |
| Incremental TCP dials, target plus plain | 1500 + 3 = 1503 | 1442 + 61 = 1503 |
| Incremental ClientHellos | 60 + 1 = 61 | 61 |
| Incremental target accepts | 1440 + 2 = 1442 | 1442 |
| Fresh TCP dials, target plus plain | 2160 + 3 = 2163 | 1442 + 721 = 2163 |
| Fresh ClientHellos | 720 + 1 = 721 | 721 |

Baseline wall times (2.73 to 2.95 ms incremental, 4.72 to 5.20 ms fresh per
op, from the earlier three-run benchmark) agree with the batch medians above.
