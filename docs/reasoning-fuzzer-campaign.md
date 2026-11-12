# Reasoning fuzzer campaign, 2026-09-06

The retained campaign receipt is
[`reasoning-fuzzer-campaign.json`](reasoning-fuzzer-campaign.json).
It contains the complete JSON summaries from the two runs below. No production
reasoning or comparison behavior was changed for this work.

## Campaign

Generator: `reasoning-v1`. Each run uses case numbers 0 through 49,999,
`--max-faults 4`, two-sided generation enabled, four workers, every property,
and no stop-on-first. Timing includes property execution and generator work.

```sh
GOCACHE=/tmp/netdoc-go-cache go build -o /tmp/netdoc-sim-fuzz ./cmd/netdoc-sim
/tmp/netdoc-sim-fuzz lab fuzz --seed 847293 --cases 50000 --workers 4 --json
/tmp/netdoc-sim-fuzz lab fuzz --seed 20260906 --cases 50000 --workers 4 --json
```

| Seed | Cases | Applicable property evaluations | Seconds | Cases/second | Violations |
| --- | ---: | ---: | ---: | ---: | ---: |
| 847293 | 50,000 | 278,096 | 163.670 | 305.49 | 0 |
| 20260906 | 50,000 | 278,286 | 164.557 | 303.85 | 0 |
| Total | 100,000 | 556,382 | | | 0 |

| Property | Seed 847293 | Seed 20260906 | Total |
| --- | ---: | ---: | ---: |
| determinism | 50,000 | 50,000 | 100,000 |
| replay-equivalence | 50,000 | 50,000 | 100,000 |
| unsupported-claim-safety | 50,000 | 50,000 | 100,000 |
| ground-truth-isolation | 50,000 | 50,000 | 100,000 |
| unobservable-perturbation | 50,000 | 50,000 | 100,000 |
| two-sided-symmetry | 22,901 | 22,921 | 45,822 |
| fault-commutativity | 597 | 603 | 1,200 |
| observational-equivalence | 2,299 | 2,381 | 4,680 |
| counterfactual-indistinguishability | 2,299 | 2,381 | 4,680 |

Failing cases: 0. Unique original failures before reduction: 0. Unique semantic
failures after deduplication: 0. There are no genuine minimized diagnostic,
comparison, simulation or calibration counterexamples to classify from these
runs, and no synthetic failures were added to a regression corpus. Passing this
bounded campaign does not establish correctness outside its property definitions.

A development pilot also ran 10,000 cases with seed 847293 before the final
IPv6-only/link/default-route/loss dimensions were added. It performed 55,962
applicable evaluations at 272.04 cases/second with no violations. Two subsequent
50,000-case development runs and focused smoke runs also completed. These are
excluded from the 100,000-case acceptance total to avoid combining evolving
construction versions or counting reruns as additional coverage.

## Reduction evidence

`TestLabFuzzReducer` uses a synthetic predicate requiring an existing named
service, independent of Network Doctor's diagnosis. It reduces:

```text
Before: 6 nodes, 8 routes
After:  2 nodes, 0 routes
Accepted edits: 14
```

The test repeats reduction and checks identical output and attempt counts,
validity, and a fixed point under the implemented edit set. This is a test of
the reducer, not a discovered reasoning failure. `TestLabFuzzPairAndClaims`
also reduces two worlds together while preserving different fault locations,
actual matched timeout witnesses, and complete input equality.

## Rejected suspicions and development defects

No candidate production bug was reported and subsequently waived. The following
issues were caught during fuzzer development and corrected in the fuzzer:

- A shallow copy of a replacement service shared DNS record storage with the
  base. Record deletion could corrupt the base into an invalid empty hostname.
  Deep copying the service before mutation fixes ownership; generation and
  independent-ownership tests cover it.
- An expectation-metadata perturbation used `incomplete`, which the existing
  scenario validator does not accept as an authored verdict. Using a valid
  different expectation retains the isolation test without an invalid fixture.
- Removing IPv4 from extra endpoints that had no IPv6 address created invalid
  interfaces. The IPv6-only construction now uses the IPv6-capable base target
  with an IP literal and omits IPv4-only extra endpoints.

Those invalid fixtures were generator/property defects, not diagnostic evidence.
A separate initially failing ownership test had itself retained a shallow copy;
its reference value is now independently copied. The confidence property also
explicitly avoids a false assertion that every evidence-equal pair requires low
confidence on every finding: refusal and family/address contrasts remain directly
observable in both worlds. Overlapping packet filters are not declared commutative.

## Validation

The default Go build-cache directory was read-only in this environment, so Go
commands used `GOCACHE=/tmp/netdoc-go-cache`. No source or test was changed to
accommodate that environment restriction.

| Exact command | Result |
| --- | --- |
| `GOCACHE=/tmp/netdoc-go-cache go test ./...` | PASS |
| `GOCACHE=/tmp/netdoc-go-cache go test -race ./...` | PASS |
| `GOCACHE=/tmp/netdoc-go-cache go test -tags integration ./internal/diagnostic ./internal/peer ./internal/simulation` | PASS with loopback socket access |
| `GOCACHE=/tmp/netdoc-go-cache go vet ./...` | PASS |
| `CGO_ENABLED=0 GOCACHE=/tmp/netdoc-go-cache go build ./...` | PASS |
| `GOOS=darwin CGO_ENABLED=0 GOCACHE=/tmp/netdoc-go-cache go build ./...` | PASS |
| `GOOS=windows CGO_ENABLED=0 GOCACHE=/tmp/netdoc-go-cache go build ./...` | PASS |
| `GOCACHE=/tmp/netdoc-go-cache go test ./internal/simulation ./cmd/netdoc-sim -run '^TestLab' -count=1` | PASS |
| `GOCACHE=/tmp/netdoc-go-cache go run ./cmd/netdoc-sim lab run --all --json` | PASS, authored corpus 20/20 |
| `git diff --check` | PASS |

The first integration attempt failed because the sandbox denied loopback
socket and netlink creation. The unchanged suite passed after rerunning with
that access. This was an environment failure, not a relaxed assertion. The
seccomp fuzzer test deliberately runs without any such access and passed both
normally and under the race detector. Cross-platform builds are compilation
checks; Darwin and Windows runtime behavior was not exercised.

The authored Scenario Lab corpus passed 20/20 before implementation and again
afterward. No production reasoning fixes, automatic corpus promotions, commits
or pushes were performed.

## Campaign under reasoning-v2, 2026-11-10

Everything above is the receipt of the 2026-09-06 campaign and is left as it
was recorded. It was produced by `reasoning-v1`, and this tree no longer
generates those worlds: the same seed and case number now build a different
world, and a case labeled `reasoning-v1` is refused. The numbers above are
therefore a record of that campaign, not something the current binary
reproduces.

`reasoning-v2` changes the construction in two ways. The reference endpoint the
QUIC row dials has an IPv6 address in dual-stack worlds, as the real one has,
and a dual-stack world draws whether that endpoint is answered in both
families, IPv4 only or IPv6 only. The modeled QUIC row also records its
attempts. Both exist so that a QUIC row tried in a single address family is a
state the fuzzer reaches and the unsupported-claim oracle can read.

The retained receipt is
[`reasoning-fuzzer-campaign-v2.json`](reasoning-fuzzer-campaign-v2.json), with
the complete JSON summaries of the two runs below: the same seeds, case range,
`--max-faults 4`, two-sided generation and every property as the first
campaign, on eight workers.

```sh
go build -o /tmp/netdoc-sim-fuzz ./cmd/netdoc-sim
/tmp/netdoc-sim-fuzz lab fuzz --seed 847293 --cases 50000 --workers 8 --json
/tmp/netdoc-sim-fuzz lab fuzz --seed 20260906 --cases 50000 --workers 8 --json
```

| Seed | Cases | Applicable property evaluations | Seconds | Cases/second | Violations |
| --- | ---: | ---: | ---: | ---: | ---: |
| 847293 | 50,000 | 300,997 | 188.574 | 265.15 | 0 |
| 20260906 | 50,000 | 301,207 | 190.851 | 261.98 | 0 |
| Total | 100,000 | 602,204 | | | 0 |

| Property | Seed 847293 | Seed 20260906 | Total |
| --- | ---: | ---: | ---: |
| determinism | 50,000 | 50,000 | 100,000 |
| replay-equivalence | 50,000 | 50,000 | 100,000 |
| unsupported-claim-safety | 50,000 | 50,000 | 100,000 |
| ground-truth-isolation | 50,000 | 50,000 | 100,000 |
| unobservable-perturbation | 50,000 | 50,000 | 100,000 |
| two-sided-symmetry | 22,901 | 22,921 | 45,822 |
| two-sided-cause-preservation | 22,901 | 22,921 | 45,822 |
| fault-commutativity | 597 | 603 | 1,200 |
| observational-equivalence | 2,299 | 2,381 | 4,680 |
| counterfactual-indistinguishability | 2,299 | 2,381 | 4,680 |

The evaluation totals are higher than the first campaign's because
`two-sided-cause-preservation` was added after it. Failing cases: 0.

Unlike the first campaign, this one followed a production reasoning change.
With the same generator and oracle and the reasoning from before that change,
10,000-case runs at seeds 847293, 1, 20261109 and 12648430 fail 29, 29, 45 and
43 cases, every one of them `quic_unavailable` read against egress that failed
in the only address family QUIC was tried in. Those runs are the reason for the
change and are not part of the totals above. As before, passing this bounded
campaign does not establish correctness outside its property definitions.
