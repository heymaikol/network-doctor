# Recorded hunt case results

Hunt case results captured from a namespace-backed run and committed so a test
can ask what a real case is worth without building a network namespace. Each
file is one `HuntCaseResult` as `canonicalHuntCaseResult` would have received
it: the manifest and the simulation report the run produced, before any hunt
projection or ceiling is applied to them.

They exist because the sizes that matter here are the sizes real evidence
reaches. A hunt case is mostly netdoc's own diagnosis, once per timed test, and
the simulator's per-query evidence, and both grow with how long the run takes
and how often netdoc retries. A report built in a unit test is a fraction of
that, so a ceiling measured against one is not a ceiling a real case fits under,
and a projection checked against one is not a projection that keeps what a real
case is worth.

## Cases

* `case-116-transient-dns-outage.json` is generated case 116 of the
  `healthy-routed-network` bug-oracle hunt at seed 12345, generator v7. Its
  resolver goes silent 150 ms into the run and answers again 654 ms later, and
  netdoc concludes without asking it a second time, so the case rediscovers
  `SuggestTransientNotResampled`. It was recorded on a loaded host, where the
  outage bites and the run stores 34 DNS queries across three timed tests: the
  same case on an idle host stores about half that and measures about 59 KiB.
  It is the case `TestGeneratedHuntCasesAreReproducible` asks a real backend
  about, and the one whose finding a 64 KiB per-case ceiling discarded.
* `case-001-two-path-target-reset-dns-outage.json` is generated case 1 of the
  `two-path-healthy` bug-oracle hunt at seed 20261028, generator v7, the case
  issue #436 names. Unlike the case above, it is the stored result, not the
  run's raw input: it is case 1 of `bug-oracle/two-path-healthy.json` in the
  `hunt-results` artifact of the scheduled Hunt run 40673426296, re-encoded with
  the same JSON value. Its report is already canonical, so the target's
  declared aliases are missing and no row carries `selected_ip`. It injects a
  TCP reset on target port 80 that no test targets, and carries the
  `tcp_reset_not_distinguished` finding (`eeb7cee872293e78`) main raised.
  `TestRecordedUnprobedResetIsAKnownSilence` fails on main and passes here.

## Adding one

Record the case from a real run rather than editing one of these by hand. A
test that reads a file here must recompute what it asserts from the manifest
and the report, never trust the derived fields the file happens to carry, and
must say what about the recording makes it evidence, so a recording that stops
being large enough, or stops carrying the finding, fails rather than passing
vacuously.
