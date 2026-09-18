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

## Adding one

Record the case from a real run rather than editing one of these by hand. A
test that reads a file here must recompute what it asserts from the manifest
and the report, never trust the derived fields the file happens to carry, and
must say what about the recording makes it evidence, so a recording that stops
being large enough, or stops carrying the finding, fails rather than passing
vacuously.
