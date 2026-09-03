# Field diagnosis replay corpus

This directory stores sanitized Network Doctor snapshots with separately
reviewed ground truth. The replay test reconstructs typed diagnostic inputs
from each `snapshot.ndoc`, runs the current `diagnostic.Interpret`, and compares
the result with `case.json`. It is a data-only path: it builds no probes, opens
no sockets, resolves no names, and reads nothing about the host it runs on, so
it produces the same answer on a machine with no network at all.

The Linux simulator, the native acceptance lane, and this corpus cover
different boundaries:

* The simulator tests network mechanics and probe behavior against controlled
  broken networks.
* Native macOS and Windows acceptance tests the per-OS adapters against the
  operating system's own answers, on hosts the simulator cannot model.
* Field replay tests current diagnostic reasoning against evidence observed in
  an earlier run.

None of the three replaces real-network field validation. A VPN tunnel, a
captive portal, split DNS under routing policy, an IPv6-only or DNS64/NAT64
network, live LAN DNS-SD devices, and a proxy-only managed network are all
outside what CI can manufacture, which is why this corpus exists at all.

The `bootstrap-*` cases are synthetic fixtures generated from typed in-memory
observations. They prove the harness without needing a real network.
They are labeled `provenance.origin: "synthetic"` and do not claim to be field
captures. All other committed cases must use `real_network` provenance.

## Case format

Each case is a directory named for its stable ID:

```text
testdata/field/
  README.md
  2026-08-31-campus-split-dns/
    case.json
    snapshot.ndoc
```

Use a lowercase, hyphen-separated ID of at most 80 characters. A date plus a
short, broad condition is recommended for a real case. Never put an
organization, reporter, hostname, SSID, address, or other network identifier
in an ID. The directory and `case.json` ID must match, and a committed ID must
not be renamed. The `.ndoc` remains named `snapshot.ndoc`.

`case.json` uses schema `netdoc.field-case.v1`:

```json
{
  "schema": "netdoc.field-case.v1",
  "id": "2026-08-31-campus-split-dns",
  "environment": {
    "categories": ["campus", "split_dns"],
    "platform": "linux",
    "platform_details": "Fedora, amd64",
    "details": "Connected to the campus VPN"
  },
  "network_doctor": {
    "version": "1.2.3",
    "assessment": "mostly_correct"
  },
  "ground_truth": {
    "statement": "The internal name intentionally resolved only through campus DNS.",
    "verification": [
      {
        "method": "configuration_review",
        "details": "The network owner confirmed the split-DNS rule and resolver scope."
      }
    ]
  },
  "expected": {
    "verdict": "degraded",
    "findings": ["dns_disagreement"],
    "not_findings": ["dns_failure", "offline"],
    "confidence": [{"finding": "dns_disagreement", "level": "medium"}]
  },
  "provenance": {
    "origin": "real_network",
    "summary": "Captured during a verified field report and reviewed by a maintainer."
  },
  "snapshot": "snapshot.ndoc",
  "notes": "The disagreement is intentional, but the diagnostic should still identify it."
}
```

`expected.findings` is the exact finding set the current engine must produce.
`expected.not_findings` names especially important false positives and improves
failure messages. `expected.confidence` is optional and deliberately partial: it
asserts the [confidence](../../docs/reference.md#diagnosis-confidence) a named
finding must be given, and each entry has to name a finding the case already
requires. Levels are `high`, `medium`, `low`, and `insufficient_evidence`.

Add one only where you can say why that evidence warrants that level, and write
the reason in `notes`. Annotating every case with whatever the engine says today
would record the implementation rather than a judgment, and later calibration
would then be measuring the corpus against itself. A case with no entry asserts
nothing about confidence, which is the honest default while the corpus is small:
the categories are a stated policy, not yet a measured hit rate. Ground truth means the real condition was established
independently of Network Doctor through controlled change, another tool,
configuration review, packet capture, successful remediation, provider
confirmation, or another documented method. It is not whatever the original
Network Doctor run happened to say.

The `snapshot.diagnosis` object is historical output, and that includes the
`confidence` recorded on each of its findings. Replay ignores all of it and
computes a new diagnosis, confidence included, from `target` and typed `checks`
observations. Never copy its prose into machine-readable inputs or use it as the
expected result: the stored assessment is what the producing version concluded,
and the point of replay is to judge the same evidence under today's rules.

The snapshot schema stays `netdoc.snapshot.v1`: replay state added to v1 is
optional, and absence is a state rather than a gap. An absent `cause_family`
means the cause was family-neutral, which is what the direct-egress probe
records when the same route fact held for both stacks. An absent
`derived.answer_comparison` means no DNS answer comparison was recorded, which
is never the same as one that found the resolvers agreeing. Where absence would
instead be a missing measurement, replay refuses the case rather than guess: a
check ID this version does not know, a status or protocol outside the current
vocabulary, an unrecognized cause family or tunnel state, a relaxed status on a
row that is not WARN, an answer comparison on any row but `dns_public`, an
answer comparison on a row that recorded no answers to compare, and a failed
target attempt carrying only human error text with no typed cause.

Two limits are worth knowing before writing `expected` for a real case, and the
first one now depends on how old the artifact is. Support redaction
pseudonymizes every address without preserving the /16 `answersAgree` compares,
in both directions: it can put two agreeing answer sets in different blocks and
two disagreeing sets in the same one. A snapshot produced by a version that
writes `derived.answer_comparison` records what the original unsanitized
comparison found, so replay reads that outcome and never recomputes it from the
pseudonyms, and the `dns_disagreement` finding and the resolver counterfactual
under it both survive intact. A sanitized snapshot that predates the field
carries no such record and is inherently lossy: replay falls back to comparing
the sanitized addresses, so its resolver counterfactual can still be lost or
invented. Nothing here repairs those older artifacts, and nothing here restores
or preserves original addresses in any artifact. That is the second limit, and
it is unchanged: evidence values that are addresses are the sanitized
addresses, not the originals, which is what the artifact actually records.

If a change to the snapshot encoder makes a committed fixture non-canonical,
re-encode it in place rather than editing the JSON by hand: decode the file
with `snapshot.Decode` and write back `snapshot.Encode`. Nothing about the
observations changes, so the expected diagnosis does not either.

Environment categories are `vpn`, `corporate`, `campus`, `captive_portal`,
`public_wifi`, `ipv6_first`, `ipv6_only`, `dns64_nat64`, `split_dns`, `proxy`,
`custom_dns`, and `other`. Add `environment.details` when using `other`.
Platforms use Go names: `linux`, `darwin` for macOS, and `windows`.

Assessments are `correct`, `mostly_correct`, `incorrect`, and `uncertain` and
describe the diagnosis stored by the producing version. Verification methods
are `controlled_change`, `independent_tool`, `configuration_review`,
`packet_capture`, `successful_remediation`, `provider_confirmation`, and
`other`.

## Adding a confirmed field report

1. Independently establish what happened and how it was verified. Simulator
   output is never a real field case.
2. Ask the reporter for a locally created `netdoc --support snapshot.ndoc ...`
   artifact. Never commit a raw `--save` snapshot or any other unsanitized
   real-user artifact.
3. Review both files manually. Remove private hostnames, addresses, SSIDs,
   usernames, paths, credentials, issue text, and confidential network details.
   Support redaction reduces risk but cannot prove an arbitrary string is safe.
4. Write `case.json`. Set the expected verdict, the exact finding list, and
   important forbidden findings from the independently confirmed condition.
5. Run `go test ./internal/fieldcase -count=1` and include both files in one
   focused review.

Validation discovers every case directory in filename order, rejects unknown
metadata fields and unexpected files, checks controlled vocabularies and
metadata consistency, decodes the current `.ndoc` schema, and requires canonical
snapshot bytes. Every fixture, including a synthetic bootstrap, must declare
`redaction.sanitized: true` with the current `support-v1` policy. Real fixtures
must also declare `real_network` provenance. The support marker is mechanically
required, but human privacy review remains mandatory.

Run only the replay harness with:

```sh
go test ./internal/fieldcase -run '^TestReplayCorpus$' -count=1
```
