# Live configured IPIP acceptance evidence

The `before-import` cases were captured from real rootless Linux network
namespaces before configured IPIP import was enabled. `provenance-before.json`
records the exact source commit, command, required environment, kernel and tools.
Both IPIP cases, all four GRE cases and all three WireGuard cases passed with
`NETDOC_SIM_REQUIRE_NETNS=1`; none skipped a prerequisite.

The physical s14 underlay link fault leaves the overlay grade `unknown`, while
taking `ipip1` down grades it `reachability_lost`. The overlay delivers before
both faults and fails to deliver after each. `outcome.txt` holds the actual
before/after route lookups, link counters, timestamps and delivery observations.
Each case has raw device, address, rules and route JSON for all four routers,
`metadata.json` with per-command provenance, and `base-topology.json`.

The pre-import run deliberately verified that the production importer still
refused configured IPIP. Its simulator tunnel records were constructed by the
test from the live captures, as each outcome states. These historical observations
are preserved byte for byte and must not be described as importer proof.

Reproduce using the command in the provenance file at its recorded commit, with
an empty evidence directory. The host needs unprivileged user/network namespaces,
iproute2, the IPIP and GRE kernel facilities, and WireGuard plus `wg` for the
regression cases. The harness changes only its disposable namespaces and does
not load modules or elevate host privileges.

Verify each case by running `sha256sum -c SHA256SUMS` inside its directory.
The captures contain only lab addresses and no WireGuard dumps or private keys.
They are a controlled namespace experiment on one kernel, not field validation
or an atomic snapshot of a changing production network.

## Production import acceptance

The `imported` cases run the same faults using the records returned by
`ImportTunnels`, not test-constructed simulator records. They require a complete
import, two IPIP records with matching source/time and kernel device attributes,
four proven rule sets and inert `tunl0` devices. The records pass through the real
merge and topology encode/decode before grading. Both IPIP cases and all GRE and
WireGuard regressions passed without skips.

`provenance-imported.json` records the source parent and a reproducible hash of
the exact Go sources built for this run, alongside the environment and command.
The capture was made from the implementation working tree before committing its
fixtures; the recorded source hash excludes evidence files. Each capture retains
its actual collection time and exact command in `metadata.json`.

`TestIPIPCommittedEvidence` verifies each case's checksums and replays both the
historical and production capture imports and fault grades offline. Its fixture
checks do not replace live acceptance. The root `SHA256SUMS` additionally covers
all committed evidence, provenance and this README. Verify it from this directory
with `sha256sum -c SHA256SUMS`. Raw counter output retains iproute2's trailing
spaces so the recorded bytes and case checksums are unchanged.
