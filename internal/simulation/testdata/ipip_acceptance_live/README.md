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
