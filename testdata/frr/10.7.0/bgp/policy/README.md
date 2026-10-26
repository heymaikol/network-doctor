# Live route-policy evidence

The 2026-10-25 UTC run used genuine FRR 10.7.0, three isolated routers, and
`lab/bgp-policy.sh`. It finished with `DONE`. `provenance.json` records the exact
invocation, package URLs and SHA-256 digests, executable digests, producer file
digests, Git reconciliation commit, router identities, VRF, and address family.
No host route or installed FRR package was changed. No capture is synthesized.

The downloaded RPMs are the unsigned Fedora Koji builds, with verified RPM
header and payload digests. Their package hashes differ from the earlier lab's
pins in the parent README. They are explicitly different artifacts of the same
10.7.0 build, not represented as matching those pins. HTTPS and checksums give
source and integrity evidence; the unsigned RPMs have no verified signature.

## Authoritative policy producer, chosen before implementation

The source for policy semantics is bgpd's **enable-mode** `show route-map json`
and `show ip prefix-list json`, preserved verbatim with the echoed command,
CRLF, and `r1# ` prompt. The before outputs are empty JSON objects. Afterward,
`R3-IN.rules` contains sequence 10, permit, match clause
`ip address prefix-list P10-2`, set clause `weight 100`, and action
`Exit routemap`; sequence 20 permits everything else without a set clause.
`P10-2` is IPv4 and permits exactly `10.10.2.0/24` at sequence 5.

The baseline `show ip bgp neighbors 10.0.3.3 json` establishes peer identity and
session state; its after counterpart independently records
`addressFamilyInfo.ipv4Unicast.routeMapForIncomingAdvertisements` as `R3-IN`.
`show ip bgp json` records candidate paths and bestpath flags. These are control
plane observations. Kernel `ip -j -4 route show table main` is an independent
forwarding observation, captured on all three routers in both phases.
Running configuration and the policy-change transcript supply audit context;
they will not be parsed for policy semantics.

The strict topology extension will embed raw transcripts with a named source,
UTC collection time, exact command, FRR version, and SHA-256, alongside the
node, VRF, direction, peer, and policy identifier. It will accept only the
verified JSON subset: ordered permit/deny rules, exact IPv4 prefix-list matches,
terminal actions, and weight assignments. Unsupported actions, incomplete
clauses, ambiguous matches, contradictory identities, and unknown peers must
be refused. Route recomputation and BGP-to-FIB correlation remain unproven.
No replacement route may be inferred from these captures.

An initial unmodified run also finished successfully in
`/tmp/netdoc-pr408-frr/run/bgp-policy`. An intermediate attempt to collect JSON
at the non-enabled prompt failed, preserved under
`/tmp/netdoc-pr408-frr-json/run/bgp-policy`; FRR printed `Unknown command`.
The committed run uses enable mode and passed without relaxing any original
route, weight, session, or configuration assertion.

## Independent observations

| Observation | Before | After |
| --- | --- | --- |
| r1 bestpath for 10.10.2.0/24 | peer 10.0.1.2 | peer 10.0.3.3 |
| r1 weight for that prefix from 10.0.3.3 | 0 | 100 |
| r1 kernel route for that prefix | gateway 10.0.1.2, e1 | gateway 10.0.3.3, e3 |
| r1 other prefix bestpaths and kernel routes | recorded | unchanged |
| r1 candidate path identities | six paths for four prefixes | unchanged |
| r2 and r3 kernel routes | recorded | byte-identical |
| r2 candidate for 10.10.2.0/24 via r1 | absent | added, unselected, AS path 65001 65003 |
| r3 candidate for 10.10.2.0/24 via r1 | present, AS path 65001 65002 | removed; local bestpath unchanged |

`TestPolicyLiveObservedChanges` grades the observations separately from the
producer's assertions. The existing lab checker grades the before/after BGP
expectations too. This establishes the evidence source; simulation grading is
added with the implementation. It proves no delivery, convergence-time, or
production-network claim.

## Reproduce and verify

Download the two package URLs from `provenance.json`, verify their SHA-256,
and extract them together with `rpm2cpio` and `cpio` into `$SCRATCH/frr-root`.
Use a fresh scratch directory on a Linux host with unprivileged namespaces:

```sh
SCRATCH="$SCRATCH" BGPD_VTY_PORT=2605 timeout 900 unshare -Urnm bash testdata/frr/10.7.0/lab/bgp-policy.sh
```

The run itself checks 66 files. The committed copy additionally includes
`terminal.log` and `provenance.json`, with all 68 files covered by `SHA256SUMS`.
Each capture has its own UTC timestamp taken just before querying the daemon.
The command, prompt, router ID, local AS, and peer address identify its source.
Raw transcripts keep their original bytes under `.gitattributes` `-text`.

```sh
(cd testdata/frr/10.7.0/bgp/policy && sha256sum -c SHA256SUMS)
go test ./internal/app -run 'TestPolicy(Live|Check|Lab)' -count=1
```
