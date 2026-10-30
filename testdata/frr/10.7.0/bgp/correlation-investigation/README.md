# BGP-to-FIB producer decision for issue #390

Decision status: awaiting maintainer / ChatGPT review. This is an investigation,
not a selected producer or an implementation of forwarding ratings.

Recommendation: select a version-pinned, FRR-side correlation exporter that
carries an explicit path identity through BGP submission, Zebra selection,
recursive resolution, and the dataplane operation/result. Retain the stock CLI
and kernel captures below as independent observations. None of the stock
collectors investigated supplies the entire required identity chain. If an FRR
extension is unacceptable, keep #390 deferred and forwarding impact unknown.
Do not substitute a prefix, gateway, AS path, or next-hop-group fingerprint.

## Repository state and scope

- Verified main: `ff3b1fbbad25aa5d3b0c66f01e725eeeaf4e71ed`.
- Original draft #407: `2fd17065f461f109a8820d843afe688651463615`.
- Local integration branch: `work/pr407-evidence`, worktree `.pr407-worktree`.
- The original root checkout remains on local `main` at `e5e2ea7`;
  `origin/main` was fetched and verified at `ff3b1fb`. No existing checkout
  was reset or fast-forwarded as a side effect of the investigation.
- Reconciliation: `19d8d38ded17c37da0afafb858b86efd9353dc14`, an ordinary
  merge of that main into the original draft. Both are ancestors. No rebase,
  history replacement, force push, merge into main, release, or deployment.
- All three original draft commits remain: `c87cdb1`, `c22bf6d`, `2fd1706`.
  The original `bridge/issue-287` worktree remains at its original commit.
- `worktrees.json` records the inspected worktrees and their dirty state.
  Existing PR 408/411 worktrees, baselines, temporary evidence, and the
  untracked tunnel runs in `issue-284` were left alone.
- Current HEAD still hardcodes unknown forwarding impact in
  `internal/app/frr_bgp_withdraw.go` and `frr_bgp_session.go`. No application,
  model, importer, rating, caller, or existing fixture is changed here. The
  additions are a research recipe, genuine captures, verification, and this
  decision record. Existing output compatibility tests remain applicable.

[Issue #390](https://github.com/heymaikol/network-doctor/issues/390) requires
maintainer selection before implementation.
[Issue #272](https://github.com/heymaikol/network-doctor/issues/272) explicitly
defers starting a broad Zebra RIB importer solely for correlation.
[Draft #407](https://github.com/heymaikol/network-doctor/pull/407) contains
capture groundwork, not that selection. Neither issue had supplied a selected
producer when inspected. PR comments contained automated status notices, not
maintainer selection or a substantive acceptance review.

## Live evidence

Runs took place on 2026-10-26 UTC, on the existing Linux x86_64 host, in
unprivileged user, mount, and network namespaces. No host route or configuration
was changed. The user explicitly requested live reproduction, superseding the
older lab README's restriction on automated-agent execution. `provenance.json`
records packages, executable hashes, commands, host, producer hashes, exit
statuses, and the source revision. The unsigned Fedora Koji RPMs have verified
header/payload digests; this is not a verified publisher signature. Their
container hashes differ from the older signed RPM hashes in the parent README.
Fresh extraction matched every executable used here.

Each accepted run printed `DONE` and exited 0. Each subdirectory retains its
original `SHA256SUMS`, checked against the complete copied set. Raw bytes were
copied unchanged. Poll files and `.err` files excluded by the original scripts
are retained in the workspace scratch runs, not silently promoted to evidence.
The outer manifest covers these original manifests and the investigation
metadata. The recipe's intentional failed route lookups keep `.status` and
`.stderr` files in their manifest.

| Capture | What was actually observed |
| --- | --- |
| `withdraw/` | Existing opt-in withdrawal script: before, after1, after2 BGP tables, kernel routes, and Zebra route tables. r2's `10.10.2.0/24` path disappears while r3's path remains; `10.10.9.0/24` disappears after its withdrawal; connected `10.10.1.0/24` remains. |
| `session-plain/` | Existing opt-in session script: before/after SIGKILL of r2 bgpd. Its paths disappear, r3 stays established, `10.10.9.0/24` disappears from Zebra and kernel. |
| `recursive-shared/` | Research recipe: a static `198.51.100.0/24` route and BGP `203.0.113.0/24` route both use recursive gateway `10.10.9.2`. r2 supplies the resolving BGP prefix `10.10.9.0/24`. Explicit withdrawal of that network leaves NHT unresolved and removes both dependent routes from Zebra and the kernel. |

The last run also makes r2 and r3 both AS 65002 and makes both advertisements
of `10.10.2.0/24` use next hop `10.0.1.2`. BGP detail lists two different peers,
identical AS paths and next-hop addresses, and `fibInstalled: true` on both.
Both are marked multipath; only one is the overall best path. Zebra prints one
FIB next hop and one duplicate next hop with no peer identity. This is a real
counterexample to reading a path-specific installation claim from those flags
or from the number of kernel next hops. FRR's default multipath support is
visible here; this is not a synthetic JSON mutation.

Other observed distinctions:

- Zebra's route JSON explicitly reports `selected`, `destSelected`, `installed`,
  `protocol`, and per-next-hop `fib`. These are separate facts. Its FIB view is
  still Zebra's view, not an independent kernel observation.
- The static and recursive BGP entries share a received next-hop-group ID, and
  both install the resolver's group ID. IDs represent shared forwarding groups,
  not BGP path or peer identities. The kernel's `nhid` confirms a group key in
  this namespace/run, not ownership by a BGP peer.
- Zebra NHT for `10.10.9.2` explicitly emits `resolvedProtocol: bgp` and
  `prefix: 10.10.9.0/24`. Separate resolution entries identify the static and
  BGP clients and their filtering/connected/default-resolution flags. After
  withdrawal it explicitly emits `unresolved: true` and no next hops.
- BGP's next-hop detail explicitly emits `resolvedPrefix` and dependent prefix
  records. Its cache-level `peer` field is not a per-path origin: the
  `10.0.1.2` cache lists the shared prefix twice, for paths from different peers.
- Ordinary `ip route get` returns a host lookup result; `fibmatch` reports the
  matched `10.10.9.0/24` kernel entry. Neither records which route FRR used to
  resolve another route. Both are corroboration, not the recursive attribution
  producer. The after-withdrawal lookups fail, with their actual exit status.
- The static route's kernel protocol label is the string `196`, while Zebra
  calls the route `static`. Never interpret an unrecognized kernel label as
  static. Collector-specific mapping is necessary even on this one host.

These observations establish what the collectors reported and the controlled
before/after changes. They do not establish a producer-emitted FIB-to-peer edge,
or prove a counterfactual prediction. No forwarding prediction is graded here
because no correlation semantics or producer has been selected.

## Candidate comparison

| Producer | Completeness and correctness | Provenance / portability | Fail-closed decision |
| --- | --- | --- | --- |
| BGP summary/table + kernel `ip -j route` | Paths and kernel entries, but neither explicit ownership nor FRR recursion. Kernel next hops are flattened. | Original CLI bytes and kernel JSON; kernel adapter is Linux-specific. | Retain context; no path-to-FIB claim. |
| BGP detail including `fibInstalled` + Zebra route/FIB JSON | Actual BGP peer records and Zebra selection/install flags, but installation flag belongs to a BGP destination. No installation-generation/path token crosses the two outputs. | Genuine FRR 10.7.0 CLI with source-backed field meanings; separate snapshots. | No per-path installation credit, including single-bestpath cases without an explicit edge. |
| `bgp send-extra-data zebra` | Copies AS path, communities, large communities, and selection reason from the best path. No peer, add-path ID, or installation generation; strings can be shared and buffers truncate. Does not describe all ECMP contributors. | FRR-specific opt-in; changing the option does not reinstall existing routes. Enabled before paths arrived in the research run only. | Supplementary attributes, never an identity join. |
| Zebra NHT + route/FIB JSON + BGP next-hop detail | Best stock recursive evidence: explicitly names resolving prefix/protocol and client. Does not name a consuming route instance or the resolver's originating BGP path/peer. Client filtering and flags can yield different resolutions for one address. | FRR-specific but no kernel API required to read CLI; raw command, node/VRF, time window required. | Accept the narrow statement "this NHT client resolved this gateway via this prefix". Do not promote it to an installed-row-to-peer edge. |
| Zebra NHG JSON + kernel NHIDs | Explicit group references, recursion/duplicate/group state; forwarding groups are shared across prefixes, protocols and paths. | IDs scoped to daemon/kernel epochs and namespace; kernel IDs are Linux-specific. | Useful group corroboration, no route-owner identity. |
| BMP plus FPM or standard ZAPI capture | BMP supplies BGP peer/path state; FPM supplies forwarding updates. Standard route ZAPI/opaque data lacks a selected BGP peer/path token. Joining streams by prefix/NH adds no missing identity or atomicity. | Versioned binary decoders, stream loss/replay handling, configured services; FPM can use netlink or protobuf. Source-reviewed, not live-captured in this investigation. | Reject as a complete producer without an added cross-layer identity. |
| Injected per-peer community/tag plus opaque data | A controlled label could carry single-bestpath provenance if enforced and recorded; ordinary communities are spoofable/shared, and bestpath opaque data does not label each multipath leg. Does not solve recursion or installation-generation races. | Requires modifying routing policy and reserving/stripping labels, changes operator configuration, version-specific behavior. Not exercised. | Not recommended for arbitrary imported networks or transparent collection. |
| FRR-side identity exporter | Can expose actual object relationships, every contributing path, resolution choices, and operation-specific install results. Requires an implemented and independently tested FRR extension. | Pinned FRR build/module and schema; Linux kernel ACK corroboration initially. No general Zebra importer needed in Network Doctor. | Recommended producer design; unsupported builds, missing edges, races, gaps or failures remain unknown. Not implemented or proven by these captures. |

## Source verification

`sources.json` pins `frr-10.7.0` to commit
`87fe21fda92ce9e2ba3eaf2b0a327bf71ee183ef` and hashes the files inspected.
Line references below refer to those downloaded files, not rolling docs.

- [BGP opaque schema](https://github.com/FRRouting/frr/blob/87fe21fda92ce9e2ba3eaf2b0a327bf71ee183ef/lib/route_opaque.h):
  `bgp_zebra_opaque` has attribute strings, not path/peer identity.
- [BGP Zebra submission and notification](https://github.com/FRRouting/frr/blob/87fe21fda92ce9e2ba3eaf2b0a327bf71ee183ef/bgpd/bgp_zebra.c):
  lines 1674-1700 copy bestpath attributes into opaque data;
  `bgp_zebra_route_notify_owner`, lines 3046-3098, looks up a destination and
  sets its installed flag, then finds the currently selected path.
- [BGP path rendering](https://github.com/FRRouting/frr/blob/87fe21fda92ce9e2ba3eaf2b0a327bf71ee183ef/bgpd/bgp_route.c):
  lines 13684-13703 render destination flags into each detailed path record.
  Therefore path-local JSON placement does not make this path-local state.
- [Zebra route rendering](https://github.com/FRRouting/frr/blob/87fe21fda92ce9e2ba3eaf2b0a327bf71ee183ef/zebra/zebra_vty.c):
  lines 548-577 distinguish selection/install fields; lines 638-675 render
  groups, next hops and opaque attributes without a BGP peer identity.
- [Zebra NHT rendering](https://github.com/FRRouting/frr/blob/87fe21fda92ce9e2ba3eaf2b0a327bf71ee183ef/zebra/zebra_rnh.c):
  lines 1337-1452 group clients by recorded resolution and emit the resolving
  prefix/protocol plus per-client flags. It is not an arbitrary route lookup.
- [BGP NHT rendering](https://github.com/FRRouting/frr/blob/87fe21fda92ce9e2ba3eaf2b0a327bf71ee183ef/bgpd/bgp_nexthop.c):
  lines 803-861 list dependent prefixes without per-path peer IDs;
  lines 1025-1041 emit cache-level peer and resolved prefix.
- [FPM documentation](https://github.com/FRRouting/frr/blob/87fe21fda92ce9e2ba3eaf2b0a327bf71ee183ef/doc/developer/fpm.rst)
  and [ZAPI route schema](https://github.com/FRRouting/frr/blob/87fe21fda92ce9e2ba3eaf2b0a327bf71ee183ef/lib/zclient.h)
  describe transport/forwarding records, not an end-to-end BGP path identity.

## Exact proposed producer and format

Proposed producer name: `netdoc-frr-correlation`, schema version `1`, initially
only FRR 10.7.0 IPv4 unicast in one recorded Linux network namespace and VRF.
This is a requested design decision, not a claim that such an exporter exists.
Do not call a polling sidecar that fingerprints stock outputs this producer.

The extension must record identities at these ownership boundaries:

1. In `bgp_zebra_announce_actual`, enumerate the actual contributing
   `bgp_path_info` objects and their peers, not just `info`'s opaque attributes.
   Allocate an announcement token that includes the bgpd instance epoch and
   generation. Carry that token and per-leg path IDs across ZAPI into Zebra.
2. Preserve those references on the specific Zebra route entry through
   replacement/selection. Carry its route generation into the immutable
   dataplane operation context and record the matching operation result, not
   a later destination-level notification. IDs must survive neither daemon
   restart nor route replacement silently. NHG deduplication must retain the
   complete contributor set rather than choosing an arbitrary peer.
3. At actual next-hop resolution, record the consuming route/leg ID, relevant
   VRF/table and lookup flags, and the selected resolving route ID/generation.
   Record every recursive edge until a terminal adjacency. Preserve a static
   route's static origin while recording a separate dependency on BGP.
   NHT cache output is corroboration, not a substitute for this object edge.
4. On Linux, bind the dataplane operation to its netlink sequence/result and
   installation generation. Capture the independently dumped kernel row,
   NHGs, rules, table, and namespace with its selector. A later kernel match
   alone does not acknowledge the earlier operation or prove continuing state.

Emit one bounded JSON bundle, with these mandatory record collections:

| Field | Required contents |
| --- | --- |
| `schema`, `producer` | Name/version, FRR source/build and patch hashes, executable hashes, supported feature flags and explicit origin-label mapping version. |
| `capture` | Bundle/run ID, host/namespace identity, kernel boot ID, daemon instance epochs, VRF/table, AFI/SAFI, UTC start/end, monotonic range, generation fence, record/byte bounds, completeness and event-gap status. |
| `sources` | Exact command or hook, daemon/node, start/end, exit status, raw-byte path, SHA256 and record pointer. Source references accompany every fact and edge. |
| `bgp_paths` | Epoch-scoped path ID and update generation, peer ID plus session epoch, peer address/local and remote AS, VRF, AFI/SAFI, prefix, received add-path ID when applicable, local-origin marker, validity/staleness, selected/multipath membership. |
| `routes` | Epoch-scoped Zebra route ID/generation, raw origin label, mapped origin, table/VRF, prefix, selection and installation states; announcement/path references as recorded by the submitting producer. |
| `fib_entries` | Kernel row selector and all forwarding legs, Zebra route/generation reference, dataplane operation ID, ACK status/sequence and generation, independent raw kernel reference and coverage/fence status. |
| `resolutions` | Consuming route/leg ID, gateway and lookup context, resolving route ID/generation, intermediate edges, terminal adjacency, per-client filtering/flags and explicit unresolved state. |
| `claims` | Typed edges `path_submitted_as_route`, `route_installed_as_fib`, `route_leg_resolved_by_route`; each names actual producer IDs and source references, or an explicit unknown/refusal reason. No generated join from equal attributes. |

This is a data contract proposal, not a synthetic fixture presented as live
evidence. The first implementation should refuse unimplemented feature flags
(EVPN/VPN, cross-VRF recursion, add-path, ECMP, GR, etc.) until their complete
identity handling has its own proof. A captured shared group or recursive edge
does not waive those requirements.

Use a named allowlist for FRR labels: `bgp` -> BGP, `ospf` -> OSPF,
`connected` -> connected, `static` -> static, `local` -> local. Only BGP and
OSPF are protocol origins in the current model. An unknown label, numeric
kernel label, unsupported collector version, or conflicting origin is unknown
or refused; it must never fall through to static. Keep raw labels and sources.

Claims this design could prove, once implemented and validated: the source peer
of each recorded contributing path; that exact route generation's acknowledged
installation; the explicitly recorded resolution chain, including static via
BGP; and which recorded dependency a withdrawal/session loss would remove.
It cannot by itself prove packet delivery, hardware offload, post-capture
state, convergence, an unseen alternate path, or the eventual forwarding
rating. Those require separate evidence and conservative semantics.

Non-atomic CLI brackets, even equal endpoints, cannot exclude an intervening
change and return. Fail closed on an absent/ambiguous edge, mixed daemon epoch,
generation mismatch, pending/failed install, incomplete multipath membership,
unresolved/filtered recursion, capture gap, or unsupported feature. A future
rating also needs evidence for replacement behavior; removing a proven source
path does not automatically prove lost reachability.

## Validation and next gate

`python3 -I verify.py` checks complete manifests, strict JSON framing, observed
route/session changes and the live ambiguity/recursion counterexamples. It
checks recorded facts, not forwarding ratings. `provenance.json` records the
run results. The canonical `./scripts/check` passed after moving `TMPDIR` to the
workspace; its initial attempt hit `/tmp` disk quota, not an assertion failure.
The scripts are syntax-checked separately. Existing legacy-output and BGP
capture tests pass with the unchanged product code.

GR/admin enhanced labs, BMP/FPM wire collection, an instrumented FRR build,
IPv6, other operating systems, real packet delivery and generation-fenced
cross-layer joins were not validated here. Earlier research attempts remain
under `.pr407-tmp/live-probe*`; failed/incomplete runs were not promoted. One
early successful exploratory bracket still showed the resolver after address
deletion, so the accepted recipe uses explicit network withdrawal plus bounded
polling; it makes no convergence-time claim.

Stop here for ChatGPT review of the proposed FRR-side producer and contract.
Do not implement forwarding correlation or broaden the Zebra import before
that selection. Do not merge PR #407 or close #390 on this evidence alone.
