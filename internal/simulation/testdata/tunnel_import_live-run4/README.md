# Live tunnel import evidence, run 4 (authoritative for #389, pending review)

Captures from the four live netns cases of the #389 tunnel import, written by
`TestTunnelImportAgainstLiveNamespaces` and `TestStructuralFailureAgainstLiveFaults`
with `-tunnel-import-evidence`, from the tree described below.

**Status: selected as the authoritative live evidence for #389, conditional on the
final verification in the review report. Not committed, pushed, or merged.**

Earlier runs are not part of the patch. `tunnel_import_live/` (run 1),
`tunnel_import_live-run2/` (run 2), and `tunnel_import_live-run3/` (run 3) are
historical and are kept as made until cleanup is authorized. Run 2 is not for shipping.
Run 3's README says it is historical and superseded by this run. Earlier run 4 captures,
made before the corrections and the echo audit, are superseded. Archived copies of all
of them, with checksums, are kept outside the repository.

## How it was made

    go test -tags netns_integration -count=1 -v -timeout 20m \
      -run 'TestTunnelImportAgainstLiveNamespaces|TestStructuralFailureAgainstLiveFaults' \
      ./internal/simulation/ -args -tunnel-import-evidence <this directory>

- Collected: 2026-10-21, 19:30:59 to 19:31:09 UTC. The time each command ran is in its
  case's `metadata.json`.
- Tree: branch `bridge/issue-284`, base HEAD `797eac0`, with the #389 changes uncommitted.
  The review patch lists them. Nothing committed.
- Kernel `7.2.10-200.fc44.x86_64`, `ip utility, iproute2-6.17.0`. Rootless `unshare -Urn`
  lab, no host interface or route changed.

## What changed from the superseded run 4

- Every capture of a node must fall within 250 ms of the others, from the earliest
  collection time to the latest. A wider spread refuses that node's fallbacks. This
  applies to fallback evidence only; gre records do not read it. The largest spread
  in this run is 27.0 ms.
- The rule refusal for a policy rule with a key the import does not read now says
  that, instead of "is not ip -j rule show output, or ...".
- The policy-rule line of the import's NotImported list is reworded. A rules problem
  refuses every gre device of its node and each kernel fallback gre0, gretap0, erspan0,
  or tunl0 of it. A gretap, erspan, or ipip device that is not an inert fallback is
  refused by its kind whatever its rules. This is text only; the decisions are unchanged.
- Strict parsing refuses JSON `null` where iproute2 never prints one, and refuses a
  linkinfo with a null kind or with info data and no kind. Any other linkinfo with no
  kind is read as a device with no kind, and accepted only when its link type is
  `ether` or `loopback`. That covers a bridge or VRF port whose linkinfo carries only
  `info_slave_kind`. No live capture here shows that shape; a unit row covers it.
- Refusal text no longer echoes names from the capture: VRF names are not echoed, and
  a kind or link type is quoted only when it has the shape of a kernel name.

Compared block by block with timestamps removed (the import's decision lines, from the
top through "without a usable capture"):

- Against the pre-correction superseded run 4: tunnel-device-down,
  underlay-leg-down-pinned, and underlay-leg-down-unpinned are identical.
  steering-rule-refuses-the-tunnel differs only in the rule refusal text. The same
  tunnels are recorded and the same fallbacks are inert.
- Against the echo-audit superseded copy, made after the rule-text fix and before the
  echo and bridge-port changes: all four decision blocks are identical.
- Against the pre-final copy, made before the policy-text wording above and before the
  case-variant unit tests: all four decision blocks are identical. The full outcome
  files are identical once timestamps, netns interface names, MAC addresses, and
  RX/TX counters are removed.

## What each case directory holds

- `ip-link-rN.json`, `ip-rule-rN.json`: `ip -d -j link` and `ip -j rule show` output
  for node rN, as read.
- `ip-addr-rN.json`: `ip -j addr show` output for node rN, as read.
- `ip-route4-rN.json`: `ip -4 -j route show table all` output for node rN, as read.
- `ip-route6-rN.json`: `ip -6 -j route show table all` output for node rN, as read.
- `base-topology.json`: the topology the import merged onto.
- `metadata.json`: per capture, its source label, node, exact command, the UTC time
  that command ran, and its file name.
- `outcome.txt`: the import's own decision first (refusals, nodes whose rules are
  proven, tunnel records, inert fallbacks, unproven and uncovered lists), then for the
  fault cases the path state and dial table, each path header stamped in UTC.
- `SHA256SUMS`: written last. It covers every other file in its case directory and
  nothing else.

Verify one case with `cd <case directory> && sha256sum -c SHA256SUMS`. All four cases
verify as written.

## What is not in the evidence

- The simulator's predictions are not saved here; the test grades them against the
  dial table in `outcome.txt`.
- Lab only. The devices and rules are those of a fresh rootless namespace, not a real
  host.
- Each capture is one recorded moment. The collection window narrows how far apart
  the captures of one fallback's node can be, but the captures are not one atomic
  snapshot. A change inside the window is not excluded, and a configuration change
  during collection is not excluded either. Nothing here shows the links staying in
  that state.
- Timestamps, netns interface names, MAC addresses, and counters differ from run to
  run. The decisions do not.
- A bridge or VRF port with no kind of its own is accepted on the strength of its
  `info_slave_kind` shape. No live capture here shows one; the shape is covered by a
  unit row only.

## Source fingerprint

Taken on the final tree, after the last code and documentation edit and the last
mutation pass:

- `git diff HEAD | sha256sum`: `192a92a37b79bad1d6fda64d1b8bb6171e018af3b0985655bda6375b20a4e8f0`
  (tracked files only)
- the eight untracked Go files of the #389 work (`internal/app/tunnel_import*.go`,
  `internal/routepath/tunnel_fallback*.go`, `internal/routepath/tunnel_import*.go`,
  `internal/simulation/failure_tunnel_netns_linux_test.go`,
  `internal/simulation/tunnel_evidence_test.go`), hashed per file with `sha256sum` in
  path order, then that output hashed together:
  `a245e4b4ed3f0f8267281d048529f29b91b8bdcc1e3e2a28827d33d90a7a249e`
- the routepath fixtures under `internal/routepath/testdata/tunnel_import/`, hashed the
  same way: `d13990a5356a183436a61cda0ad43b52c3aabd9ef820fd53719154467045712e`

Any tracked or untracked source edit after this point changes these values.
