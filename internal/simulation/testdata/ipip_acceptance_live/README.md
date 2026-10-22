# Live IPIP acceptance evidence (DRAFT, no captures recorded)

**Status: draft. Nothing here has been run on a real host. No capture directory
exists yet, and nothing is authoritative for #405.**

The cases are `TestIPIPAcceptanceAgainstLiveNamespaces` in
`failure_ipip_netns_linux_test.go`. They build the GRE import diamond with a
configured `ipip1` tunnel from r1 to r3, and grade the overlay for two faults:

- `ipip underlay leg down pinned`: r1's s14 leg, which the tunnel's outer packets
  are pinned to, goes down. Expected: overlay `unknown`, and no dial crosses after
  the fault.
- `ipip tunnel device down`: r1's `ipip1` goes down. Expected: overlay
  `reachability_lost`, and no dial crosses after the fault.

The expected grades are fixed in `ipip_acceptance_manifest_test.go`. They are not
read back from the simulator. The importer still refuses the configured ipip
devices, and the case checks that refusal. No production IPIP record is enabled.

## Prerequisites

- Unprivileged user and network namespaces. Without them the case skips, or fails
  when `NETDOC_SIM_REQUIRE_NETNS` is set.
- The `ipip` kernel module loaded, which the case checks at `/sys/module/ipip`.
  Without it the case skips, or fails under `NETDOC_SIM_REQUIRE_NETNS`. Load it
  with `sudo modprobe ipip`. The case does not load it itself.

## How a real run would be made

    go test -tags netns_integration -count=1 -v -timeout 10m \
      -run '^TestIPIPAcceptanceAgainstLiveNamespaces$' \
      ./internal/simulation -args -tunnel-import-evidence <directory>

`<directory>` must be empty or absent for each case. A case writes only into its own
subdirectory, and `writeTunnelEvidence` refuses a directory that already holds files.

## Expected layout

Each case writes to `<directory>/ipip-acceptance/<case name with dashes>/`:

- `ip-link-rN.json`, `ip-rule-rN.json`, `ip-addr-rN.json`, `ip-route4-rN.json`,
  `ip-route6-rN.json` for N = 1 to 4: the output of the five commands the importer
  reads, as read, one set per router.
- `metadata.json`: per capture, its source label, node, exact command, the UTC time it
  ran, and its file name.
- `base-topology.json`: the topology the import merged onto, with no tunnel records.
- `outcome.txt`: first the two tunnel records the test constructed, with their source
  and collection time, which are the records the simulator was graded with. Then the
  import's own decision (refusals, rules proven, tunnel records, inert fallbacks), then
  the path state and dial table for each fault.
- `SHA256SUMS`: written last. It covers every other file in the case directory.

Verify one case with:

    cd <directory>/ipip-acceptance/ipip-underlay-leg-down-pinned && sha256sum -c SHA256SUMS

## What this does not show

- It is one lab namespace on one host, not a real network.
- The tunnel records are read from the kernel by the test, not proven by the
  importer. That is the point of this draft: it does not lift the ipip refusal.
- Each capture is one moment. The collection window narrows how far apart a node's
  captures can be, but it is not an atomic snapshot.
