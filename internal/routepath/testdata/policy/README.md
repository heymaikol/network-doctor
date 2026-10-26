# Policy replay topology

`topology.json` is an offline projection of the genuine FRR lab committed in
`testdata/frr/10.7.0/bgp/policy`, with no invented replacement route.

For each node, its FIB observation comes from `NODE-before-ip-route.json`,
with that file's collection time and source name. Every route keeps `dst`,
`protocol`, `dev`, and `gateway` when present. Each connected route with
`prefsrc` contributes that exact address, with the destination prefix length,
to its interface. Kernel nexthop IDs and metrics are not needed by the walk.
No packet-delivery checks or physical link claims are added.

The `route_policies` entry embeds r1's before table and before neighbor
transcripts, followed by its after route-map and prefix-list JSON. Each raw
string decodes to the original `.raw` bytes, including CRLF and prompt, and
carries the original timestamp and verified SHA-256. The policy definition is
the proposed change, so its timestamp is later than the baseline captures.
The top-level source is r1 in the default VRF. The lab's separate after BGP and
kernel observations grade the predictions; they are not simulation input.

The evidence README records the exact producer invocation and package identity.
`TestPolicyReplayUsesPreservedRawBytes` verifies the embedded transcript bytes
against those captures. `TestExplainPolicyPredictionGradedAgainstLiveFRR`
grades selected-path predictions independently against the after table.
