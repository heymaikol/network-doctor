# Corrected producer candidate

This directory records a candidate certificate for build
`9a522b455f6347b1ce25a3cda9b6cc3bd6afb0e4f35aab1420928829935be454`.
It does not activate that build in the existing packager installation.
The historical `../../verified-build.json`, `../../verified-builder.json`,
implementation pin and historical captures remain unchanged.

`verified-build.json` pins the corrected artifacts, source archive,
instrumentation, package lock, configure/compiler inputs and verified kernel.
Its SHA256 is
`6e92a1575e9bad88e59436e16814820877ba8b25d72b5b4761047f9d00dab749`.
`certification.json` records the builder profile, two fresh build identities,
artifact comparisons and fresh capture validation. This is provenance for
independent review, not approval to merge, publish a certificate or enable an
importer.

## Reproduction

The corrected producer source is PR #407 commit
`dcd12e633731cef009adf53d23084c34842edef9`. The portable refusal test is separately
committed as `2cbee21099d047e92fd5bba19f82bc7357ab2453`; it changes no producer or
packager behavior.

Two fresh clean builds in separate containers, `build-a` and `build-b`, used
reconstructed builder config
`34d4b82aaa526fa57cc5db550cd22a9d6da242d29e5fbdedcb9b2ff13934248b`.
Both verified the entire unchanged RPM lock and actual copied instrumentation.
Compilation ran as UID/GID 65534, rootless, offline, with all capabilities dropped,
no-new-privileges, read-only root/source/archive and dedicated writable scratch.
The full eight-artifact manifests are byte-identical.

The original Containerfile and pinned Fedora base were unchanged. Reconstruction
required a temporary read-only repository containing four unavailable exact
Fedora-signed RPM versions. Signature verification was retained. The resulting
image identity differs from the original recorded builder, and OCI export has a
different manifest representation from the stored image. These distinctions are
recorded in `certification.json`. Original image bytes were not reproduced.

Six corrected artifact digests equal their historical pins: `vtysh`, `zebra`,
`staticd`, `mgmtd`, `libmgmt_be_nb.so.0` and `libyang.so.3`. `bgpd` and
`libfrr.so.0` differ: `bgpd` contains the corrected transport guard, and libfrr's
start record embeds the newly derived build ID. The build ID changes because
the instrumentation digest is an input. Equality with every historical binary
is neither expected nor claimed;
a fresh historical-source rebuild was not performed.

The corrected hook refuses unsupported peer families before reading IPv4 socket
storage or exporting a contributor. It leaves the existing IPv4-only evidence
contract and path/session/route/operation identity rules intact.

## Separate installation and trust decision

The existing packager reads exactly one `verified-build.json` beside its own
trusted code. It has no build selector. Its installed historical manifest still
refuses the corrected build. This directory is not searched automatically.

Validation used a separate operator-controlled installation containing
byte-identical approved `bundle.py` and `schema.json`, with this candidate copied
to that installation's adjacent `verified-build.json`. Capture/output authority
still came only from inherited directory descriptors 3 and 4. No request supplied
a manifest path, and accepted builds in the historical installation were not
expanded. See [the existing filesystem authority model](../../SECURITY.md).

Accepting or publishing this candidate is an explicit trust decision for final
independent review. Any activation must preserve the historical installation and
its certificate; replacing its manifest in place is not part of this change.
Supporting multiple builds in one installation would require a separately
reviewed versioning/selection design. No such implementation is included here.

## Fresh acceptance and historical separation

Fresh complete daemons from `build-a`, byte-identical to `build-b`, produced new
captures using the unchanged supported IPv4/recursive/withdrawal lab and an
isolated dual-family transport test. Candidate packaging validates against the
unchanged schema and proves the same-route/generation BGP-to-operation chain
and static-to-BGP recursive edge. Real IPv6 transport carrying IPv4 NLRI
establishes, but receives refusal and no BGP attribution edge. An independent
Zebra-to-kernel historical operation fact can remain without BGP attribution.

The unchanged historical captures reject through the candidate installation with
exit 2 and no claims. The historical installation still accepts them with their
original build ID and 25 historical edges, and rejects the new captures with exit
2 and no claims. Input file digests were checked before and after packaging.
`certification.json` pins the fresh raw identity streams and records the results.

This separation verifies unchanged capture bytes and fixed installation pins.
Capture headers are not signed execution attestations. Trusted same-run collection,
stable post-exit bytes and retained diagnostics remain required. Boot/inode
equality is not namespace-lifetime or capture-cohort authentication. No current
FIB, packet-delivery, convergence or GR retained-forwarding claim is enabled.

Full logs, actual corrected artifacts, raw fresh captures and the reconstructed
OCI builder are retained in the accompanying independent validation evidence.
Native locked-builder tests and live routing are separate from the pinned CI
ASan/UBSan regression lane. No whole-FRR leak-freedom claim is made.
