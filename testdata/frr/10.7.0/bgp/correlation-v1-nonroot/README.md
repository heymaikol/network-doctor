# Non-root locked builder certification

Baseline PR head: dfbd4b30ccdd2daa0bce4f18bef384de2ebae4a9.
Integration main: 823a91611592c5949d7cb37b26bdf547443cf063.
This evidence certifies a changed build environment. No earlier capture,
build artifact, manifest, source verifier or image is replaced.

## Actual correction and threat model

The prior image defaulted to UID 0 after package installation. Rootless Podman
limited its host authority but did not remove root's privileges inside a writable
container or make broad mounts and network access safe. S6471 therefore identifies
a real least-privilege concern, not a warning dismissed solely because of rootless
execution. Containerfile now finishes with USER 65534:65534, the existing nobody
account. Privileged RPM installation is the only root build step. No new package
or account-creation dependency is added, and the complete RPM lock is unchanged.

The certified compile/test profile uses rootless Podman, the non-root image
default, no network, a readonly container root, readonly source/archive mounts,
a dedicated writable scratch mount, all capabilities dropped, no-new-privileges
and a private nosuid,nodev /tmp tmpfs. keep-id maps the invoking host user's
scratch access to the non-root container identity without host chown. The image
and recipe hashes and required profile are in verified-builder.json.

isolation.json records UID/GID 65534, zero effective/permitted/bounding/ambient/
inheritable capabilities, NoNewPrivs=1, refused source/repository/archive/root
writes and a successful scratch write. Its network namespace differs from the
actual launching host namespace. All-table IPv4/IPv6 dumps contain only loopback
routes. This kernel also creates gre0, gretap0, erspan0 and tunl0 in new namespaces;
the probe checks all those links are administratively down. An initial lo-only
assertion was investigated and replaced with actual flags, all-table routes and
namespace assertions. No external interface, connection or host route is created.

The profile does not eliminate shared-kernel vulnerabilities or make malicious
compiler input trustworthy. A compiler can read mounted sources and alter allowed
scratch output. The operator must not mount host sockets/secrets or enable
rootful, privileged, broad writable-mount or networked compilation. Such launches
are outside this certification. Default non-root identity is a real reduction in
privilege, not a claim that rootless containers provide universal isolation.

## Builder, packages and reproducibility

New image configuration ID:
3806db6332b838c627a3693d3e7861c47371137e20eb9208755506cd83bc7ad2.
New image manifest digest:
sha256:67a80138645044df127765177335ad30e3ee175c1e9134c0b0836df98b99e00e.
Default user: 65534:65534.

Historical image configuration ID, preserved under its original local tag:
67e00e0327159ba2368a72bc96db80d52d17d0f91020d3544b9d366c71d6a9ff.
Historical manifest digest:
sha256:2a735793e2a529b3d83f553fe779f144c932e0eb7d9465cefa663b8ae0a3acef.
Its original recipe and evidence remain in baseline ancestry and prior directories.

The pinned Fedora base and exact existing RPM versions provision successfully.
Offline image provisioning initially failed because package metadata requires
repository access; the successful bootstrap uses network only for package
retrieval and verifies the entire resulting package database against the lock.
Both subsequent FRR builds and all compile/test commands run with --network=none.
No package substitution, lock update or scanner configuration change is made.

Two independent fresh source directories, nonroot-a and nonroot-b, produce
identical build.json files and byte-identical results for all eight artifacts.
Every artifact also matches the existing verified-build.json checksum. Both
builds compile and pass the actual libfrr wire codec suite with assertions enabled.
The current writer test is freshly compiled and passes all 27 original modes.

FRR build ID therefore remains:
89f0152ef221c716119b8b739a6464a96eaf3ff526d54e5e6e0822bea0dc179d.
Instrumentation SHA256 remains:
51d792997f50558e95fa8c9e918a7424360b3843fe4dec63dca4d9e03b1b6afd.
The six hashed instrumentation files, build.sh, schema, package lock, pinned FRR
manifest, packager code, and its adversarial tests are byte-identical to baseline.
The Python packager SHA256 remains:
0272f21b8f3a6344f6cad8436d2f532157ea1b9a8d0dbab3d8d233237408a24d.
The new builder identity is separately recorded; old evidence is not relabeled
as proof of a new executable. Container-image bit reproducibility across separate
RPM provisioning transactions is not claimed. FRR artifact bit reproducibility
within the recorded pinned image is directly demonstrated.

## Genuine runtime and security proof

New positive and restart runs execute binaries from nonroot-a in disposable
rootless namespaces, using the unchanged lab recipe. FRR's runtime namespace
privileges are separate from compilation privileges. These labs need routing
capabilities only inside the disposable namespace. System FRR and host networking
are unchanged. proof/ and restart/ preserve the complete original run directories,
including independent BGP, Zebra and kernel observations and recursive manifests.

The initial proof/restart namespace objects were destroyed sequentially, and
Linux reused a namespace inode. Those runs remain untouched in initial-proof/
and initial-restart/, with their bundles and the initial fresh-suite failure log.
The test expected a mixed-namespace refusal; the observed input was still refused
by missing BGP submission, with no claims. The test assertion is not weakened.
A separate namespace-alias negative copy contains byte-identical genuine inputs
from those runs and preserves this actual refusal. It is a constructed negative
mixture, not a claimed single live capture.

For the certified cross-namespace cases, the completed proof namespace is kept
alive by a waiting shell while the restart run executes, then released. No FRR
writer remains active during that wait. This controls the genuine distinct-
namespace precondition instead of changing identifiers or retrying for a desired
message. All original producer/schema assertions are retained.

A boot ID plus namespace inode is an observed context, not a permanent namespace
lifetime identity. Reuse is an existing producer/collection limitation, not a new
builder behavior. Exact BGP path/announcement edges refused the observed alias
mixture, but this is not proof that every arbitrary mixed history is detectable.
Trusted same-run collection remains required. Independent ChatGPT review must
consider capture-cohort/lifetime binding before any importer; this task adds no
correlation semantics or stronger namespace claim.

The positive case covers a single BGP peer, shared attributes/next hop across two
peers with all contributors preserved, static recursion through BGP, withdrawal,
session loss and table-100 refusal. Restart packaging exits 2 with no claims.
No relationship is reconstructed from equal CLI fields. Claims remain historical
identity edges and accepted operation results. They prove no atomic current FIB,
packet delivery or convergence guarantee.

The 37 producer/schema tests, including filesystem capability regressions, pass
with zero skips as non-root on the original evidence. They are also run against
these fresh genuine captures. Input authority remains inherited fd 3, output
authority fd 4, a fixed trusted manifest, strict direct producer basenames,
no-follow bounded regular-file reads and exclusive output. No arbitrary path or
manifest selector is introduced. The 35 individual address proofs also pass in
this restricted image with byte-identical host/container review results.

## Verification and gate

provenance.json pins current implementation files, the two build manifests and
artifact checksums, new/old images, package lock, capture identities and all
historical manifests. SHA256SUMS covers this entire derived directory. Historical
validation programs that pin prior implementation hashes are run at their
recorded commit, not weakened to accept current Containerfile/README hashes.
The original authorization verifier passes in an isolated dfbd4b3 worktree.

```sh
python3 -B -I testdata/frr/10.7.0/bgp/correlation-v1-nonroot/verify.py
```

Go 1.27.3 runs ./scripts/check --race, the full race integration packages and real
kernel route-event integration against exact main. The final frozen integrated
tree and final gate logs are recorded externally at .pr407-tmp/least-privilege to
avoid a self-referential tree identity. Actual pushed-head CodeQL and SonarCloud
results must be checked independently; no green result is inferred here.

The [individual 35-finding table](../correlation-review-dfbd4b3/README.md) requires
independent ChatGPT disposition approval. No finding is remotely dismissed,
suppressed, accepted or marked false positive. The root finding is corrected in
code and must be confirmed automatically by the actual scan. Existing scanner
rules, quality gates and meaningful assertions are retained. C sanitizers are
not run; the prior locked-image runtime-library limitation remains. No merge,
importer, ratings, release, tag, deployment or issue closure is included.
