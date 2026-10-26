# Authorized packager correction

Baseline PR head: 79ea6dde9b2884c05f5567deac41c40061f74a06.
Integration main: 823a91611592c5949d7cb37b26bdf547443cf063.
This directory contains new derived validation, not new FRR observations.
All earlier builds, captures, review records and hashes are preserved unchanged.

## Security correction

S8707 issue AaF3ExOYI5fXcO_YEVtK was a real authorization vulnerability.
The baseline read_source accepted an arbitrary outside regular file and returned
its synthetic sentinel contents. The earlier safe-use rationale is superseded.
The correction removes all path-taking CLI arguments and the redundant --build
selector. It does not move those values into an environment variable or request.

A trusted launcher authorizes a capture directory by inherited fd 3 and an output
directory by inherited fd 4. Input filenames are direct producer UUID basenames;
no untrusted root or nested selector is supported. Each open is relative to the
authorized directory descriptor with O_NOFOLLOW and O_NONBLOCK, followed by
regular-file and hard-link checks and a bounded read. The fixed implementation
manifest is loaded directly. Output is the fixed bundle.json child, created with
O_EXCL and O_NOFOLLOW. Unsupported capabilities and platforms fail closed.

See [the exact authority model](../../../../../contrib/frr-correlation/v1/SECURITY.md)
for manual invocation, supervisor responsibilities, replacement-race proof and
limitations. This secures file selection, not malicious Python execution or an
external wrapper that gives request data authority over inherited descriptors.
The repository contains no such automated wrapper and claims no arbitrary
agent/server integration support.

## Validation and identities

The locked builder passes all 37 producer/schema tests with zero skips.
The 27 original writer modes and their assertions are retained unchanged; the
current C writer harness and wire codec tests are freshly compiled against the
accepted libfrr and pass. Wire-test diagnostics are expected for deliberately
truncated or malformed inputs; CODEC_TESTS_PASSED is present in c-tests.log.
The adversarial tests reject outside absolute paths, parent and alternate path
spellings, direct/nested symlinks, outside regular files and hard links, special
files/FIFOs, oversized inputs, replacements before/after open, and manifest/root/
output selector arguments. They also prove valid inherited-descriptor operation
and preservation of existing regular/symlink output bytes.

The C producer identity remains:
89f0152ef221c716119b8b739a6464a96eaf3ff526d54e5e6e0822bea0dc179d.
Its instrumentation SHA256 remains:
51d792997f50558e95fa8c9e918a7424360b3843fe4dec63dca4d9e03b1b6afd.
No hashed instrumentation input, build recipe, lock, schema or pinned manifest
changed. Both existing independent builds' eight artifacts are rehashed and
match the pinned manifest. Rebuilding unchanged C would not add security proof
for this Python-only correction. provenance.json identifies the new Python
implementation separately.

The genuine positive streams from correlation-v1-noreplace are reprocessed.
proof-bundle.json is byte-identical to its original. The genuine restart input
still exits 2, capture.complete is false and claims is empty. The correlation
algorithm AST after source acquisition is identical to the baseline. Historical
claims retain their exact meaning: no current atomic FIB, packet-delivery or
convergence guarantee. Raw events are never reconstructed or rewritten.
All 1,313 historical SHA256 manifest entries are reverified.

Go 1.27.3 validates the isolated integration with exact main using:

```sh
./scripts/check --race
go test -race -tags integration ./internal/app ./internal/diagnostic ./internal/peer ./internal/simulation
go test -tags netns_integration -count=1 -v -run '^TestRouteEvents' ./internal/diagnostic
```

The final frozen integrated tree ID and complete final gate logs are retained
outside the tree under .pr407-tmp/authorization to avoid a self-referential tree
identity. Preliminary gate logs and the exact commands are included here.
No application source or Network Doctor public CLI changes are made.

Verify the derived proof and all referenced historical manifests from the repository root:

```sh
python3 -B -I testdata/frr/10.7.0/bgp/correlation-v1-authorized/verify.py
```

## SonarCloud review

baseline-checks.json and both baseline annotation files are exact-head 79ea6dd
snapshots. Both checks report the same 37 issue identities. baseline-issues.json
contains 40 API entries, including three historical entries absent from those
annotations. triage.json records each identity, rule, file, line, exact baseline
expression, validity, security impact and action.

The high finding is corrected in the implementation and must be checked against
the actual published-head analysis. It is never marked false positive or
suppressed. The 35 S1313 findings identify expected fixed lab addresses in an
offline verifier. That verifier performs no network requests or host configuration;
its exact assertions and immutable capture manifests are retained. S6471 identifies
the locked builder's default UID 0: only rootless, isolated build/test use with
read-only producer sources and scratch-only writable mounts is supported. A
rootful privileged deployment is not approved. No rule, exclusion, project-wide
security configuration or quality gate is changed. These documented low findings
may keep the remote checks red; their actual corrected-head status must be
reported, not inferred from this baseline review.

## Review gate and limitations

Independent ChatGPT review is required before an importer or forwarding semantics.
No merge, tag, release, deployment or issue-state change is included.
C sanitizers are not rerun; the prior locked-image runtime-library limitation
remains. Filesystem authorization does not authenticate capture contents or
make a changing capture complete. Stable post-exit collection and retained
producer diagnostics remain required. Storage failures that prevent both C
revocation and failure-marker creation still require operational refusal.
