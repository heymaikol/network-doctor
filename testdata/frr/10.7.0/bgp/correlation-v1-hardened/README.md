# Phase 1 producer hardening

Review baseline: `aa5ffe6782334a971896b2621885489088cd1ec9`.
Integration base: `823a91611592c5949d7cb37b26bdf547443cf063`.
No Network Doctor importer, forwarding rating, application change, merge,
issue closure, tag, release, or deployment is included. Independent ChatGPT
approval remains required before proceeding beyond this producer phase.

## Confirmed defects and changes

The original `ndoc_finish` read the fd, flushed, truncated, and closed without
holding the emission mutex. Two shutdown callers could close the same fd, and
an emitter could write after the trailer or use a closing/reused descriptor.
Its truncate rollback and close results were unchecked. The previous writer
test joined every writer before shutdown and could not exercise this race.

The same mutex now owns initialization, emission and all shutdown operations.
Zebra starts its dataplane thread before frr_run; the enabled state is now
published only after the start record, so workers cannot precede that record. A private
non-locking helper writes the trailer without recursive mutex acquisition.
Repeated shutdown does nothing. Linux close failure is recorded without
retrying the released descriptor. Streams are created as `.jsonl.partial`
and renamed only after successful flushes and close. Every partial stream
causes capture refusal. The design no longer needs truncate rollback, so a
failed truncate cannot leave a valid publication. An enabled hook after
shutdown revokes the published filename to partial and reports the late event.

Direct upstream binary build targets also exposed a generated-header race:
`bgp_attr.c` saw a partially generated `lib/route_types.h`. The failed clean
attempt is retained as `validation/build-a.log` and is not accepted. The recipe
now builds all three upstream `BUILT_SOURCES` headers before parallel binaries.

The packager previously overwrote its requested output and followed existing
output symlinks. It now creates exclusively and returns refusal on collision,
with tests preserving the original evidence bytes. Source reads open with no-follow
and nonblocking flags, reject non-regular files, and bound actual reads rather
than trusting a size checked before opening. Symlink and FIFO refusal and the
read limit have explicit tests. Operator-selected input and
output paths remain ordinary local CLI paths, without a fictitious server
sandbox or restrictions on arbitrary authorized input directories.

## Build identities and preservation

| Item | Original | Hardened |
| --- | --- | --- |
| Build ID | `b5207a87e19c585481294b77604ca6bd639d38679b85da2fe10c42d46cddb507` | `a8addc1b3cd33f6fd3a0fb9c8ca2eaeb4b994eadf78ad3fe21c12964d6ca9a96` |
| Instrumentation SHA256 | `acb2d79e9d980085b3d574567fae2c072998dd5cfc15a6cbf4e478674a0f6013` | `327f29dbacbc58d0e00131cbf3f3df17dd239edd7de2e3f8a3293e52c0a856fd` |

The pinned upstream source, private identity propagation patch, contributing
path logic, recursive edges, selection generations, and dataplane association
are unchanged. Only writer implementation bytes changed the instrumentation
identity. The original [correlation-v1](../correlation-v1/README.md) and
[investigation](../correlation-investigation/README.md) remain byte-identical.
They are historical evidence for their recorded executables, not this build.

Two independent fresh source directories, `hardening-d` and `hardening-e`,
used the locked recreated builder with network disabled. Build manifests and
all eight staged artifact bytes match. `build.json` is the current exact
verified subset; `provenance.json` records source, builder, runtime library,
recipe and artifact hashes. Both full logs contain `CODEC_TESTS_PASSED` and
`BUILD_DONE`. No host FRR installation or networking was replaced.

## Genuine live proof

`proof/` and `restart/` are new, unedited captures from the hardened build.
Their original recursive manifests and terminal logs are preserved. Both lab
processes exited 0 with DONE; the restart bundle intentionally exits 2.
Independent BGP summary/table/detail, Zebra route/NHT, kernel routes, nexthops,
rules, namespace and boot observations accompany the identity streams.

The positive bundle contains 12 `path_submitted_as_route` edges, seven actual
`route_leg_resolved_by_route` edges and six historical `route_installed_as_fib`
edges. It preserves both distinct peer/path contributors when two peers share
AS path and next hop. It records the static route's actual lookup of a BGP
resolver and the exact consuming and resolving route generations. Withdrawal
and session loss are independently observed. The explicit table-100 route is
refused. There are 16 pending shutdown operations without accepted results;
none receives installation credit. Other unsupported records remain refusals.

The restart run includes a genuinely killed daemon's partial epoch, a new
epoch, and a closed Zebra epoch. It is refused wholesale with no claims.
Mutation tests remove and contradict real identity edges, ACKs and generations;
these are labeled synthetic negative tests, never rewritten live evidence.

## SonarCloud review

[triage.json](sonar/triage.json) records each rule, reviewed file/line, validity,
impact and action. The exact 35-annotation check and the 39-annotation analysis
check are preserved alongside the Sonar API issue metadata. All 35 requested
annotations are `python:S1313`: fixed expected addresses in an offline evidence
verifier, with no sockets, requests, or networking configuration. They are safe
here and retained to preserve exact assertions and original evidence.

The additional four findings are one builder-root warning (`docker:S6471`)
and three path-traversal findings (`pythonsecurity:S8707`, `S2083`). Root is
inside the rootless lab builder, not a deployed privileged service. Captured
content never selects a path. Existing output overwrite/symlink following was
nevertheless a valid data-loss concern and is fixed as described above.
No finding was blanket-suppressed or marked resolved remotely. No repository
quality gate, scanner, or exclusion was changed. Server-side acceptance of
safe-use rationales remains a reviewer decision.

C review checked bounded contributor arrays and stream reads, terminated epoch
strings, per-record allocation ownership, descriptor lifetime and failed IO.
The wire codec exercises actual libfrr serialization at all truncation
boundaries. Python subprocess tests use explicit argument vectors, timeouts,
and a trusted operator-selected executable; captured data never selects it.
The lab's shell function reuse comes only from the checked-in trusted recipe.
Builds and live runs remain rootless with scratch-only writes and disposable
network/mount namespaces.

## Validation

The authoritative producer suite runs in the locked builder with jsonschema
installed: 26 tests, zero skips. It covers genuine graph chains, deterministic
bundles, independent observations, complete manifests, unsupported builds,
schemas, kernels, contexts, missing/contradictory edges, stale results, ACK
failure, restart, truncated input and safe exclusive output creation.

The compiled writer suite uses the real current `netdoc.c` with deterministic
IO wrappers and pinned FRR headers/libraries. Four writers submit 4000 records.
In the overlap case, one writer blocks inside write while two finishers start;
close cannot proceed until that writer leaves. Writers and finishers overlap,
late events revoke publication, and repeated shutdown cannot close a reused fd.
Tests cover write error, EINTR, zero and short writes, trailer write failure,
pre-trailer and post-trailer fsync failures, close EIO/EINTR, publication failure,
and oversized records. The faulting ftruncate shim is never called because
rollback-by-truncation was eliminated. The startup overlap case blocks the
start record, starts a writer and a finisher, and checks that enabled remains
false until the start record is written. These synthetic tests are not live FRR
routing evidence. They do not replace the separately rebuilt daemon runs.

Commands and outcomes are in `validation/` and `provenance.json`. Repository
checks use Go 1.27.3 on the isolated tree integrated with the specified main:

```sh
GOTOOLCHAIN=go1.27.3 GOMEMLIMIT=2GiB ./scripts/check --race
GOTOOLCHAIN=go1.27.3 GOMEMLIMIT=2GiB go test -race -tags integration ./internal/app ./internal/diagnostic ./internal/peer ./internal/simulation
```

An initial concurrent race-integration attempt was killed by host OOM; the
kernel diagnosis and failed attempt are retained. Final race gates run
sequentially with a 2 GiB Go heap target and unchanged tests and timeouts.
An optional ASan/UBSan test could not link because the locked builder lacks
the runtime libraries; no sanitizer success is claimed and the lock was not
changed to hide that limitation. The compiled ordinary writer/wire tests
and genuine daemon proof remain the required C validation.

Every evidence file is covered by the outer SHA256SUMS; each live run also
retains its own original manifest. Source and current artifact hashes are
independently verified, and `git diff --check` is required before push.

## Limits and review gate

These are historical identity edges and acknowledged operation results.
`snapshot_complete` remains false. No atomic current FIB, simultaneous daemon
fence, delivery, convergence or offload guarantee follows. Other FRR versions,
architectures, kernels, OSes, routing contexts and features remain unsupported.
No identity relationship is inferred from matching prefixes or addresses.

Read only after all producer processes exit and the trusted local collection
directory stops changing. Retain diagnostics: if the filesystem refuses a late
event's revocation rename, the diagnostic invalidates the collection. An isolated
copied JSONL cannot reveal a failed revocation or deliberately omitted partial
file. Directory metadata power-loss durability, malicious storage/producer
attestation, and C sanitizer runs are not proven. One directory fd intentionally
remains open until process exit for late-event revocation. This is a lab-only,
single-init lifecycle; it is not an exporter reload API.

Stop for independent ChatGPT review of the hardened implementation, its
filesystem/lifecycle assumptions, Sonar rationales and new evidence before any
Network Doctor importer or forwarding semantics work.
