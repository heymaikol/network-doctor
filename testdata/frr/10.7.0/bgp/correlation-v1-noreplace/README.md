# Phase 1 no-replace publication proof

Review baseline: `7df7be121846490ebc5cf389eee2e4f1e15cca56`.
Integration main: `823a91611592c5949d7cb37b26bdf547443cf063`.
This change addresses destination overwrite during exporter publication and
revocation. No application, report, Network Doctor importer, forwarding rating,
main branch, issue state, tag, release, merge or deployment is changed.

## Defect and exact correction

The prior writer created its partial stream with O_EXCL, but both renameat calls
could replace an existing destination directory entry. That could destroy an
existing final stream during publication, or an existing partial file during
late-event revocation. A symlink destination could also be replaced.

Both operations now call Linux `renameat2(..., RENAME_NOREPLACE)` under the
existing writer mutex. The kernel performs the absence check and move atomically.
There is no fallback to renameat or another overwriting operation. Unsupported
kernel/filesystem errors, including ENOSYS, EOPNOTSUPP and EINVAL, fail closed.
Publication failure leaves the original destination and the refused partial
stream intact, even if its trailer is otherwise complete.

Failed revocation retains the original final stream and destination, records the
failure, and creates an exclusive no-follow `.jsonl.failed` marker. The packager
refuses any such marker with no claims. An existing failure marker, including a
symlink, is never replaced or followed. This closes the case where an unavailable
revocation operation would otherwise leave only a seemingly complete final file.

The original startup, concurrent writers/two finishers, repeated shutdown,
descriptor reuse, late-emission and IO-fault checks are retained. No record is
appended after the completion trailer, and output close still occurs once under the mutex.

## New build and preserved history

| Identity | Value |
| --- | --- |
| Producer build | `89f0152ef221c716119b8b739a6464a96eaf3ff526d54e5e6e0822bea0dc179d` |
| Instrumentation SHA256 | `51d792997f50558e95fa8c9e918a7424360b3843fe4dec63dca4d9e03b1b6afd` |
| FRR source | `87fe21fda92ce9e2ba3eaf2b0a327bf71ee183ef`, FRR 10.7.0 |

`build.json` records every exact artifact hash. Two new fresh directories,
`noreplace-a` and `noreplace-b`, used the same locked recreated builder with
network disabled. Build manifests and all eight staged artifact bytes are
identical. Both actual compiled wire suites passed. Logs, artifact manifests,
source/build inputs, runtime dependency hashes and collection commands are
preserved in `validation/` and `provenance.json`.

Earlier [investigation](../correlation-investigation/README.md),
[original producer](../correlation-v1/README.md) and
[writer hardening](../correlation-v1-hardened/README.md) evidence remain unchanged.
In particular, build `a8addc1b` remains evidence only for its historical executable.
No old event was edited, copied into the new proof as if newly produced, or used
to manufacture a new build identity. Earlier scratch builds and runs are retained.

## Real final-build evidence

`proof/` and `restart/` are new genuine instrumented FRR runs, preserved byte for
byte with their original recursive manifests. Both lab processes exited 0 with
DONE. The positive bundle succeeds; the genuinely interrupted/restarted epoch is
refused with exit 2 and no claims. The lab modifies only disposable rootless user,
mount and network namespaces and stages FRR in scratch. No host networking or
installed system FRR is replaced.

Independent BGP table/detail/summary, Zebra routes/NHT, and kernel routes,
nexthops and rules accompany the explicit identity streams. The positive bundle
has 12 path-submission edges, seven actual recursive-resolution edges and six
historical acknowledged installation edges. It retains both peers contributing
the same AS path and forwarding next hop. The static route resolves through the
actual referenced BGP route. Withdrawal and session loss are independently
observed. Table 100 is explicitly unsupported. Sixteen pending shutdown
operations receive no installation credit.

No path-to-FIB edge is reconstructed from equal prefixes, addresses or CLI fields.
Identity propagation, contributing paths, route generations, resolution edges,
operation association and ACK requirements are unchanged by this filesystem fix.

## Negative and regression validation

The compiled real writer source runs 27 test modes in the locked builder:

- All 15 earlier modes remain, including startup/writer/shutdown overlap and
  two finishers while a writer owns the fd.
- Native no-replace collisions cover existing regular files and symlinks during
  publication and revocation. Original bytes, regular-file inode, symlink text
  and symlink-target bytes remain unchanged. No precheck-only replacement is used.
- Injected ENOSYS, EOPNOTSUPP and EINVAL cover both operations, with no fallback.
  Failed revocation leaves a marker while the closed final stream remains.
- Existing regular and symlink failure markers also retain their bytes/targets.

The original checks still enforce unique IDs, dense sequences, ordered clocks,
end-last ordering, repeated-shutdown idempotence, reused-descriptor preservation,
write/flush/close failure refusal and absence of truncation rollback.
These are explicitly synthetic fault tests, not fabricated live route evidence.

All 27 producer/schema tests pass in the locked builder with zero skips. The new
marker test proves refusal with two otherwise valid closed streams, for a regular
marker and a symlink marker; the CLI exits 2 with an empty claims list. Earlier
missing/contradictory edge, stale generation, unsuccessful installation,
unsupported-feature, source-bound and schema tests remain.

Repository validation runs on an isolated merge with the specified main, using
Go 1.27.3 and sequential race gates with GOMEMLIMIT=2GiB. The exact final frozen
integrated tree and final gate results are recorded at PR handoff, outside its
own tree to avoid a self-referential Git tree identity. Source whitespace checks
and all evidence SHA256 manifests are required before push. Raw terminal and
compiler whitespace is retained deliberately by narrow evidence attributes.

## Current Sonar review

[The new exact-head triage](../correlation-review-7df7be1/README.md) reviews all
37 annotations at `7df7be1`: one high and 36 low. The high read_source alert's
actual argparse-to-open flow, real read capability, supported local CLI boundary,
and unsupported agent/server reuse are documented individually. Older API
entries are distinguished from current annotations. No blanket harmlessness,
remote resolution, scanner change or weakened security gate is claimed.

## Limits and independent review gate

Claims remain historical accepted operations. snapshot_complete is false.
No current atomic FIB snapshot, packet delivery, convergence or offload guarantee
follows. Other producer/build/schema/OS/kernel/feature combinations remain outside
the verified subset. Unsupported no-replace operations cannot receive capture
completion credit.

Consume only the complete, unchanged collection after daemon exit. If storage
prevents both revocation and failure-marker creation, retained daemon diagnostics
invalidate the collection operationally; a copied isolated JSONL cannot prove
absence of omitted diagnostics or markers. Storage power-loss durability,
malicious operator/producer attestation and ASan/UBSan/ThreadSanitizer are not
proven. The locked builder's sanitizer runtimes were already unavailable in the
prior phase and are not substituted or claimed here. One directory fd remains
until process exit for late-event revocation.

Stop for independent ChatGPT review of no-replace behavior, the refreshed Sonar
threat model and the new-build proof before any importer or forwarding semantics.
