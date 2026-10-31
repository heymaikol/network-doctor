# Trusted capture isolation (slice S3)

This package is the boundary between a directory a producer can write and the
bytes the collector is willing to read. It does one thing: it takes the single
stream a producer left in a private inbox and turns it into a sealed, immutable,
hashed, in-memory `Snapshot`, or refuses with a fixed, sanitized reason.

It does not parse producer content, does not import `collector` or `supervisor`,
and cannot advance a `collector.Lifecycle`. Nothing in the collector or the
supervisor imports it. A `Snapshot` is not trusted evidence, and this slice
deliberately offers no way to make it one.

## What a Snapshot proves

When `Seal` returns a `Snapshot`:

- The bytes are a private copy in a sealed anonymous file. The seals (shrink,
  grow, write, seal) cannot be removed. A reopen of the anonymous file through
  `/proc` can still be opened for writing, but every write, truncate, writable
  shared mapping and further seal on it fails with `EPERM`. Mutating, replacing, truncating
  or unlinking the source cannot change it.
- At one instant, no file description open for writing existed on the source
  inode. The proof is a read lease taken before the copy and checked unbroken
  after it. The lease is granted only when no writer holds the inode, and any
  later write-open breaks it. This includes a descriptor held by a detached
  descendant that left the process group, and a writable shared mapping that
  outlived its descriptor.
- The digest is the SHA-256 of the sealed bytes, computed after sealing. No
  claim inside the content can reach it, because the content is never parsed.

## What it does not prove

- **Who wrote the bytes.** A sibling producer can still write another
  producer's inbox (see the gap table). A `Snapshot` does not authenticate its
  producer.
- **That the producer processes are gone.** The lease is per inode and per
  instant. A live, cooperative producer keeps its directory descriptor until
  exit and may revoke a published stream afterwards (rename the final name back
  to `.partial`, create `.failed`). The `Snapshot` taken before cannot see that.
  Proving quiescence needs a PID namespace whose init death can be observed.
- **That `Close` removed exactly the directory it made.** It proves the original
  is gone, not that the removal by name hit the original. A same-user process can
  make it delete an empty replacement directory (see the known gaps).
- **That anything outside the sealed bytes is intact.** The packager install,
  `verified-build.json`, the repository checkout, the supervisor binary and
  the `nsenter` and `sleep` found through `PATH` are the trusted computing base
  on disk, and nothing here protects them.
- **Anything about the network.** No FIB-to-BGP correlation, selected-FIB
  verification or forwarding rating is attempted.

## Property table

| # | Property | Status | Basis |
|---|----------|--------|-------|
| 1 | One private inbox per producer | Structural only | Fresh `0700` directory per `Inbox`. Not enforced against a hostile peer: same UID, shared mount namespace, path discoverable through `/proc/<pid>/environ`. |
| 2 | A producer cannot reach another producer's inbox | **Not enforceable now** | Needs per-producer mount and PID namespace confinement. `TestKnownGapPeerProducerCanRewriteAnotherInbox` asserts the write succeeds. |
| 3 | Snapshot bytes and in-memory state are collector-owned | Enforced for bytes and in-process state; **not** for the on-disk TCB | Sealed memfd, never exposed as an `*os.File`. |
| 4 | No writer exists when the snapshot is taken | Enforced per inode at one instant; process quiescence **not** provable | Read lease, plus a gap test for late revocation. |
| 5 | Name-to-inode binding cannot be redirected | Enforced | Retained directory descriptor, `openat` relative to it, `fstat` on the opened file, `dev/ino` recheck, single-name relisting. |
| 6 | Only a plain owned file is read | Enforced for the snapshot path | `O_NOFOLLOW`, `S_ISREG`, `nlink == 1`, owner equals euid, close-on-exec, no blocking open of a FIFO. |
| 7 | Resource bounds | Partial | 64 MiB cap, at most 8 entries, bounded cleanup. A producer's own writes are unbounded and `/tmp` may be RAM. A producer that moves its inbox away leaves `Close` incomplete and one descriptor held until exit. |
| 8 | Diagnostics carry no producer bytes | Enforced | Fixed codes and text of at most 160 bytes; no name, path or errno is echoed. |
| 9 | Namespaces are neither held nor released | Unchanged | `TestSealAndCloseDoNotTouchTheNamespace`. |
| 10 | Content never steers the capture | Enforced by construction | No parser; the package imports no JSON. |

The change checks in step 5 below compare the inode, size, link count, mode,
owner, name-to-inode binding and lease directly. `ctime` is compared as well, but
only as a best-effort extra signal: its resolution depends on the kernel, so no
case relies on it alone.

## How a Seal runs

1. List the inbox through a fresh description of the retained directory, at most
   8 names. Exactly one name must match `<role>.<lowercase uuid>.jsonl`. A second
   epoch is `mixed_epochs`, anything else is `unexpected_entry`, so `.partial`
   and `.failed` files are refusals.
2. `fstatat` without following links, then `openat` with `O_NOFOLLOW`,
   `O_NONBLOCK` and `O_CLOEXEC`, and check the filesystem type.
3. Take `F_SETLEASE(F_RDLCK)`. `EAGAIN` means a writer exists: `writer_present`.
4. Record a baseline `fstat`, admit only a regular, single-link file owned by
   the collector within the size cap, and copy it into a memfd.
5. Recheck the inode, size, link count, mode, owner, `mtime` and `ctime`,
   confirm the name still maps to the same inode, confirm `F_GETLEASE` still
   reports the read lease, and list the inbox again.
6. Add every seal, verify them, hash the sealed bytes, and release the lease on
   every path.

Only filesystems whose writers the lease can see are accepted (tmpfs, ext4,
btrfs, xfs). FUSE, NFS, overlayfs, 9p and unknown types are refused. The check
runs on the directory and on the opened file, and is tested through a `statfs`
hook, not a real FUSE mount.

The context is checked before every 1 MiB chunk of the copy. A cancelled `Seal`
returns `cancelled`, closes the partial memfd and releases the lease.
`TestSealStopsWhenCancelledBeforeTheCopy` cancels before any byte is copied, and
`TestSealStopsWhenCancelledAfterACopiedChunk` cancels after the first chunk and
requires the copy to stop at the next boundary.

## Inbox states and errors

An `Inbox` moves one way: open, then used, then closing, then closed.

- `Seal` moves an open inbox to used. Success and failure both consume it, so a
  restarted producer cannot be spliced in after a refusal, and a second `Seal`
  returns `already_used`.
- The first `Close` moves the inbox to closing, whether or not that call
  finishes. From then on `Seal` returns `closed` and accepts nothing new, even if
  the producer changes the directory between `Close` attempts. This is
  `TestCloseBeginningIsTerminalForSeal`.
- A closing inbox keeps its directory descriptor. Each `Close` call makes a
  bounded, best-effort pass over at most 8 names: it removes every plain entry
  and every empty subdirectory it can, does not stop at one it cannot remove, and
  never descends into a subdirectory. It returns `cleanup_incomplete` until the
  original directory is proven unlinked, then becomes closed and returns nil from
  then on.
- The proof is made through the retained descriptor, not through the result of
  removing the pathname. The kernel marks a directory dead only when an rmdir
  succeeds on it or a rename replaces it, and reading a dead directory fails with
  `ENOENT` while its link count is zero. A directory that was only moved away
  still reads normally. So `Close` returns nil when the original is gone, whoever
  removed it (a producer may remove its own emptied inbox), and never when a
  removal by name hit a different directory.
  `TestCloseRemovesEveryRemovableEntryInAnyOrder` runs every listing order of a
  mix of nonempty subdirectories and removable entries.
- None of this affects a `Snapshot` that was already returned.

Every error these types return is a `*Refusal` with fixed text, except that
`Snapshot.ReadAt` may also return `io.EOF` with its usual meaning. A failing
close of the sealed bytes is reported as `close_failure`, and no system error text
is passed through.

## Known gaps, each asserted by a test

- `TestKnownGapCloseCanRemoveADirectorySwappedIntoItsName`: Linux removes a
  directory by name, not by descriptor, so no check before the removal can stop a
  process running as the same user from winning the window. If it moves the
  original away and installs an empty directory at the inbox's name just before
  `Close` removes it, `Close` removes that replacement. It then returns
  `cleanup_incomplete`, because the retained descriptor shows the original is
  still linked (`TestCloseDoesNotReportSuccessForAReplacedPathname`). The reach is
  an empty, non-symlink directory at the inbox's own name, which that user could
  delete anyway, so no capability is gained. Renaming to a random name first, or
  keeping the parent open, only narrows the window, so neither is done. Only
  per-producer confinement or a different user prevents it. `NewInbox` has the
  same kind of window between creating the directory and opening it. If the
  producer moved the original away, `Close` stays incomplete and the inbox holds
  one descriptor until the process exits.

- `TestKnownGapPeerProducerCanRewriteAnotherInbox` (netns): a child in the
  supervisor's namespaces rewrites a sibling inbox before it is sealed. Flip the
  assertion when mount and PID confinement lands.
- `TestKnownGapASnapshotCannotSeeALaterRevocation`: a stream revoked after
  `Seal` leaves the `Snapshot` valid.
- `TestStopSucceedsWhileADetachedWriterHoldsTheStream` (netns): the
  supervisor's `Stop` succeeds while a detached descendant still holds the
  stream, which is why the lease is needed.

One observed isolation property is also pinned:
`TestProducerCannotReachCollectorMemoryOrSnapshot` shows that a child in the
supervisor's user namespace is refused `/proc/<collector>/mem`, the sealed
descriptor under `/proc/<collector>/fd` and `PTRACE_SEIZE`, with controls that
rule out a missing `/proc` entry. That is the kernel's cross-user-namespace
ptrace check on the kernel tested, not a guarantee about every host, and it
says nothing about a producer that escapes the user namespace. No test treats a
simulated refusal as proof of production isolation.

## Why there is no promotion

`Snapshot` has no method that returns a collector type, and the exported surface
is pinned by `TestExportedSurfaceIsPinned`. `TestCaptureHasNoPathToTrustPromotion`
fails if this package imports the collector, the supervisor or any JSON package,
or if the collector or supervisor start importing it. The first slice that
connects a `Snapshot` to a `Lifecycle` has to change those tests on purpose, in
review, and has to add the missing guarantees below first.

## Next slices

- **PID namespace.** Make the holder a PID namespace init so its death is an
  observable proof that every producer descendant is gone. That closes the
  quiescence gap in property 4.
- **Per-producer confinement.** Give each producer its own mount namespace and a
  `pivot_root` onto its inbox only, inside that PID namespace, under live FRR
  policy. That closes property 2 and flips the peer-write test.
- **Authenticated handoff.** Bind a `Snapshot` to the producer that wrote it.

## Validation

```sh
go test -race ./contrib/frr-correlation/capture
NETDOC_SIM_REQUIRE_NETNS=1 go test -race -count=1 -tags netns_integration ./contrib/frr-correlation/capture ./contrib/frr-correlation/supervisor
golangci-lint run --build-tags netns_integration ./contrib/frr-correlation/...
```

The package builds with `CGO_ENABLED=0` for every supported target. Off Linux
every operation refuses with `unsupported`. The Linux tests skip when the
temporary directory is on a filesystem the lease proof refuses, and fail
instead of skipping when `NETDOC_SIM_REQUIRE_NETNS` is set.
