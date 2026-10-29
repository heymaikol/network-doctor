# Packager filesystem authority

The S8707 finding AaF3ExOYI5fXcO_YEVtK was valid. Before this correction,
argparse values selected the capture directory, build manifest and output path.
The process opened those paths with its own permissions. Bounded reads,
O_NOFOLLOW and exclusive output creation did not authorize those selections.
The earlier safe-use triage is superseded, not a false-positive resolution.

## Authority supplied by the launcher

The packager now accepts no path or descriptor-number arguments. It does not
consult environment variables, request JSON, the working directory or capture
contents for a root or manifest selection. Its public Python entry point is
produce(directory_fd), where the descriptor itself is the authorization
capability. It loads verified-build.json beside the trusted implementation.
That installation, its manifest and its interpreter must be protected from
untrusted modification just like any other trusted executable.

A trusted launcher supplies two already-open Linux directory descriptors:

- fd 3 authorizes reads of direct producer JSONL children in one capture.
- fd 4 authorizes exclusive creation of the fixed child bundle.json.

The launcher owns the decision about those directories. A request cannot select
a root, pass a descriptor number, change the manifest or name an output file.
There is no general relative-path selector. Removing that unnecessary capability
also removes traversal through nested directories.

For manual local use, the operator chooses the directories in the shell before
launching the packager. Replace the example placeholders with operator-approved
literal paths; neither placeholder may come from an untrusted request:

```sh
python3 -I contrib/frr-correlation/v1/bundle.py \
  3< <authorized-capture-directory> 4< <authorized-output-directory>
```

For automation, a supervisor must obtain those descriptors from protected launch
configuration, pass exactly those capabilities to the child, close unrelated
inherited descriptors and invoke the trusted script/interpreter with fixed
arguments. It must not translate request paths into capabilities. This repository
has no server or agent launcher implementing that policy, and does not claim to
secure an arbitrary external wrapper. Giving untrusted code permission to replace
the executable, launch configuration or inherited descriptors is outside this
boundary. The packager is not a sandbox for malicious Python code.

Output is always bundle.json inside fd 4. O_CREAT|O_EXCL|O_NOFOLLOW prevents
replacement of existing regular files, hard links and symlinks. Output may
contain captured evidence, so the launcher must authorize its destination too.

## Descriptor-relative proof

The packager requires Linux directory descriptors. Directory enumeration uses
os.scandir(fd) with at most 1024 entries. Source names must match exactly
(bgpd|zebra).<lowercase UUID>.jsonl, with a full-string match. Absolute names,
slashes, parent components, dot aliases, encoding tricks and NUL bytes cannot
reach os.open. Unknown JSONL names are refused, not interpreted as paths.

Every source open is relative to the pinned directory descriptor with
O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC. Because an accepted name contains no separator,
there is no intermediate component to follow. The only resolution edge is the
final child; O_NOFOLLOW rejects a symlink atomically at that edge. This is the
restricted single-component equivalent of beneath/no-symlink resolution and
does not require an openat2 syscall wrapper or kernel-specific syscall number.
A future multi-component selector would require a new security design.

Renaming the authorized directory or replacing its old pathname with a symlink
does not redirect a descriptor-relative open. Replacing a child with a symlink
before open is refused. Replacing it after open cannot retarget the opened
file descriptor. fstat validates that exact descriptor as a regular file before
reading, and refuses multiple hard links. An unlinked but already-open authorized
file remains safe to read. Reads are limited to 64 MiB plus one detection byte;
record counts and lengths retain their existing bounds. Special files and FIFOs
are refused without reading their contents. No unsupported-platform fallback
uses a process-relative path open.

The supervisor must not authorize hostile mount topology or allow another
privileged actor to remount the capture directory. This is file selection
authorization, not authentication of capture bytes. As before, collect only
after daemon exit, retain diagnostics, and use a stable complete collection.
Concurrent modification of regular file contents or markers can invalidate the
historical completeness claim; a malicious producer or privileged filesystem
writer is not made trustworthy by a directory descriptor.

## Callers, compatibility and proof

Repository search found only test_bundle.py and the reproduction command in
README.md calling the packager. lab.sh records raw streams and never invokes it.
All active callers are updated. Commands and review rationale inside historical
capture directories remain unchanged as immutable evidence of earlier versions.
Use this document's invocation to reprocess them with the current implementation.
Network Doctor's public CLI and application behavior are unchanged.

The C extension, its six hashed instrumentation inputs, builder lock, schema and
verified-build.json are unchanged. Reprocessed genuine proof output must match
the original proof-bundle.json byte for byte. The genuine restart capture must
still exit 2 with no claims. New validation records identify the Python packager
separately from the unchanged FRR build ID. Historical raw streams are never
rewritten, and their recursive manifests are verified before reprocessing.

Regression tests cover absolute and parent escapes, alternate spellings, direct
and nested symlinks, an existing outside regular file, outside hard links, FIFO,
socket, directory and device inputs, oversized reads, replacements around open,
manifest/root/output argument rejection, missing capabilities, unsupported OS,
bounded enumeration, valid authorized CLI processing and exclusive output.
Unauthorized selectors are asserted to reach neither open nor read; symlink
replacements are asserted never to create a readable source wrapper.

## Builder privileges

The current builder installs the exact locked RPM packages as container root,
then defaults to UID/GID 65534. Compilation and testing are certified only with
rootless Podman, all capabilities dropped, no-new-privileges, readonly image and
source mounts, a dedicated writable scratch directory, private temporary storage
and --network=none. verified-builder.json records the new image and recipe hashes.
Rootless execution alone is not an adequate substitute for those restrictions.
The host user maps to the non-root build identity so scratch ownership does not
require host chown or elevated privileges. Other host paths are not mounted.

The package-provisioning step requires repository network access and its output
must match the entire existing RPM lock. Compilation and tests have no network.
Kernel-created fallback tunnel interfaces can appear in a fresh namespace; the
proof requires them administratively down, an empty /proc/net/route, only loopback IPv6
routes and a network namespace distinct from the host. No interface-name-only
isolation claim is made. UID, capabilities, mount-write refusals and network state
are captured by the non-root isolation probe.

The historical root-default image remains preserved with its original identity.
New non-root builds reproduce all eight original FRR artifacts byte for byte, so
the producer build identity and manifest remain unchanged. FRR runtime namespace
privileges are separate from build privileges; live labs still use disposable
rootless namespaces to exercise genuine routing operations. No system FRR or host
route is changed. Historical validation programs that pin implementation hashes
must be run at their recorded commit; the current report validates the new builder
and unchanged producer/packager without rewriting those historical programs.
