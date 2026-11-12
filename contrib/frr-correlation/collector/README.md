# FRR cohort contract and lifecycle

This first slice of [issue #390](https://github.com/heymaikol/network-doctor/issues/390)
defines `netdoc-frr-cohort/v1`. It is a rootless Go library, with no executable,
live collector, supervisor, descriptor handoff, importer or forwarding ratings.
It does not change the sibling historical `v1` contract or its CLI. The original
certificate remains unchanged; the corrected producer candidate remains inactive.

## Input and trust boundary

[`schema.json`](schema.json) describes **untrusted claims**, not an authenticated
receipt. The envelope names one bgpd epoch and one Zebra epoch, a boot, a
namespace device/inode, a cohort label, a common build and certificate digest,
two capture digests/lengths and the packaged bundle digest. PIDs and start ticks
are observations to compare against trusted process ownership, never substitutes
for it. Build identity refers to the certified artifact set, not a daemon's
self-reported version. Hashes describe bytes; they do not authorize a build.

`Decode(io.Reader)` returns an opaque `UntrustedEnvelope`. `Claims()` returns a
value copy. A caller can inspect or modify that copy without changing the input
retained by a lifecycle. No schema field asserts authentication, trusted shutdown
or namespace ownership. `selected_fib_verified` is required and must be false.

Limits are fixed: 16 KiB input, eight nested containers, 256 JSON tokens, 128
UTF-8 bytes per decoded string/key and 20 bytes per number. Reading consumes at
most 16 KiB plus one byte. The caller must supply a deadline or a nonblocking,
already frozen input; the byte bound cannot interrupt an arbitrary blocking
`io.Reader`. All fields are required and non-null. Unknown and case-variant
fields, duplicate keys (including escaped aliases), invalid UTF-8, extra JSON
values and trailing garbage are refused. Numeric tokens must be unsigned base-10
integer spellings in uint64 range, before schema arithmetic runs. No float64
conversion occurs. The schema specifies positive integers, int32-range PIDs and
captures no larger than the existing v1 limit of 64 MiB per daemon. bgpd and
Zebra must have distinct PIDs and epochs.

JSON Schema alone cannot enforce duplicate keys, lexical integer spelling,
distinct producer identities, or the parser's aggregate limits. Consumers must
use `Decode`; validating against the schema is insufficient. A structurally
valid envelope with completely forged labels can decode successfully. It still
cannot become trusted.

## Lifecycle model

`NewLifecycle` accepts only an opaque decoded value; its zero value refuses.
There is deliberately no exported promotion operation. Package-private
`advance` models the following required verification order. Only tests call it
in this slice. Adding a runtime caller is a separate security review boundary.
These stages describe verification of retained trusted context, not a launcher
implemented by this library.

| Stage | Required future proof before promotion |
| --- | --- |
| Decoded | Strict contract validation only, still untrusted |
| LaunchVerified | Live pinned namespace ownership; actual owned children, executable/build/certificate and cohort binding independently verified |
| ProducersStopped | Both owned children reaped, all writers terminated, complete successful shutdown of the expected epochs proven |
| InputsFrozen | Separate inboxes closed to writers, stable regular capture bytes frozen, hashed and matched to the envelope |
| PackageVerified | Trusted packager succeeds on those exact inputs; source hashes, epochs, build/certificate and output digest agree; incomplete/contradictory evidence refused |
| HandoffComplete | Trusted receiver acknowledges this exact result through an authenticated internal channel; namespace pin remains held |
| Consumed | Exactly one result issued for this attempt |

Skipped, repeated, reversed and unknown transitions permanently refuse the
attempt. Abort and premature `Result()` are also terminal. Copies of a lifecycle
share a mutex-protected attempt, so copying a handle cannot duplicate result
issuance. The internal transition tests model a completed handoff to prove every
gate and the single-consumption rule; they do not certify real launch or handoff.

`TrustedResult` has private storage, an invalid zero value, and refuses JSON
serialization and deserialization. It is an in-process capability within the
trusted Go package boundary, not a portable authentication seal. There is no
publicly reachable successful result in this slice. Its
`SelectedFIBVerified()` is always false, even for the completed test model.
Copying a valid internal receipt preserves immutable observations; it does not
authorize a second handoff. Future consumers must enforce their own one-use
handoff acknowledgement.

Refusals expose stable `RefusalCode` values and fixed diagnostics bounded to 160
bytes. They never include hostile keys, values, filenames, reader errors or
secrets. Failed decoding returns no populated envelope. No global replay cache
exists: duplicate serialized labels are not enough to identify a replay. This
slice prevents trust promotion for all such inputs and duplicate result issuance
within an attempt. Rejecting replay across collections requires the future
supervisor's live expected context and consumed handoff tracking.

## Threat model and upcoming acceptance gates

The trusted computing base is the kernel, reviewed collector/supervisor and
packager code, their protected installation, approved certificate policy, and the
receiver. Host administrator or code execution inside that boundary is outside
this model. Envelope senders, producer metadata and producer-writable capture
files are untrusted. UUIDs, hashes and namespace inode numbers are **not
authentication**. Rootless execution alone does not isolate mutually hostile
processes using the same UID.

The next slices must establish all of the following without modifying the
certified FRR producer:

1. The supervisor opens and retains the network namespace FD from before launch
   through capture, packaging and handoff acknowledgement, including error
   cleanup. Its retained FD pins the lifetime; checking a reused inode later
   does not. Compare namespace device/inode through retained descriptors. Boot
   identity and cohort labels supply context, not authority.
2. Launch and retain actual owned child handles and pidfds, reap those children,
   verify namespace membership and executable provenance, and protect against
   PID reuse. Numeric PIDs/start ticks or a later `/proc` lookup alone cannot
   establish ownership. Launch must close unrelated inherited descriptors and
   prevent producers from changing namespace, mounting over observations,
   tracing the supervisor, or altering the other's inputs. A label supplied by
   a producer must match the supervisor's retained facts and frozen stream.
3. Validate launch policy on the pinned FRR build. FRR 10.7.0 bgpd and Zebra
   request `CAP_SYS_ADMIN`; merely removing that capability is not a proven
   compatible launch policy. Test seccomp/capability restrictions against real
   startup, threading, shutdown and namespace operations before claiming
   isolation. No launcher or privilege changes are implemented here.
4. Use two private writable inboxes, one per producer, isolated from each other
   and from supervisor state. After both producers and descendants stop, refuse
   partial/failed streams or missing terminal records. Verify regular files,
   ownership, descriptor-relative lookup, symlink/hardlink policy, byte/resource
   limits and races. Freeze immutable collector-owned copies with no remaining
   writable aliases, then hash the exact bytes used by the packager. Path names
   and chmod alone do not prove immutability.
5. Stage the two frozen inputs separately for the existing trusted packager.
   Verify its reported source digests against those frozen bytes, its complete
   epochs and exit status, and the final output bytes before trusted handoff.
   Child crashes, writer failures, timeouts, mixed epochs, restarts or incomplete
   shutdown must refuse. A restart uses a new owned epoch and collection attempt;
   captures cannot be silently spliced across attempts or namespace lifetimes.
6. Bind the active namespace handle, owned children, expected epochs, approved
   executable artifact set, certificate identity, exact frozen captures and
   bundle to one supervisor-owned attempt. Authorize certificates from protected
   policy, not an envelope selector. The corrected candidate needs a separate
   explicit activation decision; no accepted-build policy changes here.
7. Authenticate the trusted internal handoff by process/channel ownership and
   descriptor capabilities, with an explicit acknowledgement and replay policy.
   Serialized envelopes crossing that boundary need a separately reviewed
   authenticated seal and key/authorization policy. This version provides no
   seal. Never infer trust from JSON, a UUID, a digest or a serialized result.

Adversarial live acceptance must destroy and recreate namespaces, mix old and
new cohorts, reuse numeric PIDs, restart BGP sessions, forge metadata, swap
files/symlinks during freeze, retain writable descriptors, crash during shutdown
and handoff, replay acknowledgements, and corrupt/truncate captures. Those tests
must demonstrate refusal before any result reaches a consumer. The deterministic
unit tests here exercise the contract and model only, not OS isolation.

## Selected-FIB checkpoint is separate

A successful historical data-plane operation or kernel ACK proves neither that
the route is currently selected nor that it remained selected during a later
observation. A future selected-FIB checkpoint needs its own versioned evidence,
namespace/cohort ownership, explicit observation interval and ordering fences,
complete kernel dump/change handling, and same-route/generation/operation linkage
to BGP and recursive provenance. Stale observations, missing ACKs, withdrawals,
concurrent replacement and contradictory generations must refuse the join.
This contract carries no kernel snapshot and cannot satisfy that checkpoint.
Forwarding impact remains unknown until those separate acceptance gates pass.

## Validation

```sh
go test -count=1 ./contrib/frr-correlation/collector
go test -race -count=1 ./contrib/frr-correlation/collector
go test -run='^$' -fuzz=FuzzDecode -fuzztime=10s ./contrib/frr-correlation/collector
./scripts/check.sh --race
```

Tests cover exact integers through MaxUint64, required/non-null fields, strict
JSON and limits, forged identities, replayed envelopes, every invalid transition,
premature results, abort, receipt forgery, concurrent consumption/shutdown and a
negative control that detects unexpected acceptance. Existing Go CI discovers
this package automatically; no separate workflow or new dependency is needed.
