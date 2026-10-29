# Google OSS-Fuzz integration candidate

This directory is a **staging area**, not a live OSS-Fuzz enrollment. It is
intended to become `google/oss-fuzz/projects/network-doctor/` only if the
OSS-Fuzz maintainers accept Network Doctor. No CI or release configuration is
changed by these files.

## Scope

The `gofuzz`-tagged harness in `internal/frrbgp/ossfuzz.go` probes two
network-supplied FRR BGP transcript decoders without opening sockets or starting
network namespaces. The input size cap is 256 KiB. Failed decodes must return a
zero result; repeated successful decodes must agree. Existing Go fuzz targets
are unchanged.

The adapter needs a source file that compiles under the `gofuzz` build tag.
It cannot simply reuse the existing `fuzz_test.go`: its fixtures and helpers
live in other test-only files, which the native Go to libFuzzer adapter does
not automatically include.

## Enrollment

OSS-Fuzz selects established projects with significant usage or critical
infrastructure impact. Acceptance is **not guaranteed**. See
https://google.github.io/oss-fuzz/getting-started/accepting-new-projects/

The `primary_contact` field must identify an established committer and a
Google-account-associated email address. It is deliberately a placeholder
until the maintainer chooses an address. No external request has been sent.

If accepted, copy `Dockerfile`, executable `build.sh`, and a filled-in
`project.yaml.example` (renamed `project.yaml`) into
`google/oss-fuzz/projects/network-doctor/`.

## Required validation before an upstream PR

On a host with Docker, in a clone of google/oss-fuzz, place the three prepared
files in `projects/network-doctor/` and run:

For **pre-merge testing**, change the copied Dockerfile's `ARG NETDOC_REF`
from `main` to `integration/oss-fuzz-preparation`. The default must be
restored to `main` for the upstream integration after merge. The ref override
changes only the disposable OSS-Fuzz build checkout.

```sh
python infra/helper.py build_image network-doctor
python infra/helper.py build_fuzzers --sanitizer address network-doctor
python infra/helper.py check_build network-doctor
```

Review build output and resolve any Go 1.27.3/toolchain or adapter issues before
submitting upstream. This preparation has had **syntax/static review only**:
the complete Docker/libFuzzer build and runtime were not executed.

Go's `F.Add` seeds are **not transferred** to OSS-Fuzz's native Go adapters
automatically. Before long-running fuzzing, add and validate
`netdoc_bgp_summary_seed_corpus.zip` and
`netdoc_bgp_routes_seed_corpus.zip` files in the expected libFuzzer corpus
format, using synthetic/non-sensitive FRR transcripts. These seed archives
should be copied into `$OUT` by `build.sh`. Without them, the harness starts
from arbitrary input and may spend most of its time on the refusal path.

See https://google.github.io/oss-fuzz/getting-started/new-project-guide/go-lang/
for current Go build requirements. ClusterFuzzLite can reuse the same harness
after a separate CI integration is reviewed; it does not require admission.
