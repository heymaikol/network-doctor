#!/bin/bash -eu
# Runs only in the disposable OSS-Fuzz builder checkout, not release builds.
cd "$SRC/network-doctor"
export PATH="$(go env GOPATH)/bin:$PATH"
# Native-Go-to-libFuzzer adapter; pin the upstream source commit.
go install github.com/AdamKorcz/go-118-fuzz-build@a70c2aa677fa43583571959478decabe02a96cd6
# The adapter rewrites imports to its testing shim in the builder checkout.
go get github.com/AdamKorcz/go-118-fuzz-build/testing@a70c2aa677fa43583571959478decabe02a96cd6
compile_native_go_fuzzer github.com/heymaikol/network-doctor/v2/internal/frrbgp FuzzOSSDecodeSummary netdoc_bgp_summary
compile_native_go_fuzzer github.com/heymaikol/network-doctor/v2/internal/frrbgp FuzzOSSDecodeRouteCapture netdoc_bgp_routes
