#!/bin/bash
set -euo pipefail
cd /home/mplaczek/network-doctor/.pr407-authorization-integration
scratch=/home/mplaczek/network-doctor/.pr407-tmp/authorization
export GOTOOLCHAIN=go1.27.3 GOMEMLIMIT=2GiB TMPDIR=/home/mplaczek/network-doctor/.pr407-tmp/gotmp
go version > "$scratch/toolchain.txt"
git diff --exit-code
git diff --cached --check 79ea6dde9b2884c05f5567deac41c40061f74a06
git write-tree > "$scratch/integrated-tree.txt"
podman --root /home/mplaczek/network-doctor/.pr407-tmp/containers --runroot /tmp/netdoc-pr407-containers --storage-driver vfs run --rm --network=none -v "$PWD:/repo:ro" -w /repo/contrib/frr-correlation/v1 localhost/netdoc407-locked-builder:v1 python3 -B -m unittest -v test_bundle > "$scratch/integrated-producer-tests.log" 2>&1
./scripts/check --race > "$scratch/check-race.log" 2>&1
go test -race -tags integration ./internal/app ./internal/diagnostic ./internal/peer ./internal/simulation > "$scratch/integration-race.log" 2>&1
go test -tags netns_integration -count=1 -v -run '^TestRouteEvents' ./internal/diagnostic > "$scratch/route-events.log" 2>&1
git diff --exit-code
[[ "$(git write-tree)" == "$(cat "$scratch/integrated-tree.txt")" ]]
printf 'EXACT_TREE_VALIDATION_PASSED\n'
