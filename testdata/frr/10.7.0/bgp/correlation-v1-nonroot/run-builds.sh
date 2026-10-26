#!/bin/bash
set -euo pipefail
repo=/home/mplaczek/network-doctor/.pr407-worktree
scratch=/home/mplaczek/network-doctor/.pr407-tmp/least-privilege
for build in nonroot-a nonroot-b; do
  podman --root /home/mplaczek/network-doctor/.pr407-tmp/containers --runroot /tmp/netdoc-pr407-containers --storage-driver vfs run --rm --network=none --read-only --cap-drop=ALL --security-opt=no-new-privileges --userns=keep-id:uid=65534,gid=65534 --tmpfs /tmp:rw,nosuid,nodev -v "$repo/contrib/frr-correlation/v1:/producer:ro" -v "$scratch/builds:/work:rw" -v /home/mplaczek/network-doctor/.pr407-tmp/producer-build/frr-source.tar.gz:/input/frr-source.tar.gz:ro localhost/netdoc407-nonroot-builder:v1 bash -c '[[ $(id -u) == 65534 && $(id -g) == 65534 ]]; id; cat /proc/self/uid_map; cat /proc/self/status | sed -n "/^Cap/p;/^NoNewPrivs/p"; [[ ! -w /producer/Containerfile && ! -w /etc/passwd && -w /work ]]; bash /producer/build.sh "/work/$1" /input/frr-source.tar.gz' nonroot-build "$build" > "$scratch/$build.log" 2>&1
  printf '%s: BUILD_PASSED\n' "$build"
done
