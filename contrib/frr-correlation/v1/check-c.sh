#!/bin/bash
# Test-only build in isolated scratch; never install or run FRR daemons.
set -euo pipefail
producer=$(cd "$(dirname "$0")" && pwd)
[[ $(id -u) == 65534 ]]
grep -Eq '^CapEff:[[:space:]]+0+$' /proc/self/status
export LC_ALL=C TZ=UTC SOURCE_DATE_EPOCH=1784130712
export ASAN_OPTIONS=detect_leaks=1:halt_on_error=1
export UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1
cp /opt/ci-packages.txt /work/packages.txt
printf '%s  %s\n' bf601f8f35b03a49a5a45981721394f00d3b9eac0c5bd77577732c4c4ffffa67 /opt/frr-source.tar.gz | sha256sum -c -
tar -xzf /opt/frr-source.tar.gz -C /work
source=/work/frr-87fe21fda92ce9e2ba3eaf2b0a327bf71ee183ef
cd "$source"
patch --batch --fuzz=0 -p1 < "$producer/frr.patch"
cp "$producer/netdoc.c" lib/netdoc.c
cp "$producer/netdoc.h" lib/netdoc.h
cp "$producer/bgp.inc" bgpd/netdoc_bgp.inc
cp "$producer/zebra.inc" zebra/netdoc_zebra.inc
cp "$producer/dplane.inc" zebra/netdoc_dplane.inc
echo '#define NETDOC_BUILD_ID "ci-validation-only"' > lib/netdoc_build.h
./bootstrap.sh

# Native Clippy keeps upstream generator leaks outside the instrumented targets.
mkdir /work/native /work/sanitized
cd /work/native
"$source/configure" --enable-clippy-only --disable-doc --disable-nhrpd --disable-vtysh
make -j2 lib/clippy

cd /work/sanitized
flags=(-O1 -g -UNDEBUG '-fsanitize=address,undefined' -fno-sanitize-recover=all -fno-omit-frame-pointer)
"$source/configure" --with-clippy=/work/native/lib/clippy \
    --enable-user=nobody --enable-group=nogroup --enable-vty-group=nogroup \
    --enable-multipath=64 --disable-doc --disable-snmp --disable-rpki \
    --disable-ldpd --disable-babeld --disable-protobuf --disable-zeromq --disable-grpc \
    CFLAGS="${flags[*]}" CXXFLAGS="${flags[*]}" LDFLAGS=-fsanitize=address,undefined
make -j1 lib/gitversion.h lib/route_types.h lib/vtysh_daemons.h
make -j2 bgpd/bgpd zebra/zebra
nm -u lib/.libs/netdoc.o > /work/netdoc-symbols.txt
grep -q __asan_ /work/netdoc-symbols.txt
grep -q __ubsan_ /work/netdoc-symbols.txt
export LD_LIBRARY_PATH="$PWD/lib/.libs"
flags+=(-DHAVE_CONFIG_H -I. -Ilib -I"$source" -I"$source/lib" -Llib/.libs)
gcc "${flags[@]}" "$producer/writer_test.c" -lfrr -ljson-c -pthread -o /work/writer-test
gcc "${flags[@]}" "$producer/codec_test.c" -lfrr -o /work/codec-test
for name in writer codec; do
    nm -u "/work/$name-test" > "/work/$name-symbols.txt"
    grep -q __assert_fail "/work/$name-symbols.txt"
done
python3 -B -I "$producer/test_writer.py" /work/writer-test | tee /work/writer-tests.log
[[ $(grep -c ': PASS$' /work/writer-tests.log) == 27 ]]
grep -qx WRITER_SHUTDOWN_TESTS_PASSED /work/writer-tests.log
if ! /work/codec-test > /work/codec-tests.log 2> /work/codec-stderr.log; then
    tail -n 40 /work/codec-tests.log /work/codec-stderr.log
    exit 1
fi
grep -x 'CODEC_TESTS_PASSED roundtrips=64 truncations=2227 semantic_negatives=13 mutations=512 max_wire_bytes=2227' /work/codec-tests.log
