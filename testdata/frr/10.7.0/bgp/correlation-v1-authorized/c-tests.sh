#!/bin/bash
set -euo pipefail
cd /work/producer-build/noreplace-a/frr-87fe21fda92ce9e2ba3eaf2b0a327bf71ee183ef
cmp /producer/netdoc.c lib/netdoc.c
gcc -UNDEBUG -DHAVE_CONFIG_H -I. -Ilib /producer/writer_test.c -Llib/.libs -lfrr -ljson-c -pthread -o /work/authorization/writer-test
LD_LIBRARY_PATH="$PWD/lib/.libs" python3 -I /producer/test_writer.py /work/authorization/writer-test
gcc -UNDEBUG -DHAVE_CONFIG_H -I. -Ilib /producer/codec_test.c -Llib/.libs -lfrr -o /work/authorization/codec-test
LD_LIBRARY_PATH="$PWD/lib/.libs" /work/authorization/codec-test
