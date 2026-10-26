#!/bin/bash
set -euo pipefail
cd /repo/contrib/frr-correlation/v1
python3 -B -m unittest -v test_bundle > /work/producer-tests.log 2>&1
python3 -B -I /repo/testdata/frr/10.7.0/bgp/correlation-review-dfbd4b3/review.py > /work/address-review.json
python3 -B -I /checks/isolation.py > /work/isolation.json
rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' | LC_ALL=C sort | cmp /producer/builder-packages.lock -
cd /work/nonroot-a/frr-87fe21fda92ce9e2ba3eaf2b0a327bf71ee183ef
cmp /producer/netdoc.c lib/netdoc.c
gcc -UNDEBUG -DHAVE_CONFIG_H -I. -Ilib /producer/writer_test.c -Llib/.libs -lfrr -ljson-c -pthread -o /work/writer-test
LD_LIBRARY_PATH="$PWD/lib/.libs" python3 -I /producer/test_writer.py /work/writer-test > /work/writer-tests.log 2>&1
printf 'NONROOT_ISOLATION_PRODUCER_REVIEW_WRITER_TESTS_PASSED\n'
