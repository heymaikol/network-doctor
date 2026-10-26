#!/bin/bash
# Run inside the locked builder with --network=none. No system installation.
set -euo pipefail
producer=$(cd "$(dirname "$0")" && pwd)
out=${1:?output directory, must not exist}
archive=${2:?pinned FRR source archive}
[[ $(uname -m) == x86_64 ]] || { echo "unsupported build architecture" >&2; exit 2; }
rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' | LC_ALL=C sort | cmp "$producer/builder-packages.lock" -
printf '%s  %s\n' bf601f8f35b03a49a5a45981721394f00d3b9eac0c5bd77577732c4c4ffffa67 "$archive" | sha256sum -c -
mkdir "$out"
out=$(cd "$out" && pwd)
tar -xzf "$archive" -C "$out"
cd "$out/frr-87fe21fda92ce9e2ba3eaf2b0a327bf71ee183ef"
patch --batch --fuzz=0 -p1 < "$producer/frr.patch"
cp "$producer/netdoc.c" lib/netdoc.c
cp "$producer/netdoc.h" lib/netdoc.h
cp "$producer/bgp.inc" bgpd/netdoc_bgp.inc
cp "$producer/zebra.inc" zebra/netdoc_zebra.inc
cp "$producer/dplane.inc" zebra/netdoc_dplane.inc
python3 -I - "$producer" "$out" <<'PY'
from pathlib import Path
import hashlib, json, sys
p, out = map(Path, sys.argv[1:])
names = ['frr.patch', 'netdoc.c', 'netdoc.h', 'bgp.inc', 'zebra.inc', 'dplane.inc']
implementation = hashlib.sha256(b''.join(n.encode() + b'\0' + (p/n).read_bytes() for n in names)).hexdigest()
inputs = {'source': '87fe21fda92ce9e2ba3eaf2b0a327bf71ee183ef',
          'archive_sha256': 'bf601f8f35b03a49a5a45981721394f00d3b9eac0c5bd77577732c4c4ffffa67',
          'implementation_sha256': implementation,
          'packages_sha256': hashlib.sha256((p/'builder-packages.lock').read_bytes()).hexdigest(),
          'configuration': ['--prefix=/usr', '--sbindir=/usr/libexec/frr', '--libdir=/usr/lib64/frr',
              '--libexecdir=/usr/libexec/frr', '--sysconfdir=/etc', '--localstatedir=/var',
              '--enable-user=root', '--enable-group=root', '--enable-vty-group=root', '--enable-multipath=64',
              '--disable-doc', '--disable-snmp', '--disable-rpki', '--disable-ldpd', '--disable-babeld',
              '--disable-protobuf', '--disable-zeromq', '--disable-grpc'],
          'cflags': '-O2 -g0 -ffile-prefix-map=SOURCE=. -fmacro-prefix-map=SOURCE=.',
          'source_date_epoch': 1784130712}
build_id = hashlib.sha256(json.dumps(inputs, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
Path('lib/netdoc_build.h').write_text('#define NETDOC_BUILD_ID "'+build_id+'"\n')
(out/'build.json').write_text(json.dumps({'schema': 'netdoc-frr-build/v1', 'source': inputs['source'],
    'build_id': build_id, 'inputs': inputs}, sort_keys=True, indent=2)+'\n')
PY
export LC_ALL=C TZ=UTC SOURCE_DATE_EPOCH=1784130712
./bootstrap.sh
mapfile -t configure_args < <(python3 -I -c 'import json,sys; print("\n".join(json.load(open(sys.argv[1]))["inputs"]["configuration"]))' "$out/build.json")
./configure "${configure_args[@]}" CFLAGS="-O2 -g0 -ffile-prefix-map=$PWD=. -fmacro-prefix-map=$PWD=." \
  CXXFLAGS="-O2 -g0 -ffile-prefix-map=$PWD=. -fmacro-prefix-map=$PWD=."
make -j8 bgpd/bgpd zebra/zebra staticd/staticd mgmtd/mgmtd vtysh/vtysh
gcc -UNDEBUG -DHAVE_CONFIG_H -I. -Ilib "$producer/codec_test.c" -Llib/.libs -lfrr -o "$out/codec-test"
LD_LIBRARY_PATH="$PWD/lib/.libs" "$out/codec-test"
mkdir -p "$out/frr-root/usr/libexec/frr" "$out/frr-root/usr/bin" "$out/frr-root/usr/lib64/frr"
for daemon in bgpd zebra staticd mgmtd; do cp "$daemon/.libs/$daemon" "$out/frr-root/usr/libexec/frr/"; done
cp vtysh/.libs/vtysh "$out/frr-root/usr/bin/"
cp -L lib/.libs/libfrr.so.0 mgmtd/.libs/libmgmt_be_nb.so.0 "$out/frr-root/usr/lib64/frr/"
cp -L /usr/lib64/libyang.so.3 "$out/frr-root/usr/lib64/"
python3 -I - "$out" <<'PY'
from pathlib import Path
import hashlib, json, sys
p = Path(sys.argv[1])
build = json.loads((p/'build.json').read_text())
build['artifacts'] = {str(f.relative_to(p/'frr-root')): hashlib.sha256(f.read_bytes()).hexdigest()
                      for f in sorted((p/'frr-root').rglob('*')) if f.is_file()}
(p/'build.json').write_text(json.dumps(build, sort_keys=True, indent=2)+'\n')
(p/'SHA256SUMS').write_text(''.join(h+'  frr-root/'+n+'\n' for n,h in build['artifacts'].items())
                          + hashlib.sha256((p/'build.json').read_bytes()).hexdigest()+'  build.json\n')
PY
(cd "$out" && sha256sum -c --strict SHA256SUMS)
echo BUILD_DONE
