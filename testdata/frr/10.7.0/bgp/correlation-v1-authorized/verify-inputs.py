from pathlib import Path
import ast
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import types

repo = Path('/home/mplaczek/network-doctor/.pr407-worktree')
p = repo / 'contrib/frr-correlation/v1'
sys.path.insert(0, str(p))
import bundle
old = subprocess.check_output(['git', 'show', '79ea6dde9b2884c05f5567deac41c40061f74a06:contrib/frr-correlation/v1/bundle.py'], cwd=repo, text=True)
baseline = types.ModuleType('baseline')
exec(compile(old, 'baseline-bundle.py', 'exec'), baseline.__dict__)
with tempfile.TemporaryDirectory() as temp:
    root = Path(temp)
    capture = root / 'authorized'
    capture.mkdir()
    outside = root / 'outside'
    outside.write_bytes(b'SYNTHETIC UNAUTHORIZED SENTINEL')
    assert baseline.read_source(outside, 1024) == b'SYNTHETIC UNAUTHORIZED SENTINEL'
    print('BEFORE: unrestricted outside regular-file content read reproduced at 79ea6dd')
    fd = os.open(capture, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for name in (str(outside), '../outside'):
            try:
                bundle.read_source(fd, name, 1024)
            except bundle.Refused:
                print('AFTER: absolute/parent request refused before open/read')
            else:
                raise AssertionError('unauthorized read')
    finally:
        os.close(fd)
for text in (old, (p / 'bundle.py').read_text()):
    tree = ast.parse(text)
    fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'produce')
    fn.body = fn.body[1:]
    fn.args = ast.arguments(posonlyargs=[], args=[], kwonlyargs=[], kw_defaults=[], defaults=[])
    if text == old:
        expected = ast.dump(fn, include_attributes=False)
    else:
        assert ast.dump(fn, include_attributes=False) == expected
print('CORRELATION_LOGIC_AST_IDENTICAL_AFTER_SOURCE_ACQUISITION')
for name in ('frr.patch', 'netdoc.c', 'netdoc.h', 'bgp.inc', 'zebra.inc', 'dplane.inc', 'build.sh',
             'builder-packages.lock', 'Containerfile', 'verified-build.json', 'schema.json',
             'writer_test.c', 'test_writer.py', 'codec_test.c'):
    assert (p / name).read_bytes() == subprocess.check_output(['git', 'show',
        '79ea6dde9b2884c05f5567deac41c40061f74a06:contrib/frr-correlation/v1/' + name], cwd=repo)
print('ALL_C_BUILD_SCHEMA_WRITER_AND_WIRE_TEST_INPUTS_UNCHANGED')
manifest = json.loads((p / 'verified-build.json').read_bytes())
names = ['frr.patch', 'netdoc.c', 'netdoc.h', 'bgp.inc', 'zebra.inc', 'dplane.inc']
implementation = hashlib.sha256(b''.join(n.encode() + b'\0' + (p / n).read_bytes() for n in names)).hexdigest()
assert implementation == manifest['inputs']['implementation_sha256'] == (p / 'implementation.sha256').read_text().strip()
for name in ('noreplace-a', 'noreplace-b'):
    build = repo.parent / '.pr407-tmp/producer-build' / name
    for file, digest in manifest['artifacts'].items():
        assert hashlib.sha256((build / 'frr-root' / file).read_bytes()).hexdigest() == digest, (name, file)
print('BOTH_EXISTING_REPRODUCIBLE_BUILDS_ALL_EIGHT_ARTIFACTS_REVERIFIED', manifest['build_id'])
count = 0
for sums in (repo / 'testdata/frr/10.7.0/bgp').glob('correlation-*/**/SHA256SUMS'):
    if 'correlation-v1-authorized' in sums.parts:
        continue
    for row in sums.read_text().splitlines():
        digest, name = row.split('  ', 1)
        assert hashlib.sha256((sums.parent / name).read_bytes()).hexdigest() == digest, (sums, name)
        count += 1
print('HISTORICAL_SHA256_MANIFEST_ENTRIES_VERIFIED', count)
print('AUTHORIZATION_REGRESSION_REPRODUCED_AND_FIXED')
