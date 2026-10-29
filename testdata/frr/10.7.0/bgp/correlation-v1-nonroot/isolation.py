import json
import os
from pathlib import Path
import socket
import subprocess

assert os.getuid() == os.getgid() == 65534
status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
for key in ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb'):
    assert int(status[key].strip(), 16) == 0, key
assert status['NoNewPrivs'].strip() == '1'
interfaces = socket.if_nameindex()
flags = {name: int((Path('/sys/class/net') / name / 'flags').read_text(), 16) for _, name in interfaces}
assert all(not (value & 1) for name, value in flags.items() if name != 'lo')
assert os.readlink('/proc/self/ns/net') != Path('/checks/host-netns.txt').read_text().strip()
assert all(line.split()[-1] == 'lo' for line in Path('/proc/net/ipv6_route').read_text().splitlines())
assert len(Path('/proc/net/route').read_text().splitlines()) == 1
routes = {family: json.loads(subprocess.check_output(['ip', '-j', family, 'route', 'show', 'table', 'all'])) for family in ('-4', '-6')}
assert all(route.get('dev') == 'lo' for rows in routes.values() for route in rows)
refused = []
for path in ('/producer/.least-privilege-probe', '/repo/.least-privilege-probe', '/etc/.least-privilege-probe'):
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError as error:
        assert error.errno in (13, 30), (path, error)
        refused.append({'path': path, 'errno': error.errno})
    else:
        os.close(fd)
        raise AssertionError('unexpected writable protected path: ' + path)
try:
    fd = os.open('/input/frr-source.tar.gz', os.O_WRONLY)
except OSError as error:
    assert error.errno in (13, 30)
    refused.append({'path': '/input/frr-source.tar.gz', 'errno': error.errno})
else:
    os.close(fd)
    raise AssertionError('unexpected writable input archive')
probe = Path('/work/isolation-scratch-probe')
with probe.open('x') as f:
    f.write('authorized scratch only\n')
probe.unlink()
print(json.dumps({'uid': os.getuid(), 'gid': os.getgid(), 'uid_map': Path('/proc/self/uid_map').read_text(),
                  'capabilities': {k: status[k].strip() for k in ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb')},
                  'no_new_privileges': True, 'all_table_routes': routes, 'interfaces': interfaces, 'interface_flags': flags, 'network_namespace': os.readlink('/proc/self/ns/net'),
                  'protected_writes_refused': refused, 'scratch_write_succeeded': True}, sort_keys=True, indent=2))
