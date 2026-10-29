"""Verify the current builder certification and unchanged historical observations."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[4]
PRODUCER = REPO / "contrib/frr-correlation/v1"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def manifest(root):
    names = []
    for row in (root / "SHA256SUMS").read_text().splitlines():
        digest, name = row.split("  ", 1)
        assert not Path(name).is_absolute() and ".." not in Path(name).parts
        assert not (root / name).is_symlink() and sha(root / name) == digest, name
        names.append(name)
    actual = sorted(str(f.relative_to(root)) for f in root.rglob("*") if f.is_file() and f != root / "SHA256SUMS")
    assert sorted(names) == actual and len(names) == len(set(names))


manifest(HERE)
p = json.loads((HERE / "provenance.json").read_bytes())
for name, digest in p["current_implementation_files"].items():
    assert sha(PRODUCER / name) == digest, name
for name, digest in p["historical_manifests"].items():
    path = HERE.parent / name
    assert sha(path) == digest, name
    manifest(path.parent)
builder = json.loads((PRODUCER / "verified-builder.json").read_bytes())
assert builder["default_user"] == "65534:65534"
assert builder["containerfile_sha256"] == sha(PRODUCER / "Containerfile")
assert builder["packages_sha256"] == sha(PRODUCER / "builder-packages.lock")
image = json.loads((HERE / "builder-image.json").read_bytes())[0]
assert image["Id"] == builder["image_id"] and image["Digest"] == builder["image_digest"]
assert image["Config"]["User"] == builder["default_user"]
expected = json.loads((PRODUCER / "verified-build.json").read_bytes())
a = json.loads((HERE / "nonroot-a-build.json").read_bytes())
b = json.loads((HERE / "nonroot-b-build.json").read_bytes())
assert a == b and a["artifacts"] == expected["artifacts"] and a["build_id"] == expected["build_id"]
assert (HERE / "build.json").read_bytes() == (PRODUCER / "verified-build.json").read_bytes()
names = ["frr.patch", "netdoc.c", "netdoc.h", "bgp.inc", "zebra.inc", "dplane.inc"]
assert hashlib.sha256(b"".join(n.encode() + b"\0" + (PRODUCER / n).read_bytes() for n in names)).hexdigest() == expected["inputs"]["implementation_sha256"]
assert sha(PRODUCER / "bundle.py") == "0272f21b8f3a6344f6cad8436d2f532157ea1b9a8d0dbab3d8d233237408a24d"
isolation = json.loads((HERE / "isolation.json").read_bytes())
assert isolation["uid"] == isolation["gid"] == 65534 and isolation["no_new_privileges"]
assert all(int(v, 16) == 0 for v in isolation["capabilities"].values())
assert all(not (flags & 1) for name, flags in isolation["interface_flags"].items() if name != "lo")
assert all(row.get("dev") == "lo" for rows in isolation["all_table_routes"].values() for row in rows)
assert len(isolation["protected_writes_refused"]) == 4 and isolation["scratch_write_succeeded"]
spec = importlib.util.spec_from_file_location("trusted_bundle", PRODUCER / "bundle.py")
bundle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bundle)
fd = os.open(HERE / "proof/identity/r1", os.O_RDONLY | os.O_DIRECTORY)
try:
    result = bundle.produce(fd)
finally:
    os.close(fd)
assert (json.dumps(result, indent=2, sort_keys=True) + "\n").encode() == (HERE / "proof-bundle.json").read_bytes()
fd = os.open(HERE / "restart/identity/r1", os.O_RDONLY | os.O_DIRECTORY)
try:
    try:
        bundle.produce(fd)
    except bundle.Refused:
        pass
    else:
        raise AssertionError("restart accepted")
finally:
    os.close(fd)
refused = json.loads((HERE / "restart-refusal.json").read_bytes())
assert not refused["claims"] and not refused["capture"]["complete"]
fd = os.open(HERE / "initial-proof/identity/r1", os.O_RDONLY | os.O_DIRECTORY)
try:
    initial = bundle.produce(fd)
finally:
    os.close(fd)
assert (json.dumps(initial, indent=2, sort_keys=True) + "\n").encode() == (HERE / "initial-proof-bundle.json").read_bytes()
starts = [json.loads(f.read_bytes().splitlines()[0]) for f in sorted((HERE / "namespace-alias-negative").glob("*.jsonl"))]
assert len(starts) == 2 and starts[0]["netns_inode"] == starts[1]["netns_inode"]
fd = os.open(HERE / "namespace-alias-negative", os.O_RDONLY | os.O_DIRECTORY)
try:
    try:
        bundle.produce(fd)
    except bundle.Refused as error:
        assert str(error) == "missing BGP submission"
    else:
        raise AssertionError("observed namespace alias mixture was accepted")
finally:
    os.close(fd)
alias = json.loads((HERE / "namespace-alias-refusal.json").read_bytes())
assert alias["claims"] == [] and alias["capture"]["complete"] is False
print("NONROOT_BUILDER_AND_GENUINE_EVIDENCE_VERIFIED")
