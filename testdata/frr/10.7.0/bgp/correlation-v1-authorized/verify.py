"""Verify this derived proof against immutable genuine captures and pinned inputs."""
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
        path = root / name
        assert not path.is_symlink() and sha(path) == digest, name
        names.append(name)
    actual = sorted(str(f.relative_to(root)) for f in root.rglob("*")
                    if f.is_file() and f != root / "SHA256SUMS")
    assert sorted(names) == actual and len(names) == len(set(names))


manifest(HERE)
provenance = json.loads((HERE / "provenance.json").read_bytes())
for name, digest in provenance["current_implementation_files"].items():
    assert sha(PRODUCER / name) == digest, name
build = json.loads((PRODUCER / "verified-build.json").read_bytes())
assert build["build_id"] == provenance["unchanged_frr_build_id"]
names = ["frr.patch", "netdoc.c", "netdoc.h", "bgp.inc", "zebra.inc", "dplane.inc"]
implementation = hashlib.sha256(b"".join(n.encode() + b"\0" + (PRODUCER / n).read_bytes()
                                           for n in names)).hexdigest()
assert implementation == build["inputs"]["implementation_sha256"]
for name, digest in provenance["historical_manifests"].items():
    path = HERE.parent / name
    assert sha(path) == digest, name
    manifest(path.parent)

spec = importlib.util.spec_from_file_location("trusted_bundle", PRODUCER / "bundle.py")
bundle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bundle)
raw = HERE.parent / "correlation-v1-noreplace"
fd = os.open(raw / "proof/identity/r1", os.O_RDONLY | os.O_DIRECTORY)
try:
    result = bundle.produce(fd)
finally:
    os.close(fd)
encoded = (json.dumps(result, indent=2, sort_keys=True) + "\n").encode()
assert encoded == (HERE / "proof-bundle.json").read_bytes() == (raw / "proof-bundle.json").read_bytes()
fd = os.open(raw / "restart/identity/r1", os.O_RDONLY | os.O_DIRECTORY)
try:
    try:
        bundle.produce(fd)
    except bundle.Refused:
        pass
    else:
        raise AssertionError("genuine restart was accepted")
finally:
    os.close(fd)
refusal = json.loads((HERE / "restart-refusal.json").read_bytes())
assert refusal["claims"] == [] and refusal["capture"]["complete"] is False
print("AUTHORIZED_PACKAGER_PROVENANCE_AND_GENUINE_REPROCESSING_VERIFIED")
