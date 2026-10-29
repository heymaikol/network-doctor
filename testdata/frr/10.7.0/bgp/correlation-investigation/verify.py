"""Verify preserved observations, never infer BGP-to-FIB ownership or a rating."""

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def manifest(directory, recursive=False):
    rows = (directory / "SHA256SUMS").read_text().splitlines()
    listed = []
    for row in rows:
        digest, name = row.split("  ", 1)
        path = directory / name
        assert path.is_file() and not path.is_symlink(), name
        assert hashlib.sha256(path.read_bytes()).hexdigest() == digest, name
        listed.append(name)
    assert len(listed) == len(set(listed)), "duplicate manifest entries"
    paths = directory.rglob("*") if recursive else directory.iterdir()
    actual = sorted(str(p.relative_to(directory)) for p in paths if p.is_file()
                    and p != directory / "SHA256SUMS")
    assert sorted(listed) == actual, "manifest is incomplete"


def pairs(items):
    result = {}
    for key, value in items:
        assert key not in result, ("duplicate JSON key", key)
        result[key] = value
    return result


def constant(value):
    raise ValueError(value)


def load(path):
    return json.loads(path.read_bytes(), object_pairs_hook=pairs, parse_constant=constant)


def frame(directory, name, command, node="r1"):
    data = (directory / name).read_bytes()
    head, tail = command.encode() + b"\r\n", b"\r\n" + node.encode() + b"> "
    assert data.startswith(head) and data.endswith(tail), name
    result = json.loads(data[len(head):-len(tail)], object_pairs_hook=pairs,
                        parse_constant=constant)
    assert isinstance(result, dict), name
    return result


def bgp(directory, phase):
    return frame(directory, f"r1-{phase}-show_ip_bgp_json.raw", "show ip bgp json")["routes"]


def zebra(directory, phase):
    return frame(directory, f"r1-{phase}-show_ip_route_json.raw", "show ip route json")


def kernel(directory, phase):
    return {row["dst"]: row for row in load(directory / f"r1-{phase}-ip_route.json")}


def installed(rows, prefix, origin):
    matches = [r for r in rows[prefix] if r.get("destSelected")]
    assert len(matches) == 1, prefix
    route = matches[0]
    assert route["protocol"] == origin and route["installed"] is True, prefix
    return route


manifest(ROOT, recursive=True)
for arm in ("withdraw", "session-plain", "recursive-shared"):
    directory = ROOT / arm
    manifest(directory)
    assert (ROOT / f"{arm}-terminal.log").read_text().splitlines()[-1] == "DONE"
    assert not list(directory.glob("*.failed"))

withdraw = ROOT / "withdraw"
before, after1, after2 = [bgp(withdraw, p) for p in ("before", "after1", "after2")]
assert {p["peerId"] for p in before["10.10.2.0/24"]} == {"10.0.1.2", "10.0.3.3"}
assert [p["peerId"] for p in after1["10.10.2.0/24"]] == ["10.0.3.3"]
assert "10.10.9.0/24" not in after2
for phase in ("before", "after1", "after2"):
    routes = zebra(withdraw, phase)
    installed(routes, "10.10.1.0/24", "connected")
    installed(routes, "10.10.2.0/24", "bgp")
    assert "10.10.1.0/24" in kernel(withdraw, phase)
assert "10.10.9.0/24" not in zebra(withdraw, "after2")
assert "10.10.9.0/24" not in kernel(withdraw, "after2")

session = ROOT / "session-plain"
assert any(p["peerId"] == "10.0.1.2" for ps in bgp(session, "before").values() for p in ps)
assert all(p["peerId"] != "10.0.1.2" for ps in bgp(session, "after").values() for p in ps)
summary = frame(session, "r1-after-show_ip_bgp_summary_json.raw", "show ip bgp summary json")
peers = summary["ipv4Unicast"]["peers"]
assert peers["10.0.1.2"]["state"] != "Established"
assert peers["10.0.3.3"]["state"] == "Established"
assert "10.10.9.0/24" not in zebra(session, "after")
assert "10.10.9.0/24" not in kernel(session, "after")

shared = ROOT / "recursive-shared"
detail = frame(shared, "r1-before-bgp-detail.raw", "show ip bgp detail json")
paths = detail["routes"]["10.10.2.0/24"]
assert len(paths) == 2
assert {p["peer"]["peerId"] for p in paths} == {"10.0.1.2", "10.0.3.3"}
assert all(p["aspath"]["string"] == "65002" and p["fibInstalled"] is True
           and p["multipath"] is True and p["nexthops"][0]["ip"] == "10.0.1.2"
           for p in paths)
assert sum(p.get("bestpath", {}).get("overall", False) for p in paths) == 1
routes = zebra(shared, "before")
route = installed(routes, "10.10.2.0/24", "bgp")
assert sum(n.get("fib", False) for n in route["nexthops"]) == 1
assert sum(n.get("duplicate", False) for n in route["nexthops"]) == 1
assert "peerId" not in route and all("peerId" not in n for n in route["nexthops"])

static = installed(routes, "198.51.100.0/24", "static")
recursive = installed(routes, "203.0.113.0/24", "bgp")
resolver = installed(routes, "10.10.9.0/24", "bgp")
assert static["nexthopGroupId"] == recursive["nexthopGroupId"]
assert static["installedNexthopGroupId"] == resolver["installedNexthopGroupId"]
for route in (static, recursive):
    assert any(n.get("recursive") and n["ip"] == "10.10.9.2" for n in route["nexthops"])
    assert any(n.get("resolver") and n.get("fib") and n["ip"] == "10.0.1.2"
               for n in route["nexthops"])
nht = frame(shared, "r1-before-nht.raw", "show ip nht json")
resolutions = nht["default"]["ipv4"]["10.10.9.2"]["resolutions"]
assert all(r["prefix"] == "10.10.9.0/24" and r["resolvedProtocol"] == "bgp"
           for r in resolutions)
assert {c["protocol"] for r in resolutions for c in r["clientList"]} == {"static", "bgp"}
cache = frame(shared, "r1-before-bgp-nexthop.raw", "show ip bgp nexthop detail json")
assert cache["ipv4"]["10.10.9.2"]["resolvedPrefix"] == "10.10.9.0/24"
assert sum(p["prefix"] == "10.10.2.0/24" for p in cache["ipv4"]["10.0.1.2"]["paths"]) == 2
assert kernel(shared, "before")["198.51.100.0/24"]["protocol"] == "196"
lookup = load(shared / "r1-before-get.json")[0]
fibmatch = load(shared / "r1-before-fibmatch.json")[0]
assert lookup["dst"] == "10.10.9.2" and fibmatch["dst"] == "10.10.9.0/24"
assert (shared / "r1-before-get.status").read_text().strip() == "0"
assert (shared / "r1-before-fibmatch.status").read_text().strip() == "0"
for prefix in ("10.10.9.0/24", "198.51.100.0/24", "203.0.113.0/24"):
    assert prefix not in zebra(shared, "after") and prefix not in kernel(shared, "after")
after_detail = frame(shared, "r1-after-bgp-detail.raw", "show ip bgp detail json")
assert all(p["valid"] is False for p in after_detail["routes"]["203.0.113.0/24"])
after_nht = frame(shared, "r1-after-nht.raw", "show ip nht json")
assert all(r["unresolved"] is True and not r["nexthops"]
           for r in after_nht["default"]["ipv4"]["10.10.9.2"]["resolutions"])
for name in ("get", "fibmatch"):
    assert int((shared / f"r1-after-{name}.status").read_text()) != 0
    assert (shared / f"r1-after-{name}.stderr").read_text().strip()
for start in shared.glob("*.started_at"):
    assert start.read_text().strip() <= start.with_suffix(".finished_at").read_text().strip()
for phase in ("before", "after"):
    for name, command in (("bgp-detail-end", "show ip bgp detail json"),
                          ("route-end", "show ip route json"),
                          ("fib", "show ip fib json"),
                          ("nhg", "show nexthop-group rib json")):
        frame(shared, f"r1-{phase}-{name}.raw", command)
    frame(shared, f"r2-{phase}-bgp.raw", "show ip bgp json", node="r2")

print("Complete manifests and live observations verified; no forwarding attribution asserted.")
