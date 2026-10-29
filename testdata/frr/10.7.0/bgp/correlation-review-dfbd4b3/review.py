"""Replay the original offline verifier and test every reported address use in memory."""
import ast
import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys

HERE = Path(__file__).resolve().parent
SOURCE = HERE.parent / "correlation-investigation/verify.py"
ROOT = SOURCE.parent
RAW = SOURCE.read_bytes()
assert hashlib.sha256(RAW).hexdigest() == "ba38ab6f93eb1715c6dbb265e7c8585c5b6deb547e6fa928537b0745f7c68d5f"
TREE = ast.parse(RAW)
ISSUES = json.loads((HERE / "baseline-issues.json").read_bytes())["issues"]
FINDINGS = sorted((x for x in ISSUES if x["rule"] == "python:S1313" and x["status"] == "OPEN"),
                  key=lambda x: (x["line"], x["textRange"]["startOffset"]))
assert len(FINDINGS) == 35 and len({x["key"] for x in FINDINGS}) == 35
assert {n.names[0].name for n in TREE.body if isinstance(n, ast.Import)} == {"hashlib", "json"}
assert [(n.module, [a.name for a in n.names]) for n in TREE.body if isinstance(n, ast.ImportFrom)] == [("pathlib", ["Path"])]

# Each entry identifies the actual immutable observation and the value's local use.
CONTEXT = {
    81: ("withdraw", ["r1-before-show_ip_bgp_json.raw"], "select captured route / compare its peer set"),
    82: ("withdraw", ["r1-after1-show_ip_bgp_json.raw"], "select captured route / compare remaining peer list"),
    83: ("withdraw", ["r1-after2-show_ip_bgp_json.raw"], "assert withdrawn prefix absent from captured BGP dictionary"),
    86: ("withdraw", ["r1-before-show_ip_route_json.raw", "r1-after1-show_ip_route_json.raw", "r1-after2-show_ip_route_json.raw"], "installed indexes captured routes and asserts selected/installed connected metadata"),
    87: ("withdraw", ["r1-before-show_ip_route_json.raw", "r1-after1-show_ip_route_json.raw", "r1-after2-show_ip_route_json.raw"], "installed indexes captured routes and asserts selected/installed BGP metadata"),
    88: ("withdraw", ["r1-before-ip_route.json", "r1-after1-ip_route.json", "r1-after2-ip_route.json"], "assert connected prefix present in captured kernel dictionary"),
    89: ("withdraw", ["r1-after2-show_ip_route_json.raw"], "assert withdrawn prefix absent from captured Zebra dictionary"),
    90: ("withdraw", ["r1-after2-ip_route.json"], "assert withdrawn prefix absent from captured kernel dictionary"),
    93: ("session-plain", ["r1-before-show_ip_bgp_json.raw"], "assert captured paths include the peer before session loss"),
    94: ("session-plain", ["r1-after-show_ip_bgp_json.raw"], "assert captured paths exclude the lost peer"),
    97: ("session-plain", ["r1-after-show_ip_bgp_summary_json.raw"], "index captured peer and assert it is not Established"),
    98: ("session-plain", ["r1-after-show_ip_bgp_summary_json.raw"], "index captured peer and assert it remains Established"),
    99: ("session-plain", ["r1-after-show_ip_route_json.raw"], "assert lost prefix absent from captured Zebra dictionary"),
    100: ("session-plain", ["r1-after-ip_route.json"], "assert lost prefix absent from captured kernel dictionary"),
    104: ("recursive-shared", ["r1-before-bgp-detail.raw"], "select captured path list for subsequent path-count and attribute assertions"),
    106: ("recursive-shared", ["r1-before-bgp-detail.raw"], "compare captured peer set; does not choose an owner"),
    108: ("recursive-shared", ["r1-before-bgp-detail.raw"], "compare captured shared next-hop attribute"),
    112: ("recursive-shared", ["r1-before-show_ip_route_json.raw"], "select installed captured BGP route; assert one FIB leg and one duplicate"),
    119: ("recursive-shared", ["r1-before-show_ip_route_json.raw"], "select captured resolver route; compare recorded nexthop group IDs"),
    123: ("recursive-shared", ["r1-before-show_ip_route_json.raw"], "assert recorded recursive gateway on both captured consuming routes"),
    124: ("recursive-shared", ["r1-before-show_ip_route_json.raw"], "assert recorded resolver/FIB gateway on both captured consuming routes"),
    127: ("recursive-shared", ["r1-before-nht.raw"], "index captured NHT resolution list for later assertions"),
    128: ("recursive-shared", ["r1-before-nht.raw"], "compare captured resolver prefix and origin"),
    132: ("recursive-shared", ["r1-before-bgp-nexthop.raw"], "index captured BGP next-hop cache / compare its resolved prefix"),
    133: ("recursive-shared", ["r1-before-bgp-nexthop.raw"], "index captured cache / count captured paths with the prefix"),
    137: ("recursive-shared", ["r1-before-get.json", "r1-before-fibmatch.json"], "compare recorded route-get and fibmatch destinations, without executing either command"),
    140: ("recursive-shared", ["r1-after-show_ip_route_json.raw", "r1-after-ip_route.json"], "iterate expected absent prefixes and assert absence in both captured dictionaries"),
    146: ("recursive-shared", ["r1-after-nht.raw"], "index captured NHT entry and assert recorded unresolved state and empty legs"),
}


class ForbiddenEffect(RuntimeError):
    pass


active = False
observed = []


def audit(event, args):
    if not active:
        return
    forbidden = event.startswith(("socket.", "subprocess.", "ctypes.")) or event in {
        "os.system", "os.exec", "os.posix_spawn", "os.spawn", "os.fork", "os.forkpty",
        "os.remove", "os.rmdir", "os.rename", "os.mkdir", "os.link", "os.symlink",
        "os.truncate", "os.chmod", "os.chown", "os.setxattr", "os.removexattr"}
    if event == "open":
        mode, flags = args[1:]
        forbidden = bool(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND)) \
            or bool(mode and any(c in mode for c in "wax+"))
    if forbidden:
        observed.append(event)
        raise ForbiddenEffect(event)


sys.addaudithook(audit)
# Prove the monitor actually refuses networking, process creation and file writes.
monitor = []
for operation in (lambda: socket.socket(),
                  lambda: subprocess.run([sys.executable, "-c", "pass"], check=True),
                  lambda: os.open("/review-must-not-create", os.O_CREAT | os.O_WRONLY, 0o600)):
    active = True
    try:
        operation()
    except ForbiddenEffect as error:
        monitor.append(str(error))
    else:
        raise AssertionError("monitor did not reject side effect")
    finally:
        active = False
assert monitor == ["socket.__new__", "subprocess.Popen", "open"]
observed.clear()


def run(tree):
    global active
    namespace = {"__file__": str(SOURCE), "__name__": "__main__"}
    active = True
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            exec(compile(tree, str(SOURCE), "exec"), namespace)
    finally:
        active = False
    assert not observed
    return namespace


baseline = run(TREE)
records = []
for issue in FINDINGS:
    location = issue["textRange"]
    line, start, end = issue["line"], location["startOffset"], location["endOffset"]
    constants = [n for n in ast.walk(TREE) if isinstance(n, ast.Constant) and isinstance(n.value, str)
                 and n.lineno == line and n.col_offset <= start and n.end_col_offset >= end]
    assert len(constants) == 1
    node = constants[0]
    arm, names, flow = CONTEXT[line]
    mutation = copy.deepcopy(TREE)
    target = next(n for n in ast.walk(mutation) if isinstance(n, ast.Constant)
                  and n.lineno == node.lineno and n.col_offset == node.col_offset)
    # Absence checks must be challenged with a key/peer actually present in the recording.
    if line == 83:
        replacement = next(iter(baseline["after2"]))
    elif line == 94:
        replacement = next(p["peerId"] for paths in baseline["bgp"](ROOT / arm, "after").values() for p in paths)
    elif line in (89, 90, 99, 100, 140):
        phase = "after2" if line in (89, 90) else "after"
        reader = baseline["kernel"] if line in (90, 100) else baseline["zebra"]
        replacement = next(iter(reader(ROOT / arm, phase)))
    else:
        replacement = "REVIEW_UNMATCHED_VALUE"
    assert replacement != node.value
    target.value = replacement
    try:
        run(mutation)
    except (AssertionError, KeyError) as error:
        outcome = type(error).__name__
    else:
        raise AssertionError("finding mutation was not detected: " + issue["key"])
    assert not observed
    evidence = [{"file": arm + "/" + name,
                 "sha256": hashlib.sha256((ROOT / arm / name).read_bytes()).hexdigest()}
                for name in names]
    records.append({"issue": issue["key"], "rule": issue["rule"], "line": line,
                    "start_offset": start, "end_offset": end, "literal": node.value,
                    "source_expression": ast.get_source_segment(RAW.decode(), node),
                    "source_line": RAW.decode().splitlines()[line - 1], "flow": flow,
                    "evidence": evidence, "classification": "legitimate fixed test data with proven safe usage",
                    "genuine_defect": False, "network_or_routing_effect": "none; builtin JSON selection/comparison only",
                    "security_decision": "affects offline fixture-validation success only; no authentication, authorization or configuration decision",
                    "behavioral_proof": {"one_literal_changed_in_memory": True, "replacement": replacement,
                                         "detected_as": outcome, "forbidden_effects": list(observed)},
                    "remote_disposition": "unchanged; independent ChatGPT approval required"})
print(json.dumps({"schema": "netdoc-frr-address-review/v1", "head": "dfbd4b30ccdd2daa0bce4f18bef384de2ebae4a9",
                  "source": "../correlation-investigation/verify.py", "source_sha256": hashlib.sha256(RAW).hexdigest(),
                  "baseline_passes_with_effect_guards": True, "guard_self_tests": monitor,
                  "scope": "Pinned offline verifier and original local immutable observations; not a general untrusted-code sandbox",
                  "findings": records}, sort_keys=True, indent=2))
