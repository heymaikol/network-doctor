# Individual review of all 35 S1313 findings

Baseline head: dfbd4b30ccdd2daa0bce4f18bef384de2ebae4a9.
Every finding affects correlation-investigation/verify.py, whose exact SHA256 is
ba38ab6f93eb1715c6dbb265e7c8585c5b6deb547e6fa928537b0745f7c68d5f.
No source byte, expected value or original observation is changed.

Classification counts: 35 legitimate fixed test-data uses with proven safe usage;
0 genuine address-related vulnerabilities, 0 claimed rule-detection false
positives, 0 accepted unresolved risks, 0 cases left uninvestigated.
These are local assessments, not remote dispositions. Each of the 35 findings
still requires independent ChatGPT approval before any Sonar disposition changes.

Each address has an individual source range, data flow, original evidence SHA256
and behavioral mutation result in address-review.json. Columns below use original
line numbers and zero-based source offsets. A shared rule is not the justification.

## Source and behavioral proof

The original verifier imports only hashlib, json and pathlib. frame() reads an
existing captured file, checks its recorded command echo/prompt, and JSON-decodes
it; strings such as show ip route json are never executed. bgp(), zebra() and
kernel() return ordinary JSON dictionaries. installed() indexes such a dictionary
and asserts selected/installed/origin metadata; it never installs a route.

Addresses flow into dictionary selection, equality, membership, path-count and
absence assertions. Some select values later used by other assertions; each
flow is listed below. They influence offline evidence-validation success. They
do not authorize users, choose application policy, create connections, select a
network destination, configure routes or invoke a probe. This verifier is not
called by Network Doctor or the packager and asserts no BGP-to-FIB ownership.
It assumes a trusted local repository and its manifests, not arbitrary external
manifests or untrusted executable Python. No stronger sandbox claim is made.

review.py replays the unchanged verifier with an audit monitor that denies Python
networking, process creation and filesystem writes. The monitor first proves
itself by blocking a socket constructor, a subprocess and a file-create attempt.
The baseline then passes under those guards. For every exact reported literal,
a separate in-memory AST copy changes only that literal. Positive checks use an
unmatched value; absence checks use an actually present key or peer from the
original recording. All 35 mutations are detected by AssertionError or KeyError,
with zero forbidden-effect attempts. Original files and hashes remain unchanged.
The complete replay also passes as non-root with readonly source mounts and no
network in the new locked builder. Host and container JSON results are identical.

Reproduce without modifying records:

```sh
python3 -B -I testdata/frr/10.7.0/bgp/correlation-review-dfbd4b3/review.py
```

## Finding-by-finding table

| Exact issue ID | Line:offset | Literal and exact source expression | Trace of use | Original preserved evidence | Individual assessment and behavioral proof |
| --- | --- | --- | --- | --- | --- |
| AaF2BX4yrSoZWpziCtPy | 81:36 | `10.10.2.0/24`<br>`assert {p["peerId"] for p in before["10.10.2.0/24"]} == {"10.0.1.2", "10.0.3.3"}` | select captured route / compare its peer set | [withdraw/r1-before-show_ip_bgp_json.raw](../correlation-investigation/withdraw/r1-before-show_ip_bgp_json.raw) | Legitimate fixed test data; no defect found. One-literal mutation detected as KeyError. |
| AaF2BX4yrSoZWpziCtPz | 81:57 | `10.0.1.2`<br>`assert {p["peerId"] for p in before["10.10.2.0/24"]} == {"10.0.1.2", "10.0.3.3"}` | select captured route / compare its peer set | [withdraw/r1-before-show_ip_bgp_json.raw](../correlation-investigation/withdraw/r1-before-show_ip_bgp_json.raw) | Legitimate fixed test data; no defect found. One-literal mutation detected as AssertionError. |
| AaF2BX4yrSoZWpziCtP0 | 81:69 | `10.0.3.3`<br>`assert {p["peerId"] for p in before["10.10.2.0/24"]} == {"10.0.1.2", "10.0.3.3"}` | select captured route / compare its peer set | [withdraw/r1-before-show_ip_bgp_json.raw](../correlation-investigation/withdraw/r1-before-show_ip_bgp_json.raw) | Legitimate fixed test data; no defect found. One-literal mutation detected as AssertionError. |
| AaF2BX4yrSoZWpziCtP1 | 82:36 | `10.10.2.0/24`<br>`assert [p["peerId"] for p in after1["10.10.2.0/24"]] == ["10.0.3.3"]` | select captured route / compare remaining peer list | [withdraw/r1-after1-show_ip_bgp_json.raw](../correlation-investigation/withdraw/r1-after1-show_ip_bgp_json.raw) | Legitimate fixed test data; no defect found. One-literal mutation detected as KeyError. |
| AaF2BX4yrSoZWpziCtP2 | 82:57 | `10.0.3.3`<br>`assert [p["peerId"] for p in after1["10.10.2.0/24"]] == ["10.0.3.3"]` | select captured route / compare remaining peer list | [withdraw/r1-after1-show_ip_bgp_json.raw](../correlation-investigation/withdraw/r1-after1-show_ip_bgp_json.raw) | Legitimate fixed test data; no defect found. One-literal mutation detected as AssertionError. |
| AaF2BX4yrSoZWpziCtP3 | 83:7 | `10.10.9.0/24`<br>`assert "10.10.9.0/24" not in after2` | assert withdrawn prefix absent from captured BGP dictionary | [withdraw/r1-after2-show_ip_bgp_json.raw](../correlation-investigation/withdraw/r1-after2-show_ip_bgp_json.raw) | Legitimate fixed test data; no defect found. One-literal mutation detected as AssertionError. |
| AaF2BX4yrSoZWpziCtP4 | 86:22 | `10.10.1.0/24`<br>`installed(routes, "10.10.1.0/24", "connected")` | installed indexes captured routes and asserts selected/installed connected metadata | [withdraw/r1-before-show_ip_route_json.raw](../correlation-investigation/withdraw/r1-before-show_ip_route_json.raw)<br>[withdraw/r1-after1-show_ip_route_json.raw](../correlation-investigation/withdraw/r1-after1-show_ip_route_json.raw)<br>[withdraw/r1-after2-show_ip_route_json.raw](../correlation-investigation/withdraw/r1-after2-show_ip_route_json.raw) | Legitimate fixed test data; no defect found. One-literal mutation detected as KeyError. |
| AaF2BX4yrSoZWpziCtP5 | 87:22 | `10.10.2.0/24`<br>`installed(routes, "10.10.2.0/24", "bgp")` | installed indexes captured routes and asserts selected/installed BGP metadata | [withdraw/r1-before-show_ip_route_json.raw](../correlation-investigation/withdraw/r1-before-show_ip_route_json.raw)<br>[withdraw/r1-after1-show_ip_route_json.raw](../correlation-investigation/withdraw/r1-after1-show_ip_route_json.raw)<br>[withdraw/r1-after2-show_ip_route_json.raw](../correlation-investigation/withdraw/r1-after2-show_ip_route_json.raw) | Legitimate fixed test data; no defect found. One-literal mutation detected as KeyError. |
| AaF2BX4yrSoZWpziCtP6 | 88:11 | `10.10.1.0/24`<br>`assert "10.10.1.0/24" in kernel(withdraw, phase)` | assert connected prefix present in captured kernel dictionary | [withdraw/r1-before-ip_route.json](../correlation-investigation/withdraw/r1-before-ip_route.json)<br>[withdraw/r1-after1-ip_route.json](../correlation-investigation/withdraw/r1-after1-ip_route.json)<br>[withdraw/r1-after2-ip_route.json](../correlation-investigation/withdraw/r1-after2-ip_route.json) | Legitimate fixed test data; no defect found. One-literal mutation detected as AssertionError. |
| AaF2BX4yrSoZWpziCtP7 | 89:7 | `10.10.9.0/24`<br>`assert "10.10.9.0/24" not in zebra(withdraw, "after2")` | assert withdrawn prefix absent from captured Zebra dictionary | [withdraw/r1-after2-show_ip_route_json.raw](../correlation-investigation/withdraw/r1-after2-show_ip_route_json.raw) | Legitimate fixed test data; no defect found. One-literal mutation detected as AssertionError. |
| AaF2BX4yrSoZWpziCtP8 | 90:7 | `10.10.9.0/24`<br>`assert "10.10.9.0/24" not in kernel(withdraw, "after2")` | assert withdrawn prefix absent from captured kernel dictionary | [withdraw/r1-after2-ip_route.json](../correlation-investigation/withdraw/r1-after2-ip_route.json) | Legitimate fixed test data; no defect found. One-literal mutation detected as AssertionError. |
| AaF2BX4yrSoZWpziCtP9 | 93:26 | `10.0.1.2`<br>`assert any(p["peerId"] == "10.0.1.2" for ps in bgp(session, "before").values() for p in ps)` | assert captured paths include the peer before session loss | [session-plain/r1-before-show_ip_bgp_json.raw](../correlation-investigation/session-plain/r1-before-show_ip_bgp_json.raw) | Legitimate fixed test data; no defect found. One-literal mutation detected as AssertionError. |
| AaF2BX4yrSoZWpziCtP- | 94:26 | `10.0.1.2`<br>`assert all(p["peerId"] != "10.0.1.2" for ps in bgp(session, "after").values() for p in ps)` | assert captured paths exclude the lost peer | [session-plain/r1-after-show_ip_bgp_json.raw](../correlation-investigation/session-plain/r1-after-show_ip_bgp_json.raw) | Legitimate fixed test data; no defect found. One-literal mutation detected as AssertionError. |
| AaF2BX4yrSoZWpziCtP_ | 97:13 | `10.0.1.2`<br>`assert peers["10.0.1.2"]["state"] != "Established"` | index captured peer and assert it is not Established | [session-plain/r1-after-show_ip_bgp_summary_json.raw](../correlation-investigation/session-plain/r1-after-show_ip_bgp_summary_json.raw) | Legitimate fixed test data; no defect found. One-literal mutation detected as KeyError. |
| AaF2BX4yrSoZWpziCtQA | 98:13 | `10.0.3.3`<br>`assert peers["10.0.3.3"]["state"] == "Established"` | index captured peer and assert it remains Established | [session-plain/r1-after-show_ip_bgp_summary_json.raw](../correlation-investigation/session-plain/r1-after-show_ip_bgp_summary_json.raw) | Legitimate fixed test data; no defect found. One-literal mutation detected as KeyError. |
| AaF2BX4yrSoZWpziCtQB | 99:7 | `10.10.9.0/24`<br>`assert "10.10.9.0/24" not in zebra(session, "after")` | assert lost prefix absent from captured Zebra dictionary | [session-plain/r1-after-show_ip_route_json.raw](../correlation-investigation/session-plain/r1-after-show_ip_route_json.raw) | Legitimate fixed test data; no defect found. One-literal mutation detected as AssertionError. |
| AaF2BX4yrSoZWpziCtQC | 100:7 | `10.10.9.0/24`<br>`assert "10.10.9.0/24" not in kernel(session, "after")` | assert lost prefix absent from captured kernel dictionary | [session-plain/r1-after-ip_route.json](../correlation-investigation/session-plain/r1-after-ip_route.json) | Legitimate fixed test data; no defect found. One-literal mutation detected as AssertionError. |
| AaF2BX4yrSoZWpziCtQD | 104:25 | `10.10.2.0/24`<br>`paths = detail["routes"]["10.10.2.0/24"]` | select captured path list for subsequent path-count and attribute assertions | [recursive-shared/r1-before-bgp-detail.raw](../correlation-investigation/recursive-shared/r1-before-bgp-detail.raw) | Legitimate fixed test data; no defect found. One-literal mutation detected as KeyError. |
| AaF2BX4yrSoZWpziCtQE | 106:48 | `10.0.1.2`<br>`assert {p["peer"]["peerId"] for p in paths} == {"10.0.1.2", "10.0.3.3"}` | compare captured peer set; does not choose an owner | [recursive-shared/r1-before-bgp-detail.raw](../correlation-investigation/recursive-shared/r1-before-bgp-detail.raw) | Legitimate fixed test data; no defect found. One-literal mutation detected as AssertionError. |
| AaF2BX4yrSoZWpziCtQF | 106:60 | `10.0.3.3`<br>`assert {p["peer"]["peerId"] for p in paths} == {"10.0.1.2", "10.0.3.3"}` | compare captured peer set; does not choose an owner | [recursive-shared/r1-before-bgp-detail.raw](../correlation-investigation/recursive-shared/r1-before-bgp-detail.raw) | Legitimate fixed test data; no defect found. One-literal mutation detected as AssertionError. |
| AaF2BX4yrSoZWpziCtQG | 108:68 | `10.0.1.2`<br>`and p["multipath"] is True and p["nexthops"][0]["ip"] == "10.0.1.2"` | compare captured shared next-hop attribute | [recursive-shared/r1-before-bgp-detail.raw](../correlation-investigation/recursive-shared/r1-before-bgp-detail.raw) | Legitimate fixed test data; no defect found. One-literal mutation detected as AssertionError. |
| AaF2BX4yrSoZWpziCtQH | 112:26 | `10.10.2.0/24`<br>`route = installed(routes, "10.10.2.0/24", "bgp")` | select installed captured BGP route; assert one FIB leg and one duplicate | [recursive-shared/r1-before-show_ip_route_json.raw](../correlation-investigation/recursive-shared/r1-before-show_ip_route_json.raw) | Legitimate fixed test data; no defect found. One-literal mutation detected as KeyError. |
| AaF2BX4yrSoZWpziCtQI | 119:29 | `10.10.9.0/24`<br>`resolver = installed(routes, "10.10.9.0/24", "bgp")` | select captured resolver route; compare recorded nexthop group IDs | [recursive-shared/r1-before-show_ip_route_json.raw](../correlation-investigation/recursive-shared/r1-before-show_ip_route_json.raw) | Legitimate fixed test data; no defect found. One-literal mutation detected as KeyError. |
| AaF2BX4yrSoZWpziCtQJ | 123:49 | `10.10.9.2`<br>`assert any(n.get("recursive") and n["ip"] == "10.10.9.2" for n in route["nexthops"])` | assert recorded recursive gateway on both captured consuming routes | [recursive-shared/r1-before-show_ip_route_json.raw](../correlation-investigation/recursive-shared/r1-before-show_ip_route_json.raw) | Legitimate fixed test data; no defect found. One-literal mutation detected as AssertionError. |
| AaF2BX4yrSoZWpziCtQK | 124:65 | `10.0.1.2`<br>`assert any(n.get("resolver") and n.get("fib") and n["ip"] == "10.0.1.2"` | assert recorded resolver/FIB gateway on both captured consuming routes | [recursive-shared/r1-before-show_ip_route_json.raw](../correlation-investigation/recursive-shared/r1-before-show_ip_route_json.raw) | Legitimate fixed test data; no defect found. One-literal mutation detected as AssertionError. |
| AaF2BX4yrSoZWpziCtQL | 127:37 | `10.10.9.2`<br>`resolutions = nht["default"]["ipv4"]["10.10.9.2"]["resolutions"]` | index captured NHT resolution list for later assertions | [recursive-shared/r1-before-nht.raw](../correlation-investigation/recursive-shared/r1-before-nht.raw) | Legitimate fixed test data; no defect found. One-literal mutation detected as KeyError. |
| AaF2BX4yrSoZWpziCtQM | 128:26 | `10.10.9.0/24`<br>`assert all(r["prefix"] == "10.10.9.0/24" and r["resolvedProtocol"] == "bgp"` | compare captured resolver prefix and origin | [recursive-shared/r1-before-nht.raw](../correlation-investigation/recursive-shared/r1-before-nht.raw) | Legitimate fixed test data; no defect found. One-literal mutation detected as AssertionError. |
| AaF2BX4yrSoZWpziCtQN | 132:21 | `10.10.9.2`<br>`assert cache["ipv4"]["10.10.9.2"]["resolvedPrefix"] == "10.10.9.0/24"` | index captured BGP next-hop cache / compare its resolved prefix | [recursive-shared/r1-before-bgp-nexthop.raw](../correlation-investigation/recursive-shared/r1-before-bgp-nexthop.raw) | Legitimate fixed test data; no defect found. One-literal mutation detected as KeyError. |
| AaF2BX4yrSoZWpziCtQO | 132:55 | `10.10.9.0/24`<br>`assert cache["ipv4"]["10.10.9.2"]["resolvedPrefix"] == "10.10.9.0/24"` | index captured BGP next-hop cache / compare its resolved prefix | [recursive-shared/r1-before-bgp-nexthop.raw](../correlation-investigation/recursive-shared/r1-before-bgp-nexthop.raw) | Legitimate fixed test data; no defect found. One-literal mutation detected as AssertionError. |
| AaF2BX4yrSoZWpziCtQP | 133:26 | `10.10.2.0/24`<br>`assert sum(p["prefix"] == "10.10.2.0/24" for p in cache["ipv4"]["10.0.1.2"]["paths"]) == 2` | index captured cache / count captured paths with the prefix | [recursive-shared/r1-before-bgp-nexthop.raw](../correlation-investigation/recursive-shared/r1-before-bgp-nexthop.raw) | Legitimate fixed test data; no defect found. One-literal mutation detected as AssertionError. |
| AaF2BX4yrSoZWpziCtQQ | 133:64 | `10.0.1.2`<br>`assert sum(p["prefix"] == "10.10.2.0/24" for p in cache["ipv4"]["10.0.1.2"]["paths"]) == 2` | index captured cache / count captured paths with the prefix | [recursive-shared/r1-before-bgp-nexthop.raw](../correlation-investigation/recursive-shared/r1-before-bgp-nexthop.raw) | Legitimate fixed test data; no defect found. One-literal mutation detected as KeyError. |
| AaF2BX4yrSoZWpziCtQR | 137:24 | `10.10.9.2`<br>`assert lookup["dst"] == "10.10.9.2" and fibmatch["dst"] == "10.10.9.0/24"` | compare recorded route-get and fibmatch destinations, without executing either command | [recursive-shared/r1-before-get.json](../correlation-investigation/recursive-shared/r1-before-get.json)<br>[recursive-shared/r1-before-fibmatch.json](../correlation-investigation/recursive-shared/r1-before-fibmatch.json) | Legitimate fixed test data; no defect found. One-literal mutation detected as AssertionError. |
| AaF2BX4yrSoZWpziCtQS | 137:59 | `10.10.9.0/24`<br>`assert lookup["dst"] == "10.10.9.2" and fibmatch["dst"] == "10.10.9.0/24"` | compare recorded route-get and fibmatch destinations, without executing either command | [recursive-shared/r1-before-get.json](../correlation-investigation/recursive-shared/r1-before-get.json)<br>[recursive-shared/r1-before-fibmatch.json](../correlation-investigation/recursive-shared/r1-before-fibmatch.json) | Legitimate fixed test data; no defect found. One-literal mutation detected as AssertionError. |
| AaF2BX4yrSoZWpziCtQT | 140:15 | `10.10.9.0/24`<br>`for prefix in ("10.10.9.0/24", "198.51.100.0/24", "203.0.113.0/24"):` | iterate expected absent prefixes and assert absence in both captured dictionaries | [recursive-shared/r1-after-show_ip_route_json.raw](../correlation-investigation/recursive-shared/r1-after-show_ip_route_json.raw)<br>[recursive-shared/r1-after-ip_route.json](../correlation-investigation/recursive-shared/r1-after-ip_route.json) | Legitimate fixed test data; no defect found. One-literal mutation detected as AssertionError. |
| AaF2BX4yrSoZWpziCtQU | 146:49 | `10.10.9.2`<br>`for r in after_nht["default"]["ipv4"]["10.10.9.2"]["resolutions"])` | index captured NHT entry and assert recorded unresolved state and empty legs | [recursive-shared/r1-after-nht.raw](../correlation-investigation/recursive-shared/r1-after-nht.raw) | Legitimate fixed test data; no defect found. One-literal mutation detected as KeyError. |

All referenced files are hash-pinned by the original recursive manifests; their
individual hashes are also recorded in address-review.json. The verifier's full
statement context remains available in the unchanged verify.py. A key lookup
failure in a mutation proves that particular address selected recorded JSON; an
assertion failure proves the affected comparison or absence check is meaningful.
Neither outcome is counted as a network, routing or authorization operation.

The separate docker:S6471 finding is a real least-privilege concern and is
corrected separately with a non-root default builder user; see
[the builder proof](../correlation-v1-nonroot/README.md). It is not dismissed by this
address review. No remote finding was dismissed, suppressed, accepted or marked
false positive. Scanner rules and quality gates are unchanged.
