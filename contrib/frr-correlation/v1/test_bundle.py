"""Negative copies below are mutations of genuine logs, never live fixtures."""
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from bundle import Refused, decode, main, produce, read_source

HERE = Path(__file__).resolve().parent
EVIDENCE = HERE.parents[2] / "testdata/frr/10.7.0/bgp/correlation-v1-hardened"


class ProducerProof(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        shutil.copytree(EVIDENCE / "proof/identity/r1", self.root / "logs")
        self.logs = self.root / "logs"
        self.build = decode((EVIDENCE / "build.json").read_bytes())

    def mutate(self, daemon, change, renumber=False):
        path = next(self.logs.glob(daemon + ".*.jsonl"))
        rows = [decode(line) for line in path.read_bytes().splitlines()]
        change(rows)
        if renumber:
            for seq, row in enumerate(rows, 1):
                row["seq"] = seq
        path.write_text("".join(json.dumps(r) + "\n" for r in rows))

    def result(self):
        return produce(self.logs, self.build)

    def test_partial_stream_is_refused_even_with_two_closed_streams(self):
        (self.logs / "zebra.other.jsonl.partial").write_bytes(b"")
        with self.assertRaisesRegex(Refused, "incomplete producer stream"):
            self.result()

    def test_output_does_not_overwrite_existing_file_or_symlink(self):
        source = next(self.logs.glob("*.jsonl"))
        original = source.read_bytes()
        link = self.root / "output.json"
        link.symlink_to(source)
        for output in (source, link):
            with patch("sys.argv", ["bundle.py", str(self.logs), "--build", str(EVIDENCE / "build.json"), "--output", str(output)]):
                self.assertEqual(main(), 2)
            self.assertEqual(source.read_bytes(), original)

    def test_output_exclusive_creation_for_success_and_refusal(self):
        for refused in (False, True):
            if refused:
                (self.logs / "extra.partial").write_bytes(b"")
            output = self.root / (str(refused) + ".json")
            with patch("sys.argv", ["bundle.py", str(self.logs), "--build", str(EVIDENCE / "build.json"), "--output", str(output)]):
                self.assertEqual(main(), 2 if refused else 0)
            self.assertEqual(decode(output.read_bytes())["capture"]["complete"], not refused)

    def test_source_symlink_and_fifo_are_refused(self):
        source = next(self.logs.glob("*.jsonl"))
        preserved = self.root / "preserved.jsonl"
        source.rename(preserved)
        source.symlink_to(preserved)
        with self.assertRaises(OSError):
            self.result()
        source.unlink()
        os.mkfifo(source)
        with self.assertRaisesRegex(Refused, "non-regular"):
            self.result()

    def test_source_read_is_bounded(self):
        source = self.root / "oversized"
        source.write_bytes(b"x" * 4097)
        with self.assertRaisesRegex(Refused, "size limit"):
            read_source(source, 4096)

    def test_live_identity_chains(self):
        bundle = self.result()
        self.assertTrue(bundle["capture"]["complete"])
        self.assertFalse(bundle["capture"]["snapshot_complete"])
        installed = {(c["route_id"], c["generation"]) for c in bundle["claims"] if c["type"] == "route_installed_as_fib"}
        shared = [r for r in bundle["routes"] if len(r["contributors"]) == 2 and (r["route_id"], r["generation"]) in installed]
        self.assertTrue(shared)
        self.assertTrue(all(len({p["peer_id"] for p in r["contributors"]}) == 2 for r in shared))
        paths = {(p["path_id"], p["revision"]): p for p in bundle["bgp_paths"]}
        for route in shared:
            contributors = [paths[(c["path_id"], c["revision"])] for c in route["contributors"]]
            self.assertEqual(len({(p["as_path"], p["nexthop"]) for p in contributors}), 1)
            self.assertEqual(len({p["peer_address"] for p in contributors}), 2)
        static = {r["route_id"] for r in bundle["routes"] if r["origin"] == "static" and r["prefix"] == "198.51.100.0/24"}
        routes = {(r["route_id"], r["generation"]): r for r in bundle["routes"]}
        edges = [c for c in bundle["claims"] if c["type"] == "route_leg_resolved_by_route" and c["route_id"] in static]
        self.assertTrue(edges)
        for edge in edges:
            resolver = routes[(edge["resolver_id"], edge["resolver_generation"])]
            self.assertEqual(resolver["origin"], "bgp")
            self.assertTrue(resolver["contributors"])
        self.assertTrue(any(r["route_id"] in static for r in bundle["fib_entries"]))

    def test_committed_bundle_matches_sources(self):
        self.assertEqual(self.result(), decode((EVIDENCE / "proof-bundle.json").read_bytes()))

    def test_complete_evidence_manifests(self):
        for root in (EVIDENCE, EVIDENCE / "proof", EVIDENCE / "restart"):
            names = []
            for line in (root / "SHA256SUMS").read_text().splitlines():
                digest, name = line.split("  ", 1)
                self.assertFalse(Path(name).is_absolute() or ".." in Path(name).parts)
                self.assertEqual(hashlib.sha256((root / name).read_bytes()).hexdigest(), digest)
                names.append(name)
            actual = [str(f.relative_to(root)) for f in root.rglob("*") if f.is_file() and f != root / "SHA256SUMS"]
            self.assertEqual(sorted(names), sorted(actual))

    def test_independent_observations_agree_without_producing_edges(self):
        proof = EVIDENCE / "proof"
        def frame(phase, command):
            raw = (proof / f"r1-{phase}-{command.replace(' ', '_')}.raw").read_bytes()
            head, tail = command.encode()+b"\r\n", b"\r\nr1> "
            self.assertTrue(raw.startswith(head) and raw.endswith(tail))
            return decode(raw[len(head):-len(tail)])
        before = frame("before", "show ip bgp json")["routes"]
        self.assertEqual({p["peerId"] for p in before["10.10.2.0/24"]}, {"10.0.1.2", "10.0.3.3"})
        zebra = frame("before", "show ip route json")
        self.assertTrue(zebra["198.51.100.0/24"][0]["installed"])
        self.assertEqual(zebra["198.51.100.0/24"][0]["protocol"], "static")
        shared = zebra["10.10.2.0/24"][0]["nexthops"]
        self.assertEqual(sum(n.get("fib", False) for n in shared), 1)
        self.assertEqual(sum(n.get("duplicate", False) for n in shared), 1)
        for phase in ("withdrawn", "session_lost"):
            kernel = {r["dst"]: r for r in decode((proof / f"r1-{phase}-ip_route.json").read_bytes())}
            self.assertNotIn("10.10.9.0/24", frame(phase, "show ip bgp json")["routes"])
            for prefix in ("10.10.9.0/24", "198.51.100.0/24"):
                self.assertNotIn(prefix, kernel)
                self.assertNotIn(prefix, frame(phase, "show ip route json"))
            self.assertIn("10.10.1.0/24", kernel)
        after = frame("session_lost", "show ip bgp json")["routes"]
        self.assertEqual([p["peerId"] for p in after["10.10.2.0/24"]], ["10.0.3.3"])
        summary = frame("session_lost", "show ip bgp summary json")["ipv4Unicast"]["peers"]
        self.assertNotEqual(summary["10.0.1.2"]["state"], "Established")
        self.assertEqual(summary["10.0.3.3"]["state"], "Established")

    def test_mixed_genuine_capture_is_refused(self):
        next(self.logs.glob("zebra.*.jsonl")).unlink()
        other = next((EVIDENCE / "restart/identity/r1").glob("zebra.*.jsonl"))
        shutil.copyfile(other, self.logs / other.name)
        with self.assertRaisesRegex(Refused, "mixed namespaces"):
            self.result()

    def test_unverified_operation_is_refused(self):
        changed = []
        def change(rows):
            row = next(r for r in rows if r["event"] == "operation" and r["prefix"] == "198.51.100.0/24")
            row["supported"] = False
            changed.append(row["operation_id"])
        self.mutate("zebra", change)
        self.assertFalse(any(c.get("operation_id") == changed[0] for c in self.result()["claims"]))

    def test_boolean_kernel_error_is_not_a_positive_ack(self):
        def change(rows):
            next(r for r in rows if r["event"] == "netlink_ack")["error"] = False
        self.mutate("zebra", change)
        with self.assertRaisesRegex(Refused, "error type"):
            self.result()

    def test_missing_path_is_refused_even_with_contiguous_sequence(self):
        self.mutate("bgpd", lambda rows: rows.remove(next(r for r in rows if r["event"] == "bgp_path" and r["prefix"] == "10.10.9.0/24")), True)
        with self.assertRaisesRegex(Refused, "path edge"):
            self.result()

    def test_contradictory_contributor_is_refused(self):
        def change(rows):
            row = next(r for r in rows if r["event"] == "route_received" and r["contributors"])
            row["contributors"][0]["revision"] += 1
        self.mutate("zebra", change)
        with self.assertRaisesRegex(Refused, "contradictory path-to-route"):
            self.result()

    def test_missing_resolution_object_is_refused(self):
        def change(rows):
            op = next(r for r in rows if r["event"] == "operation" and r["prefix"] == "198.51.100.0/24")
            target = op["resolution_refs"][0]["resolution_id"]
            rows.remove(next(r for r in rows if r.get("resolution_id") == target))
        self.mutate("zebra", change, True)
        with self.assertRaisesRegex(Refused, "operation-to-resolution"):
            self.result()

    def test_shared_group_cannot_substitute_another_routes_resolution(self):
        def change(rows):
            op = next(r for r in rows if r["event"] == "operation" and r["prefix"] == "198.51.100.0/24")
            other = next(r for r in rows if r["event"] == "resolution" and r["route_id"] != op["route_id"])
            op["resolution_refs"][0]["resolution_id"] = other["resolution_id"]
        self.mutate("zebra", change)
        with self.assertRaisesRegex(Refused, "contradictory operation-to-resolution"):
            self.result()

    def test_kernel_failure_gets_no_installation_credit(self):
        changed = []
        def change(rows):
            row = next(r for r in rows if r["event"] == "netlink_ack" and r["prefix"] == "198.51.100.0/24")
            row["error"] = -1
            changed.append(row["operation_id"])
        self.mutate("zebra", change)
        result = self.result()
        self.assertFalse(any(c.get("operation_id") == changed[0] for c in result["claims"]))
        self.assertTrue(any("unsuccessful explicit kernel ACK" in r["reason"] for r in result["refusals"]))

    def test_missing_positive_ack_gets_no_installation_credit(self):
        changed = []
        def change(rows):
            row = next(r for r in rows if r["event"] == "netlink_ack" and r["prefix"] == "198.51.100.0/24")
            changed.append(row["operation_id"])
            rows.remove(row)
        self.mutate("zebra", change, True)
        self.assertFalse(any(c.get("operation_id") == changed[0] for c in self.result()["claims"]))

    def test_stale_result_gets_no_installation_credit(self):
        changed = []
        def change(rows):
            row = next(r for r in rows if r["event"] == "operation_result" and r["prefix"] == "198.51.100.0/24")
            changed.append(row["operation_id"])
            row["accepted_generation"] = False
        self.mutate("zebra", change)
        self.assertFalse(any(c.get("operation_id") == changed[0] for c in self.result()["claims"]))

    def test_ack_cannot_name_a_different_generation(self):
        def change(rows):
            next(r for r in rows if r["event"] == "netlink_ack")["generation"] += 1
        self.mutate("zebra", change)
        with self.assertRaisesRegex(Refused, "operation identity"):
            self.result()

    def test_unmapped_origin_never_becomes_static(self):
        ids = []
        def change(rows):
            ids.append(next(r["route_id"] for r in rows if r.get("prefix") == "198.51.100.0/24" and r["event"] == "route_received"))
            for row in rows:
                if row.get("route_id") == ids[0] and "origin" in row:
                    row["origin"] = "new-vendor-protocol"
        self.mutate("zebra", change)
        result = self.result()
        self.assertFalse(any(c.get("route_id") == ids[0] for c in result["claims"]))
        self.assertTrue(any("unmapped origin" in r["reason"] for r in result["refusals"]))

    def test_unsupported_context_was_seen_live(self):
        result = self.result()
        unsupported = {r["route_id"] for r in result["routes"] if r["table"] == 100}
        self.assertTrue(unsupported)
        self.assertFalse(any(c.get("route_id") in unsupported for c in result["claims"]))

    def test_unsupported_build_os_kernel_and_namespace(self):
        for key, value in (("build_id", "unknown"), ("os", "windows"), ("kernel", "different"),
                           ("schema", "netdoc-frr-correlation/v2"), ("netns_inode", 1)):
            with self.subTest(key=key):
                path = next(self.logs.glob("bgpd.*.jsonl"))
                original = path.read_bytes()
                self.mutate("bgpd", lambda rows: rows[0].update({key: value}))
                with self.assertRaises(Refused):
                    self.result()
                path.write_bytes(original)

    def test_live_restart_capture_is_refused(self):
        with self.assertRaisesRegex(Refused, "restarts|trailer|incomplete producer stream"):
            produce(EVIDENCE / "restart/identity/r1", self.build)

    def test_truncated_duplicate_key_or_event_gap_is_refused(self):
        path = next(self.logs.glob("bgpd.*.jsonl"))
        original = path.read_bytes()
        for bad in (original[:-2], original.replace(b'"event":"start"', b'"event":"start","event":"start"', 1)):
            path.write_bytes(bad)
            with self.assertRaises((Refused, ValueError)):
                self.result()
        path.write_bytes(original)
        self.mutate("bgpd", lambda rows: rows.pop(1))
        with self.assertRaisesRegex(Refused, "gap"):
            self.result()

    @unittest.skipUnless(importlib.util.find_spec("jsonschema"), "run in the locked builder for schema validation")
    def test_versioned_schema(self):
        import jsonschema
        schema = decode((HERE / "schema.json").read_bytes())
        jsonschema.Draft202012Validator.check_schema(schema)
        jsonschema.validate(self.result(), schema)
        refused = decode((EVIDENCE / "restart-refusal.json").read_bytes())
        jsonschema.validate(refused, schema)


if __name__ == "__main__":
    unittest.main()
