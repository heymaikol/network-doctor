"""Negative copies below are mutations of genuine logs, never live fixtures."""
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from bundle import Refused, decode, main, produce, read_source

HERE = Path(__file__).resolve().parent
EVIDENCE = HERE.parents[2] / "testdata/frr/10.7.0/bgp/correlation-v1-noreplace"


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
        fd = os.open(self.logs, os.O_RDONLY | os.O_DIRECTORY)
        try:
            return produce(fd)
        finally:
            os.close(fd)

    def cli(self, output_directory, args=()):
        capture = os.open(self.logs, os.O_RDONLY | os.O_DIRECTORY)
        output = os.open(output_directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with patch("bundle.CAPTURE_FD", capture), patch("bundle.OUTPUT_FD", output), \
                    patch("sys.argv", ["bundle.py", *args]):
                return main()
        finally:
            os.close(capture)
            os.close(output)

    def assert_refused_without_claims(self, reason):
        with self.assertRaisesRegex(Refused, reason):
            self.result()
        with tempfile.TemporaryDirectory(dir=self.root) as output:
            self.assertEqual(self.cli(output), 2)
            refused = decode((Path(output) / "bundle.json").read_bytes())
            self.assertFalse(refused["capture"]["complete"])
            self.assertEqual(refused["claims"], [])
            self.assertEqual(refused.get("fib_entries", []), [])

    def test_excessive_json_nesting_returns_refusal_bundle(self):
        source = next(self.logs.glob("bgpd.*.jsonl"))
        lines = source.read_bytes().splitlines(keepends=True)
        # Fits the 65,535 byte record bound but exceeds Python JSON nesting.
        nested = b"[" * 16000 + b"0" + b"]" * 16000 + b"\n"
        self.assertLessEqual(len(nested) - 1, 65535)
        lines.insert(1, nested)
        source.write_bytes(b"".join(lines))
        with tempfile.TemporaryDirectory(dir=self.root) as output:
            self.assertEqual(self.cli(output), 2)
            result = decode((Path(output) / "bundle.json").read_bytes())
            self.assertFalse(result["capture"]["complete"])
            self.assertFalse(result["capture"]["snapshot_complete"])
            self.assertEqual(result["claims"], [])
            self.assertTrue(any("recursion" in item["reason"].lower()
                                for item in result["refusals"]))

    def test_output_serialization_recursion_returns_refusal_bundle(self):
        original_dumps = json.dumps
        attempts = []
        with tempfile.TemporaryDirectory(dir=self.root) as output:
            destination = Path(output) / "bundle.json"

            def fail_once(*args, **kwargs):
                attempts.append(1)
                if len(attempts) == 1:
                    self.assertFalse(destination.exists())
                    raise RecursionError("synthetic deep output")
                return original_dumps(*args, **kwargs)

            with patch("bundle.json.dumps", side_effect=fail_once):
                self.assertEqual(self.cli(output), 2)

            self.assertEqual(len(attempts), 2)
            refused = decode(destination.read_bytes())
            self.assertFalse(refused["capture"]["complete"])
            self.assertFalse(refused["capture"]["snapshot_complete"])
            self.assertEqual(refused["claims"], [])
            self.assertEqual(refused["refusals"],
                             [{"reason": "output JSON nesting exceeds supported limit"}])

    def test_partial_stream_is_refused_even_with_two_closed_streams(self):
        (self.logs / "zebra.other.jsonl.partial").write_bytes(b"")
        with self.assertRaisesRegex(Refused, "incomplete producer stream"):
            self.result()

    def test_failed_revocation_marker_refuses_retained_closed_streams(self):
        marker = self.logs / "zebra.other.jsonl.failed"
        target = self.root / "marker-target"
        target.write_bytes(b"ORIGINAL DESTINATION\n")
        for symbolic in (False, True):
            if symbolic:
                marker.symlink_to(target)
            else:
                marker.write_bytes(b"")
            with self.assertRaisesRegex(Refused, "failed producer stream"):
                self.result()
            output = self.root / ("marker-refusal-" + str(symbolic))
            output.mkdir()
            self.assertEqual(self.cli(output), 2)
            refused = decode((output / "bundle.json").read_bytes())
            self.assertFalse(refused["capture"]["complete"])
            self.assertEqual(refused["claims"], [])
            self.assertEqual(target.read_bytes(), b"ORIGINAL DESTINATION\n")
            marker.unlink()

    def test_output_does_not_overwrite_existing_file_or_symlink(self):
        source = next(self.logs.glob("*.jsonl"))
        original = source.read_bytes()
        output = self.root / "bundle.json"
        for symbolic in (False, True):
            if symbolic:
                output.symlink_to(source)
            else:
                os.link(source, output)
            self.assertEqual(self.cli(self.root), 2)
            self.assertEqual(source.read_bytes(), original)
            self.assertEqual(output.read_bytes(), original)
            output.unlink()

    def test_output_exclusive_creation_for_success_and_refusal(self):
        for refused in (False, True):
            if refused:
                (self.logs / "extra.partial").write_bytes(b"")
            output = self.root / str(refused)
            output.mkdir()
            self.assertEqual(self.cli(output), 2 if refused else 0)
            self.assertEqual(decode((output / "bundle.json").read_bytes())["capture"]["complete"], not refused)
            self.assertEqual(self.cli(output), 2)

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
        source = next(self.logs.glob("*.jsonl"))
        source.write_bytes(b"x" * 4097)
        fd = os.open(self.logs, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with self.assertRaisesRegex(Refused, "size limit"):
                read_source(fd, source.name, 4096)
        finally:
            os.close(fd)

    def test_unauthorized_names_never_open_or_read(self):
        source = next(self.logs.glob("*.jsonl"))
        outside = self.root / source.name
        outside.write_bytes(b"OUTSIDE SECRET")
        fd = os.open(self.logs, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, fd)
        names = (str(outside), "../" + source.name, "./" + source.name,
                 "nested/" + source.name, "nested/../" + source.name,
                 "//" + str(outside), "..", ".", source.name + "/", source.name + "\x00",
                 "verified-build.json", "bgpd.%2e%2e.jsonl")
        for name in names:
            with self.subTest(name=name), patch("bundle.os.open") as opened, \
                    patch("bundle.os.fdopen") as read:
                with self.assertRaisesRegex(Refused, "unauthorized source name"):
                    read_source(fd, name, 4096)
                opened.assert_not_called()
                read.assert_not_called()
        self.assertEqual(outside.read_bytes(), b"OUTSIDE SECRET")

    def test_symlink_escapes_never_read_target(self):
        source = next(self.logs.glob("*.jsonl"))
        source.unlink()
        outside = self.root / "secret"
        outside.write_bytes(b"OUTSIDE SECRET")
        nested = self.logs / "nested"
        nested.symlink_to(self.root, target_is_directory=True)
        fd = os.open(self.logs, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, fd)
        for target in (outside, nested / "secret"):
            source.symlink_to(target)
            with patch("bundle.os.fdopen") as read:
                with self.assertRaises(OSError):
                    read_source(fd, source.name, 4096)
                read.assert_not_called()
            source.unlink()
        self.assertEqual(outside.read_bytes(), b"OUTSIDE SECRET")

    def test_hard_link_to_outside_file_is_refused(self):
        source = next(self.logs.glob("*.jsonl"))
        source.unlink()
        outside = self.root / "secret"
        outside.write_bytes(b"OUTSIDE SECRET")
        os.link(outside, source)
        fd = os.open(self.logs, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, fd)
        with self.assertRaisesRegex(Refused, "multiply linked"):
            read_source(fd, source.name, 4096)
        self.assertEqual(outside.read_bytes(), b"OUTSIDE SECRET")

    def test_special_sources_never_read(self):
        source = next(self.logs.glob("*.jsonl"))
        source.unlink()
        fd = os.open(self.logs, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, fd)
        for kind in ("fifo", "directory", "socket", "device"):
            with self.subTest(kind=kind):
                sock = None
                if kind == "fifo":
                    os.mkfifo(source)
                elif kind == "directory":
                    source.mkdir()
                elif kind == "socket":
                    sock = socket.socket(socket.AF_UNIX)
                    try:
                        sock.bind(str(source))
                    except OSError:
                        sock.close()
                        raise
                else:
                    source.symlink_to("/dev/null")
                with self.assertRaises((OSError, Refused)):
                    read_source(fd, source.name, 4096)
                if sock:
                    sock.close()
                if kind == "directory":
                    source.rmdir()
                else:
                    source.unlink()

    def test_leaf_replacement_before_open_cannot_escape(self):
        source = next(self.logs.glob("*.jsonl"))
        outside = self.root / "secret"
        outside.write_bytes(b"OUTSIDE SECRET")
        original_open = os.open
        def replace(name, flags, **kwargs):
            source.unlink()
            source.symlink_to(outside)
            return original_open(name, flags, **kwargs)
        fd = os.open(self.logs, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, fd)
        with patch("bundle.os.open", side_effect=replace), patch("bundle.os.fdopen") as read:
            with self.assertRaises(OSError):
                read_source(fd, source.name, 67108864)
            read.assert_not_called()
        self.assertEqual(outside.read_bytes(), b"OUTSIDE SECRET")

    def test_open_descriptor_survives_leaf_and_root_replacement(self):
        source = next(self.logs.glob("*.jsonl"))
        expected = source.read_bytes()
        outside = self.root / "secret"
        outside.write_bytes(b"OUTSIDE SECRET")
        fd = os.open(self.logs, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, fd)
        original_open = os.open
        def replace(name, flags, **kwargs):
            opened = original_open(name, flags, **kwargs)
            source.unlink()
            source.symlink_to(outside)
            return opened
        with patch("bundle.os.open", side_effect=replace):
            self.assertEqual(read_source(fd, source.name, 67108864), expected)
        source.unlink()
        source.write_bytes(expected)
        moved = self.root / "moved"
        self.logs.rename(moved)
        self.logs.symlink_to(self.root, target_is_directory=True)
        (self.root / source.name).write_bytes(b"OUTSIDE SECRET")
        self.assertEqual(read_source(fd, source.name, 67108864), expected)

    def test_manifest_root_and_output_path_arguments_are_not_capabilities(self):
        for args in (("--build", "/etc/passwd"), (str(self.logs),),
                     ("--root", str(self.root)), ("--output", "/tmp/bundle.json")):
            with self.subTest(args=args), patch("sys.argv", ["bundle.py", *args]), \
                    patch("bundle.os.open") as opened, patch("bundle.os.fdopen") as read:
                with self.assertRaises(SystemExit) as exit_status:
                    main()
                self.assertEqual(exit_status.exception.code, 2)
                opened.assert_not_called()
                read.assert_not_called()

    def test_missing_invalid_and_unsupported_capabilities_fail_closed(self):
        for fd in (-1, str(self.logs)):
            with self.assertRaises((OSError, Refused)):
                produce(fd)
        fd = os.open(next(self.logs.glob("*.jsonl")), os.O_RDONLY)
        self.addCleanup(os.close, fd)
        with self.assertRaisesRegex(Refused, "directory capability"):
            produce(fd)
        with patch("bundle.sys.platform", "unsupported"):
            with self.assertRaisesRegex(Refused, "Linux directory capability"):
                self.result()

    def test_directory_enumeration_is_bounded(self):
        with patch("bundle.os.scandir") as scan:
            scan.return_value.__enter__.return_value = iter([type("Entry", (), {"name": "ignored"})()] * 1025)
            with self.assertRaisesRegex(Refused, "entry limit"):
                self.result()

    def test_real_cli_uses_only_inherited_capabilities(self):
        command = 'exec "$1" -I "$2" 3< "$3" 4< "$4"'
        result = subprocess.run(["bash", "-c", command, "trusted-launcher", sys.executable,
                                 str(HERE / "bundle.py"), str(self.logs), str(self.root)],
                                capture_output=True, timeout=30, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(decode((self.root / "bundle.json").read_bytes()), self.result())
        original = (self.root / "bundle.json").read_bytes()
        result = subprocess.run(["bash", "-c", command, "trusted-launcher", sys.executable,
                                 str(HERE / "bundle.py"), str(self.logs), str(self.root)],
                                capture_output=True, timeout=30, check=False)
        self.assertEqual(result.returncode, 2)
        self.assertEqual((self.root / "bundle.json").read_bytes(), original)

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
        self.assertEqual(self.cli(self.root), 0)
        self.assertEqual((self.root / "bundle.json").read_bytes(),
                         (EVIDENCE / "proof-bundle.json").read_bytes())

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

    def test_contributor_revisions_require_positive_uint64(self):
        for daemon, event in (("bgpd", "bgp_submission"), ("zebra", "route_received"),
                              ("zebra", "route_generation")):
            path = next(self.logs.glob(daemon + ".*.jsonl"))
            original = path.read_bytes()
            for value in (True, False, -1, 0, 2**64, 1.0):
                with self.subTest(event=event, value=value):
                    def change(rows):
                        row = next(r for r in rows if r["event"] == event and r["contributors"])
                        row["contributors"][0]["revision"] = value
                    try:
                        self.mutate(daemon, change)
                        self.assert_refused_without_claims("invalid contributor revision")
                    finally:
                        path.write_bytes(original)

    def test_nested_legs_require_integer_ordinals(self):
        for daemon, event, field in (("bgpd", "bgp_submission", "contributors"),
                                     ("zebra", "route_received", "contributors"),
                                     ("zebra", "route_generation", "contributors"),
                                     ("zebra", "operation", "resolution_refs")):
            path = next(self.logs.glob(daemon + ".*.jsonl"))
            original = path.read_bytes()
            for value in (True, False, -1, 64, 2**64, 0.0):
                with self.subTest(event=event, value=value):
                    def change(rows):
                        row = next(r for r in rows if r["event"] == event and len(r[field]) == 2)
                        row[field][int(value) if type(value) is bool else 0]["leg"] = value
                    try:
                        self.mutate(daemon, change)
                        self.assert_refused_without_claims("invalid nested leg")
                    finally:
                        path.write_bytes(original)

    def test_operation_leg_count_requires_uint64(self):
        path = next(self.logs.glob("zebra.*.jsonl"))
        original = path.read_bytes()
        for value in (True, False, -1, 2**64, 1.0):
            with self.subTest(value=value):
                try:
                    self.mutate("zebra", lambda rows: next(r for r in rows if r["event"] == "operation").update(source_leg_count=value))
                    self.assert_refused_without_claims("incomplete operation leg inventory")
                finally:
                    path.write_bytes(original)

    def assert_resolution_context_refused(self, field, value):
        def change(rows):
            row = next(r for r in rows if r["event"] == "resolution" and r["supported"] is True and r["recursive"] is True)
            row[field] = value
        self.mutate("zebra", change)
        self.assert_refused_without_claims("contradictory resolution context")

    def test_resolution_resolver_table_must_match_selected_route(self):
        self.assert_resolution_context_refused("resolver_table", 100)

    def test_resolution_resolving_vrf_must_match_supported_lookup(self):
        self.assert_resolution_context_refused("resolving_vrf", 7)

    def test_resolution_table_must_match_consumer(self):
        self.assert_resolution_context_refused("table", 100)

    def test_resolution_vrf_must_match_supported_lookup(self):
        self.assert_resolution_context_refused("vrf", 7)

    def test_unsupported_resolution_cannot_hide_contradictory_tables(self):
        path = next(self.logs.glob("zebra.*.jsonl"))
        original = path.read_bytes()
        for field in ("table", "resolver_table"):
            with self.subTest(field=field):
                def change(rows):
                    row = next(r for r in rows if r["event"] == "resolution" and r["supported"] is True)
                    row.update(supported=False)
                    row[field] = 100
                try:
                    self.mutate("zebra", change)
                    self.assert_refused_without_claims("contradictory resolution context")
                finally:
                    path.write_bytes(original)

    def test_unsupported_resolution_gets_no_resolution_or_installation_credit(self):
        changed = []
        def change(rows):
            row = next(r for r in rows if r["event"] == "resolution" and r["supported"] is True and r["recursive"] is True)
            changed.append(row["resolution_id"])
            row["supported"] = False
        self.mutate("zebra", change)
        result = self.result()
        self.assertFalse(any(c.get("resolution_id") == changed[0] or changed[0] in c.get("resolution_ids", [])
                             for c in result["claims"]))

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
            fd = os.open(EVIDENCE / "restart/identity/r1", os.O_RDONLY | os.O_DIRECTORY)
            try:
                produce(fd)
            finally:
                os.close(fd)

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
