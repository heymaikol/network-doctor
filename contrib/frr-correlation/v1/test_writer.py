"""Run the compiled real writer with deterministic concurrent shutdown and IO faults."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def main():
    executable = str(Path(sys.argv[1]).resolve())
    cases = ("startup", "joined", "concurrent", "late", "write_error", "write_eintr", "write_zero",
             "write_short", "flush_before", "flush_after", "close", "close_eintr", "trailer_write", "publish", "oversize",
             "publish_existing_regular", "publish_existing_symlink", "revoke_existing_regular", "revoke_existing_symlink",
             "publish_enosys", "publish_eopnotsupp", "publish_einval", "revoke_enosys", "revoke_eopnotsupp", "revoke_einval",
             "revoke_marker_regular", "revoke_marker_symlink")
    for mode in cases:
        with tempfile.TemporaryDirectory() as scratch:
            result = subprocess.run([executable, mode], env=dict(os.environ, NETDOC_CORRELATION_DIR=scratch),
                                    capture_output=True, text=True, timeout=30, check=True)
            assert "WRITER_TEST_PASSED" in result.stdout
            files = list(Path(scratch).iterdir())
            if mode.startswith(("publish_", "revoke_")):
                root = Path(scratch)
                final = next(root.glob("zebra.*.jsonl"), None)
                partial = next(root.glob("*.partial"), None)
                marker = next(root.glob("*.failed"), None)
                revoke = mode.startswith("revoke_")
                collision = "_existing_" in mode
                marker_collision = "_marker_" in mode
                if collision or marker_collision:
                    destination = marker if marker_collision else partial if revoke else final
                    assert destination.read_bytes() == b"ORIGINAL DESTINATION\n"
                    assert (root / "sentinel").read_bytes() == b"ORIGINAL DESTINATION\n"
                    assert destination.is_symlink() == mode.endswith("_symlink")
                    if destination.is_symlink():
                        assert destination.readlink() == Path("sentinel")
                    else:
                        assert destination.stat().st_ino == (root / "sentinel").stat().st_ino
                expected_count = (2 if revoke else 1) + (2 if collision else 1 if marker_collision else 0)
                assert len(files) == expected_count
                assert (marker is not None) == revoke
                assert final is not None if revoke else partial is not None
                source = final if revoke else partial
                rows = [json.loads(line) for line in source.read_bytes().splitlines()]
                assert len(rows) == 3 and rows[0]["event"] == "start" and rows[-1]["event"] == "end"
                assert rows[-1]["complete"] is True
                if not revoke:
                    assert (final is not None) == collision
                print(mode + ": PASS")
                continue
            assert len(files) == 1, files
            path = files[0]
            assert path.name.endswith(".jsonl" if mode == "joined" else ".partial"), path
            if mode != "write_short":
                rows = [json.loads(line) for line in path.read_bytes().splitlines()]
                assert [r["seq"] for r in rows] == list(range(1, len(rows) + 1))
                assert [r["monotonic_ns"] for r in rows] == sorted(r["monotonic_ns"] for r in rows)
                ends = [i for i, row in enumerate(rows) if row["event"] == "end"]
                assert not ends or ends == [len(rows) - 1], ends
                if mode == "joined":
                    assert len(rows) == 4002 and rows[-1]["complete"] is True
                    assert len({r["id"] for r in rows[1:-1]}) == 4000
                if mode in ("flush_after", "close", "close_eintr", "publish", "late"):
                    assert rows[-1]["complete"] is True  # Refused because filename is partial.
            print(mode + ": PASS")
    print("WRITER_SHUTDOWN_TESTS_PASSED")


if __name__ == "__main__":
    main()
