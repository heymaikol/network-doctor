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
             "write_short", "flush_before", "flush_after", "close", "close_eintr", "trailer_write", "publish", "oversize")
    for mode in cases:
        with tempfile.TemporaryDirectory() as scratch:
            result = subprocess.run([executable, mode], env=dict(os.environ, NETDOC_CORRELATION_DIR=scratch),
                                    capture_output=True, text=True, timeout=30, check=True)
            assert "WRITER_TEST_PASSED" in result.stdout
            files = list(Path(scratch).iterdir())
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
