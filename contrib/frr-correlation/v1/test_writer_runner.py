"""Keep synthetic writer failures and timeout diagnostics in retained CI logs."""
import contextlib
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest import mock


def main():
    logs = Path(sys.argv[1])
    runner = Path(__file__).with_name("test_writer.py")
    private = "environment sentinel must not be logged"
    with tempfile.TemporaryDirectory(dir=logs) as scratch:
        child = Path(scratch) / "writer"
        for name, status in (("exit", 7), ("assert", 0), ("decode", 0)):
            malformed = "sys.stdout.buffer.write(b'WRITER_TEST_PASSED\\xff\\n')\n" if name == "decode" else ""
            child.write_text(f"#!{sys.executable}\nimport sys\n" + malformed +
                             "print('WRITER_STDOUT_DIAGNOSTIC')\n"
                             "print('WRITER_STDERR_DIAGNOSTIC', file=sys.stderr)\n"
                             f"sys.exit({status})\n")
            child.chmod(0o700)
            log = logs / f"writer-runner-{name}.log"
            with log.open("x") as destination:
                result = subprocess.run([sys.executable, "-B", "-I", str(runner), str(child)],
                                        env=dict(os.environ, WRITER_ENV_SENTINEL=private),
                                        stdout=destination, stderr=subprocess.STDOUT,
                                        timeout=30, check=False)
            text = log.read_text()
            assert result.returncode != 0
            assert "WRITER_STDOUT_DIAGNOSTIC" in text and "WRITER_STDERR_DIAGNOSTIC" in text
            assert f"startup: failed (child exit status {status})" in text
            if name == "decode":
                assert "UnicodeDecodeError" in text and "WRITER_TEST_PASSED\ufffd" in text
            assert private not in text and "WRITER_SHUTDOWN_TESTS_PASSED" not in text

        spec = importlib.util.spec_from_file_location("writer_runner", runner)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        for name, stdout, stderr in (("timeout", b"TIMEOUT_STDOUT_DIAGNOSTIC\n", b"TIMEOUT_STDERR_DIAGNOSTIC\xff\n"),
                                     ("empty-timeout", None, None)):
            expired = subprocess.TimeoutExpired([str(child), "startup"], 30, output=stdout, stderr=stderr)
            log = logs / f"writer-runner-{name}.log"
            with log.open("x") as destination, contextlib.redirect_stderr(destination), \
                    mock.patch.object(sys, "argv", [str(runner), str(child)]), \
                    mock.patch.object(subprocess, "run", side_effect=expired):
                try:
                    module.main()
                except subprocess.TimeoutExpired as error:
                    assert error is expired
                else:
                    raise AssertionError("writer timeout passed")
            text = log.read_text()
            assert "startup: timed out after 30 seconds" in text
            if stdout is not None:
                assert "TIMEOUT_STDOUT_DIAGNOSTIC" in text and "TIMEOUT_STDERR_DIAGNOSTIC\ufffd" in text
            assert private not in text and "WRITER_SHUTDOWN_TESTS_PASSED" not in text
    print("WRITER_RUNNER_DIAGNOSTICS_TESTS_PASSED cases=5")


if __name__ == "__main__":
    main()
