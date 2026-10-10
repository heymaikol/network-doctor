#!/usr/bin/env python3
"""Run each one-hour Watch arm in its own test process and summarize the runs.

Usage, from the repository root: python3 docs/performance/watch_one_hour_cpu.py REPS

The only argument is the repetition count. Output goes to a fresh temporary
directory, which is printed first, so no argument can name a path.

The test binary is built once, so compile time stays outside every measured
region. Each repetition runs all five arms, and the starting arm moves by one
each repetition so no arm always runs first or last. The summary gives the
median, minimum, maximum and coefficient of variation of each reported metric.
"""

import argparse
import os
import statistics
import subprocess
import sys
import tempfile
from collections import defaultdict

PACKAGE = "./internal/diagnostic"
BENCH = "BenchmarkRealWatchPasses"
ARMS = [
    ("stable", "incremental"),
    ("stable", "forced"),
    ("stable", "fresh"),
    ("events", "incremental"),
    ("events", "fresh"),
]
MAX_REPS = 100


def build(outdir):
    binary = os.path.join(outdir, "diag.test")
    subprocess.run(
        ["go", "test", "-c", "-tags", "integration", "-o", binary, PACKAGE],
        check=True,
    )
    return binary


def run_arm(binary, outdir, sched, arm, rep):
    pattern = f"^{BENCH}$/^{sched}$/^{arm}$"
    path = os.path.join(outdir, f"{sched}-{arm}-r{rep}.txt")
    with open(path, "w") as out:
        subprocess.run(
            [
                binary,
                "-test.run", "^$",
                "-test.bench", pattern,
                "-test.benchtime=720x",
                "-test.benchmem",
                "-test.count=1",
            ],
            stdout=out,
            stderr=subprocess.STDOUT,
            check=True,
        )
    return path


def parse(path):
    """Return {unit: value} from the benchmark line, e.g. {"ns/op": 2.8e6, ...}."""
    metrics = {}
    with open(path) as f:
        for line in f:
            if not line.startswith(BENCH + "/"):
                continue
            fields = line.split()
            # fields[0] is the name, fields[1] the iteration count, then value unit pairs.
            for i in range(2, len(fields) - 1, 2):
                try:
                    value = float(fields[i])
                except ValueError:
                    continue
                metrics[fields[i + 1]] = value
    return metrics


def summarize(samples):
    values = sorted(samples)
    mean = statistics.mean(values)
    cv = statistics.stdev(values) / mean * 100 if len(values) > 1 and mean else 0.0
    return statistics.median(values), values[0], values[-1], cv


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("reps", type=int, choices=range(1, MAX_REPS + 1), metavar="REPS")
    reps = parser.parse_args().reps

    outdir = tempfile.mkdtemp(prefix="watch-one-hour-")
    print(f"output: {outdir}", flush=True)
    binary = build(outdir)

    samples = defaultdict(lambda: defaultdict(list))
    for rep in range(1, reps + 1):
        shift = (rep - 1) % len(ARMS)
        for sched, arm in ARMS[shift:] + ARMS[:shift]:
            metrics = parse(run_arm(binary, outdir, sched, arm, rep))
            for unit, value in metrics.items():
                samples[(sched, arm)][unit].append(value)

    lines = ["sched\tarm\tunit\tmedian\tmin\tmax\tcv_pct\tn"]
    for sched, arm in ARMS:
        for unit in sorted(samples[(sched, arm)]):
            median, lo, hi, cv = summarize(samples[(sched, arm)][unit])
            n = len(samples[(sched, arm)][unit])
            lines.append(f"{sched}\t{arm}\t{unit}\t{median:.6g}\t{lo:.6g}\t{hi:.6g}\t{cv:.2f}\t{n}")
    summary = "\n".join(lines) + "\n"
    with open(os.path.join(outdir, "summary.tsv"), "w") as f:
        f.write(summary)
    sys.stdout.write(summary)


if __name__ == "__main__":
    main()
