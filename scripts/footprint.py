#!/usr/bin/env python3
"""Footprint budgets: measure, compare with `footprint-budgets.json`, write a summary, fail when over budget.

    footprint.py idle  <bosun binary>        idle resident memory of `bosun serve` (Linux)
    footprint.py image <image name>          size of a container image (needs docker)
    footprint.py check name=value ...        any other metric (the benchmarks of WP-27 and WP-28 report here)

Every measurement is checked against its entry in `footprint-budgets.json`:

    "idle_rss_mb": {"budget": 50, "baseline": 21.0, "unit": "MB"}

It fails when the value is over `budget`, or more than `regression_pct` percent over `baseline` (the last accepted
number, so a creeping increase is caught long before the budget is). `higher_is_better: true` flips both
directions for throughput. Raise a baseline in the same pull request that justifies it. Results go to the
GitHub step summary when there is one, and to stdout.
"""
import json
import os
import pathlib
import signal
import subprocess
import sys
import tempfile
import time
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
BUDGETS = ROOT / "footprint-budgets.json"


def load():
    return json.loads(BUDGETS.read_text())


def judge(name, value, spec, regression_pct):
    """Return (ok, text)."""
    budget = spec["budget"]
    baseline = spec.get("baseline")
    up = spec.get("higher_is_better", False)
    unit = spec.get("unit", "")
    problems = []
    if (value < budget) if up else (value > budget):
        problems.append(f"{'under' if up else 'over'} the budget of {budget} {unit}")
    if baseline is not None:
        limit = baseline * (1 - regression_pct / 100) if up else baseline * (1 + regression_pct / 100)
        if (value < limit) if up else (value > limit):
            problems.append(f"more than {regression_pct}% {'below' if up else 'above'} the baseline of {baseline} {unit}")
    return (not problems, "; ".join(problems))


def report(rows):
    lines = ["### Footprint", "", "| Metric | Value | Budget | Baseline | |", "|---|---|---|---|---|"]
    ok_all = True
    for name, value, spec, ok, why in rows:
        unit = spec.get("unit", "")
        lines.append(
            f"| {name} | {value:.1f} {unit} | {spec['budget']} {unit} | {spec.get('baseline', '')} | "
            f"{'ok' if ok else 'FAIL: ' + why} |"
        )
        ok_all &= ok
    text = "\n".join(lines) + "\n"
    print(text)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as f:
            f.write(text)
    return ok_all


def free_port():
    import socket

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def rss_mb(pid):
    for line in pathlib.Path(f"/proc/{pid}/status").read_text().splitlines():
        if line.startswith("VmRSS:"):
            return int(line.split()[1]) / 1024
    raise SystemExit("no VmRSS (this check needs Linux)")


def idle(binary):
    ui, proxy = free_port(), free_port()
    with tempfile.TemporaryDirectory() as data:
        p = subprocess.Popen(
            [binary, "serve", "--data-dir", data, "--proxy", f"127.0.0.1:{proxy}", "--listen", f"127.0.0.1:{ui}"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env={"PATH": os.environ.get("PATH", ""), "BOSUN_LOG": "warn"},
        )
        try:
            for _ in range(100):
                try:
                    urllib.request.urlopen(f"http://127.0.0.1:{ui}/api/v1/status", timeout=1).read()
                    break
                except Exception:
                    time.sleep(0.1)
            else:
                raise SystemExit("bosun did not start")
            # Serve the UI once (as a browser would), then let it settle: idle means nothing is happening.
            urllib.request.urlopen(f"http://127.0.0.1:{ui}/", timeout=2).read()
            time.sleep(3)
            return rss_mb(p.pid)
        finally:
            p.send_signal(signal.SIGTERM)
            try:
                p.wait(10)
            except subprocess.TimeoutExpired:
                p.kill()


def image(name):
    out = subprocess.check_output(["docker", "image", "inspect", "-f", "{{.Size}}", name], text=True)
    return int(out.strip()) / 1e6


def main(argv):
    if len(argv) < 2:
        raise SystemExit(__doc__)
    cfg = load()
    pct = cfg.get("regression_pct", 10)
    metrics = cfg["metrics"]
    cmd = argv[1]
    if cmd == "idle":
        found = {"idle_rss_mb": idle(argv[2])}
    elif cmd == "image":
        found = {"image_mb": image(argv[2])}
    elif cmd == "check":
        found = {k: float(v) for k, v in (a.split("=", 1) for a in argv[2:])}
    else:
        raise SystemExit(__doc__)
    rows = []
    for name, value in found.items():
        spec = metrics.get(name)
        if spec is None:
            raise SystemExit(f"no budget for {name} in {BUDGETS.name}")
        ok, why = judge(name, value, spec, pct)
        rows.append((name, value, spec, ok, why))
    if not report(rows):
        raise SystemExit(1)


if __name__ == "__main__":
    main(sys.argv)
