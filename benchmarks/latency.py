#!/usr/bin/env python3
"""Reproducible in-process latency benchmark for the review layer."""

from __future__ import annotations

import argparse
import platform
import statistics
import sys
import tempfile
import time
from collections.abc import Callable
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agent_oversight.approval import auto_approve  # noqa: E402
from agent_oversight.audit import AuditLogger  # noqa: E402
from agent_oversight.policy import Policy  # noqa: E402
from agent_oversight.review import ActionReviewer  # noqa: E402
from agent_oversight.tools import build_action  # noqa: E402

CASES = {
    "allow (read_file)": ("read_file", {"path": "notes.txt"}),
    "deny (external email)": (
        "send_email",
        {"to": "alice@evil.example", "subject": "Status", "body": "hello"},
    ),
    "approval (transfer 5000)": ("transfer_funds", {"amount": 5000, "to": "treasury"}),
}


def _percentile(sorted_samples: list[int], percentile: float) -> float:
    position = percentile / 100 * (len(sorted_samples) - 1)
    index = min(len(sorted_samples) - 1, max(0, round(position)))
    return sorted_samples[index] / 1000


def _measure(call: Callable[[], object], iterations: int, warmup: int) -> dict[str, float]:
    for _ in range(warmup):
        call()

    samples: list[int] = []
    for _ in range(iterations):
        started = time.perf_counter_ns()
        call()
        samples.append(time.perf_counter_ns() - started)

    samples.sort()
    return {
        "p50": _percentile(samples, 50),
        "p95": _percentile(samples, 95),
        "p99": _percentile(samples, 99),
        "mean": statistics.fmean(samples) / 1000,
        "max": samples[-1] / 1000,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=20_000)
    parser.add_argument("--warmup", type=int, default=1_000)
    args = parser.parse_args()
    if args.iterations < 1 or args.warmup < 0:
        parser.error("iterations must be positive and warmup must be non-negative")

    policy = Policy.load(ROOT / "policies" / "default.yml")
    reviewer = ActionReviewer(policy, audit=None, approver=auto_approve)
    actions = {label: build_action(tool, tool_args) for label, (tool, tool_args) in CASES.items()}

    rows: list[tuple[str, str, dict[str, float]]] = []
    for label, action in actions.items():
        policy_only = _measure(
            lambda a=action: policy.evaluate(a),
            args.iterations,
            args.warmup,
        )
        review_only = _measure(
            lambda a=action: reviewer.review(a),
            args.iterations,
            args.warmup,
        )
        rows.append((label, "policy only", policy_only))
        rows.append((label, "review (no audit)", review_only))

    with tempfile.TemporaryDirectory() as tmp_dir:
        audited = ActionReviewer(
            policy,
            audit=AuditLogger(Path(tmp_dir) / "audit.jsonl"),
            approver=auto_approve,
        )
        for label, action in actions.items():
            review_and_audit = _measure(
                lambda a=action: audited.review(a),
                args.iterations,
                args.warmup,
            )
            rows.append((label, "review + audit", review_and_audit))

    print(f"Platform: {platform.platform()} ({platform.machine()})")
    print(f"Python: {platform.python_version()}")
    print(f"Iterations per case: {args.iterations:,} (warmup {args.warmup:,})")
    print()
    print("| Case | Mode | p50 (us) | p95 (us) | p99 (us) | mean (us) | max (us) |")
    print("|---|---|---:|---:|---:|---:|---:|")
    for label, mode, stats in rows:
        print(
            f"| {label} | {mode} | {stats['p50']:.2f} | {stats['p95']:.2f} "
            f"| {stats['p99']:.2f} | {stats['mean']:.2f} | {stats['max']:.2f} |"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
