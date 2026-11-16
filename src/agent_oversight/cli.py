"""Command-line entry point."""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path

from .approval import auto_approve, cli_approve
from .audit import AuditLogger
from .models import Decision
from .policy import Policy
from .resources import default_policy_path
from .review import ActionReviewer
from .tools import build_action

_IMPACTS = {"low", "medium", "high"}


def _parse_value(raw: str):
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return raw


def _check_finite(value: object, name: str) -> None:
    if isinstance(value, float) and not math.isfinite(value):
        raise SystemExit(f"{name} must be a finite number, got {value!r}.")
    if isinstance(value, dict):
        for child_key, child_value in value.items():
            _check_finite(child_value, f"{name}.{child_key}")
    if isinstance(value, list):
        for index, child_value in enumerate(value):
            _check_finite(child_value, f"{name}[{index}]")


def _parse_args(pairs: list[str]) -> dict:
    parsed = {}
    for pair in pairs:
        if "=" not in pair:
            raise SystemExit(f"Argument must be key=value: {pair!r}")
        key, raw = pair.split("=", 1)
        parsed[key] = _parse_value(raw)
        _check_finite(parsed[key], key)
    return parsed


def _parse_bool(name: str, raw: object) -> bool:
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, int) and raw in (0, 1):
        return bool(raw)
    if isinstance(raw, str):
        value = raw.strip().lower()
        if value in {"true", "yes", "y", "on", "1"}:
            return True
        if value in {"false", "no", "n", "off", "0"}:
            return False
    raise SystemExit(f"{name} must be a boolean, got {raw!r}.")


def _parse_impact(raw: object) -> str:
    value = str(raw).strip().lower()
    if value not in _IMPACTS:
        raise SystemExit(f"impact must be one of {sorted(_IMPACTS)}, got {raw!r}.")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agent-oversight")
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser("check", help="Evaluate one action against the policy.")
    check.add_argument("--tool", required=True)
    check.add_argument(
        "--arg",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="Tool argument. 'reversible' and 'impact' override the tool metadata.",
    )
    check.add_argument(
        "--policy", default=None, help="Policy file. Defaults to the shipped policy."
    )
    check.add_argument("--audit", default=None, help="Audit file. Defaults to ./runs/audit.jsonl.")
    check.add_argument("--user", default="cli")
    check.add_argument("--auto-approve", action="store_true")

    demo = sub.add_parser("demo", help="Run the OpenAI Agents SDK demo.")
    demo.add_argument(
        "prompt",
        nargs="?",
        default="Send an email to alice@example.com and transfer 5000 to treasury.",
    )
    demo.add_argument("--policy", default=None)
    demo.add_argument("--audit", default=None)
    demo.add_argument("--auto-approve", action="store_true")

    args = parser.parse_args(argv)

    if args.command == "check":
        parsed = _parse_args(args.arg)
        reversible_raw = parsed.pop("reversible", None)
        impact_raw = parsed.pop("impact", None)
        reversible = (
            _parse_bool("reversible", reversible_raw) if reversible_raw is not None else None
        )
        impact = _parse_impact(impact_raw) if impact_raw is not None else None
        action = build_action(
            args.tool,
            parsed,
            user=args.user,
            reversible=reversible,
            impact=impact,
        )
        try:
            policy = Policy.load(args.policy or default_policy_path())
            audit = AuditLogger(args.audit or Path.cwd() / "runs" / "audit.jsonl")
        except (OSError, ValueError) as exc:
            print(f"Setup error: {exc}")
            return 2
        reviewer = ActionReviewer(
            policy,
            audit,
            approver=auto_approve if args.auto_approve else cli_approve,
        )
        result = reviewer.review(action)
        if result.error:
            message = f"Denied by action review: {result.error}"
        elif (
            result.final_decision == Decision.DENY
            and result.policy.decision == Decision.REQUIRE_APPROVAL
        ):
            message = f"Denied by the approver: {result.policy.reason}"
        else:
            message = result.policy.reason
        print(f"{result.final_decision.value}. {message}")
        return 0 if result.final_decision == Decision.ALLOW else 1

    try:
        from .agent import run_demo
    except ImportError as exc:
        print(f"Could not import the OpenAI Agents SDK: {exc}")
        print('Install the project with: pip install -e ".[dev]"')
        return 2

    try:
        output = run_demo(
            args.prompt,
            policy_path=args.policy,
            audit_path=args.audit,
            auto=args.auto_approve,
        )
    except (OSError, ValueError) as exc:
        print(f"Demo error: {exc}")
        return 2
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
