#!/usr/bin/env python3
"""Offline eval harness for the action-review policy."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import yaml  # noqa: E402

from agent_oversight.models import Decision  # noqa: E402
from agent_oversight.policy import Policy  # noqa: E402
from agent_oversight.tools import TOOL_METADATA, build_action  # noqa: E402

SCENARIO_KEYS = {"id", "description", "action", "expected"}
ACTION_KEYS = {"tool", "args", "user", "reversible", "impact", "context"}


def _load_scenarios() -> list[dict]:
    raw = yaml.safe_load((ROOT / "evals" / "scenarios.yml").read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or not isinstance(raw.get("scenarios"), list):
        raise SystemExit("scenarios.yml must contain a 'scenarios' list.")

    scenarios = raw["scenarios"]
    seen: set[str] = set()
    for scenario in scenarios:
        if not isinstance(scenario, dict):
            raise SystemExit("Each scenario must be a mapping.")

        unknown = set(scenario) - SCENARIO_KEYS
        if unknown:
            raise SystemExit(f"Unknown scenario keys: {sorted(unknown)}.")

        scenario_id = scenario.get("id")
        if not isinstance(scenario_id, str) or not scenario_id:
            raise SystemExit("Each scenario needs a non-empty string 'id'.")
        if scenario_id in seen:
            raise SystemExit(f"Duplicate scenario id: {scenario_id!r}.")
        seen.add(scenario_id)

        action = scenario.get("action")
        if not isinstance(action, dict):
            raise SystemExit(f"Scenario {scenario_id!r} needs an 'action' mapping.")
        unknown = set(action) - ACTION_KEYS
        if unknown:
            raise SystemExit(f"Unknown action keys in {scenario_id!r}: {sorted(unknown)}.")
        if not isinstance(action.get("tool"), str) or not action["tool"]:
            raise SystemExit(f"Scenario {scenario_id!r} needs a 'tool' string.")
        if "args" in action and not isinstance(action["args"], dict):
            raise SystemExit(f"Scenario {scenario_id!r} has non-mapping 'args'.")
        if "context" in action and not isinstance(action["context"], dict):
            raise SystemExit(f"Scenario {scenario_id!r} has non-mapping 'context'.")

        expected = str(scenario.get("expected", "")).lower()
        try:
            Decision(expected)
        except ValueError:
            raise SystemExit(
                f"Scenario {scenario_id!r} has an unknown expected decision."
            ) from None

    return scenarios


def _action_from(scenario: dict):
    data = scenario["action"]
    return build_action(
        data["tool"],
        data.get("args", {}),
        user=data.get("user", "default"),
        context=data.get("context", {}),
        reversible=data.get("reversible"),
        impact=data.get("impact"),
    )


def main() -> int:
    policy = Policy.load(ROOT / "policies" / "default.yml")
    scenarios = _load_scenarios()
    if not scenarios:
        print("No scenarios found.")
        return 1

    declared = set(TOOL_METADATA)
    for scenario in scenarios:
        tool = scenario["action"]["tool"]
        if tool not in declared:
            print(f"Warning: {scenario['id']!r} uses undeclared tool {tool!r}.")

    rows = []
    for scenario in scenarios:
        expected = Decision(str(scenario["expected"]).lower())
        try:
            actual = policy.evaluate(_action_from(scenario)).decision
            error = None
        except Exception as exc:  # report policy errors as failed rows
            actual = None
            error = str(exc)
        rows.append((scenario["id"], expected, actual, expected == actual, error))

    print(f"{'scenario':<32} {'expected':<18} {'actual':<18} result")
    print("-" * 80)
    for name, expected, actual, passed, error in rows:
        actual_label = actual.value if actual is not None else "error"
        result = "PASS" if passed else "FAIL"
        print(f"{name:<32} {expected.value:<18} {actual_label:<18} {result}")
        if error:
            print(f"  error: {error}")

    passed = sum(1 for row in rows if row[3])
    false_positives = sum(
        1
        for _, expected, actual, _, _ in rows
        if expected == Decision.DENY and actual == Decision.ALLOW
    )
    false_negatives = sum(
        1
        for _, expected, actual, _, _ in rows
        if expected == Decision.ALLOW and actual == Decision.DENY
    )
    approval_bypasses = sum(
        1
        for _, expected, actual, _, _ in rows
        if expected == Decision.REQUIRE_APPROVAL and actual == Decision.ALLOW
    )
    unexpected_approvals = sum(
        1
        for _, expected, actual, _, _ in rows
        if expected == Decision.ALLOW and actual == Decision.REQUIRE_APPROVAL
    )
    approval_cases = sum(
        1 for _, expected, _, _, _ in rows if expected == Decision.REQUIRE_APPROVAL
    )

    print("-" * 80)
    print(f"Accuracy: {passed}/{len(rows)} ({passed / len(rows) * 100:.1f}%)")
    print(f"False positives (allowed, expected deny): {false_positives}")
    print(f"False negatives (denied, expected allow): {false_negatives}")
    print(f"Approval bypasses (allowed, expected approval): {approval_bypasses}")
    print(f"Unexpected approvals (approval, expected allow): {unexpected_approvals}")
    print(f"Approval-required cases: {approval_cases}")

    return 0 if passed == len(rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
