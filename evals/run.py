#!/usr/bin/env python3
"""Offline eval harness for the action-review policy."""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import yaml  # noqa: E402

from agent_oversight.models import Decision  # noqa: E402
from agent_oversight.policy import Policy  # noqa: E402
from agent_oversight.tools import TOOL_METADATA, build_action  # noqa: E402

SCENARIO_KEYS = {"id", "description", "action", "expected", "rule"}
ACTION_KEYS = {"tool", "args", "user", "reversible", "impact", "context"}
SCENARIO_COUNT = 16
_IMPACTS = {"low", "medium", "high"}


@dataclass
class Row:
    scenario: str
    expected: Decision
    actual: Decision | None
    expected_rule: str | None
    actual_rule: str | None
    error: str | None

    @property
    def rule_ok(self) -> bool:
        return self.expected_rule is None or self.expected_rule == self.actual_rule

    @property
    def passed(self) -> bool:
        return self.actual == self.expected and self.rule_ok


def _load_scenarios() -> list[dict]:
    raw = yaml.safe_load((ROOT / "evals" / "scenarios.yml").read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or not isinstance(raw.get("scenarios"), list):
        raise SystemExit("scenarios.yml must contain a 'scenarios' list.")

    scenarios = raw["scenarios"]
    if len(scenarios) != SCENARIO_COUNT:
        raise SystemExit(
            f"Expected {SCENARIO_COUNT} scenarios, found {len(scenarios)}. "
            "Update SCENARIO_COUNT and the README when the set changes."
        )

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

        tool = action.get("tool")
        if not isinstance(tool, str) or not tool:
            raise SystemExit(f"Scenario {scenario_id!r} needs a 'tool' string.")
        if tool not in TOOL_METADATA:
            raise SystemExit(f"Scenario {scenario_id!r} uses undeclared tool {tool!r}.")

        args = action.get("args", {})
        if not isinstance(args, dict):
            raise SystemExit(f"Scenario {scenario_id!r} has non-mapping 'args'.")
        declared_args = set(TOOL_METADATA[tool].get("args", set()))
        unknown_args = set(args) - declared_args
        if unknown_args:
            raise SystemExit(
                f"Scenario {scenario_id!r} has unknown {tool!r} arguments: {sorted(unknown_args)}."
            )

        if "context" in action and not isinstance(action["context"], dict):
            raise SystemExit(f"Scenario {scenario_id!r} has non-mapping 'context'.")
        if "user" in action and not isinstance(action["user"], str):
            raise SystemExit(f"Scenario {scenario_id!r} has a non-string 'user'.")
        if "reversible" in action and not isinstance(action["reversible"], bool):
            raise SystemExit(f"Scenario {scenario_id!r} has a non-boolean 'reversible'.")
        if "impact" in action and action["impact"] not in _IMPACTS:
            raise SystemExit(f"Scenario {scenario_id!r} has an invalid 'impact'.")

        expected = str(scenario.get("expected", "")).lower()
        try:
            Decision(expected)
        except ValueError:
            raise SystemExit(
                f"Scenario {scenario_id!r} has an unknown expected decision."
            ) from None

        if "rule" in scenario:
            rule = scenario["rule"]
            if not isinstance(rule, str) or not rule.strip():
                raise SystemExit(f"Scenario {scenario_id!r} has an invalid 'rule'.")

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

    rows: list[Row] = []
    for scenario in scenarios:
        expected = Decision(str(scenario["expected"]).lower())
        expected_rule = scenario.get("rule")
        try:
            result = policy.evaluate(_action_from(scenario))
            actual: Decision | None = result.decision
            actual_rule: str | None = result.rule
            error = None
        except Exception as exc:  # report policy errors as failed rows
            actual = None
            actual_rule = None
            error = str(exc)
        rows.append(
            Row(
                scenario=scenario["id"],
                expected=expected,
                actual=actual,
                expected_rule=expected_rule,
                actual_rule=actual_rule,
                error=error,
            )
        )

    print(f"{'scenario':<32} {'expected':<18} {'actual':<18} result")
    print("-" * 80)
    for row in rows:
        actual_label = row.actual.value if row.actual is not None else "error"
        result = "PASS" if row.passed else "FAIL"
        print(f"{row.scenario:<32} {row.expected.value:<18} {actual_label:<18} {result}")
        if row.error:
            print(f"  error: {row.error}")
        if not row.rule_ok:
            print(f"  rule: expected {row.expected_rule!r}, got {row.actual_rule!r}")

    passed = sum(1 for row in rows if row.passed)
    errors = sum(1 for row in rows if row.actual is None)
    rule_mismatches = sum(1 for row in rows if not row.rule_ok)
    false_positives = sum(
        1 for row in rows if row.expected == Decision.DENY and row.actual == Decision.ALLOW
    )
    false_negatives = sum(
        1 for row in rows if row.expected == Decision.ALLOW and row.actual == Decision.DENY
    )
    approval_bypasses = sum(
        1
        for row in rows
        if row.expected == Decision.REQUIRE_APPROVAL and row.actual == Decision.ALLOW
    )
    unexpected_approvals = sum(
        1
        for row in rows
        if row.expected == Decision.ALLOW and row.actual == Decision.REQUIRE_APPROVAL
    )
    approval_cases = sum(1 for row in rows if row.expected == Decision.REQUIRE_APPROVAL)

    print("-" * 80)
    print(f"Accuracy: {passed}/{len(rows)} ({passed / len(rows) * 100:.1f}%)")
    print(f"False positives (allowed, expected deny): {false_positives}")
    print(f"False negatives (denied, expected allow): {false_negatives}")
    print(f"Approval bypasses (allowed, expected approval): {approval_bypasses}")
    print(f"Unexpected approvals (approval, expected allow): {unexpected_approvals}")
    print(f"Rule mismatches: {rule_mismatches}")
    print(f"Evaluation errors: {errors}")
    print(f"Approval-required cases: {approval_cases}")

    return 0 if passed == len(rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
