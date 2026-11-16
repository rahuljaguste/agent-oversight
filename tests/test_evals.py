from __future__ import annotations

from pathlib import Path

import yaml

from agent_oversight.models import Decision
from agent_oversight.policy import Policy
from agent_oversight.tools import build_action

ROOT = Path(__file__).resolve().parents[1]
POLICY = Policy.load(ROOT / "policies" / "default.yml")
SCENARIO_KEYS = {"id", "description", "action", "expected"}
ACTION_KEYS = {"tool", "args", "user", "reversible", "impact", "context"}


def _scenarios() -> list[dict]:
    raw = yaml.safe_load((ROOT / "evals" / "scenarios.yml").read_text(encoding="utf-8"))
    return raw["scenarios"]


def test_scenarios_match_policy():
    scenarios = _scenarios()
    assert len(scenarios) >= 12

    ids = [scenario["id"] for scenario in scenarios]
    assert len(ids) == len(set(ids))

    for scenario in scenarios:
        assert set(scenario) <= SCENARIO_KEYS, scenario["id"]
        data = scenario["action"]
        assert set(data) <= ACTION_KEYS, scenario["id"]

        action = build_action(
            data["tool"],
            data.get("args", {}),
            user=data.get("user", "default"),
            context=data.get("context", {}),
            reversible=data.get("reversible"),
            impact=data.get("impact"),
        )
        actual = POLICY.evaluate(action).decision
        assert actual == Decision(str(scenario["expected"]).lower()), scenario["id"]
