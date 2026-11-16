from __future__ import annotations

from pathlib import Path

import pytest

import evals.run as run
from agent_oversight.models import Decision
from agent_oversight.policy import Policy
from evals.run import SCENARIO_COUNT, _action_from, _load_scenarios

ROOT = Path(__file__).resolve().parents[1]
POLICY = Policy.load(ROOT / "policies" / "default.yml")


def test_scenarios_match_policy():
    scenarios = _load_scenarios()
    assert len(scenarios) == SCENARIO_COUNT

    for scenario in scenarios:
        result = POLICY.evaluate(_action_from(scenario))
        assert result.decision == Decision(str(scenario["expected"]).lower()), scenario["id"]
        if "rule" in scenario:
            assert result.rule == scenario["rule"], scenario["id"]


def _write_scenarios(tmp_path: Path, monkeypatch, body: str) -> None:
    directory = tmp_path / "evals"
    directory.mkdir()
    (directory / "scenarios.yml").write_text(body, encoding="utf-8")
    monkeypatch.setattr(run, "ROOT", tmp_path)
    monkeypatch.setattr(run, "SCENARIO_COUNT", 1)


def test_loader_rejects_undeclared_tool(tmp_path, monkeypatch):
    _write_scenarios(
        tmp_path,
        monkeypatch,
        "scenarios:\n  - id: bad\n    action:\n      tool: read_flie\n"
        "      args: {path: notes.txt}\n    expected: allow\n",
    )
    with pytest.raises(SystemExit, match="undeclared tool"):
        _load_scenarios()


def test_loader_rejects_unknown_arguments(tmp_path, monkeypatch):
    _write_scenarios(
        tmp_path,
        monkeypatch,
        "scenarios:\n  - id: bad\n    action:\n      tool: fetch_url\n"
        "      args: {url: https://docs.example.com, uri: https://evil.example}\n"
        "    expected: allow\n",
    )
    with pytest.raises(SystemExit, match="unknown"):
        _load_scenarios()
