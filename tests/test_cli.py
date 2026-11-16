from __future__ import annotations

import json

import pytest

from agent_oversight.approval import cli_approve
from agent_oversight.cli import _parse_args, _parse_bool, _parse_impact, main
from agent_oversight.models import Decision, PolicyResult
from agent_oversight.tools import build_action


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (True, True),
        (False, False),
        ("true", True),
        ("False", False),
        ("no", False),
        ("off", False),
        ("1", True),
        ("0", False),
        (1, True),
        (0, False),
    ],
)
def test_parse_bool(raw, expected):
    assert _parse_bool("reversible", raw) is expected


@pytest.mark.parametrize("raw", ["maybe", 2, 1.5, None])
def test_parse_bool_rejects(raw):
    with pytest.raises(SystemExit):
        _parse_bool("reversible", raw)


@pytest.mark.parametrize("raw", ["NaN", "Infinity", "-Infinity"])
def test_parse_args_rejects_non_finite(raw):
    with pytest.raises(SystemExit):
        _parse_args([f"amount={raw}"])


@pytest.mark.parametrize("raw", ["low", "MEDIUM", "high"])
def test_parse_impact_accepts(raw):
    assert _parse_impact(raw) == raw.lower()


def test_parse_impact_rejects():
    with pytest.raises(SystemExit):
        _parse_impact("critical")


def test_cli_boolean_override_is_honoured(tmp_path):
    audit = tmp_path / "audit.jsonl"
    code = main(
        [
            "check",
            "--tool",
            "read_file",
            "--arg",
            "path=notes.txt",
            "--arg",
            "reversible=False",
            "--auto-approve",
            "--audit",
            str(audit),
        ]
    )

    assert code == 0
    record = json.loads(audit.read_text(encoding="utf-8").strip())
    assert record["reversible"] is False
    assert record["policy_decision"] == "require_approval"
    assert record["approved_by"] == "auto"


def test_cli_denies_absolute_path(tmp_path):
    audit = tmp_path / "audit.jsonl"
    code = main(
        [
            "check",
            "--tool",
            "read_file",
            "--arg",
            "path=/etc/passwd",
            "--auto-approve",
            "--audit",
            str(audit),
        ]
    )

    assert code == 1
    record = json.loads(audit.read_text(encoding="utf-8").strip())
    assert record["rule"] == "deny_path_escape"
    assert record["final_decision"] == "deny"


def test_cli_approval_redacts_secret(monkeypatch, capsys):
    action = build_action(
        "send_email",
        {"to": "alice@example.com", "subject": "Status", "body": "sk-live-SECRET"},
    )
    result = PolicyResult(
        decision=Decision.REQUIRE_APPROVAL,
        rule="approve_irreversible",
        reason="needs approval",
    )
    monkeypatch.setattr("builtins.input", lambda _prompt: "y")

    approval = cli_approve(action, result)

    output = capsys.readouterr().out
    assert approval.approved is True
    assert "sk-live-SECRET" not in output
    assert "[redacted" in output
