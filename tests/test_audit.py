from __future__ import annotations

import json

import pytest

from agent_oversight.audit import (
    AuditLogger,
    redact_args,
    redact_text,
    sensitive_values,
)


def test_nested_values_under_sensitive_keys_are_redacted():
    redacted, changed = redact_args({"body": {"html": "sk-live-SECRET"}})
    assert changed is True
    assert redacted == {"body": "[redacted 26 chars]"}


def test_nested_sensitive_keys_are_redacted():
    redacted, changed = redact_args(
        {"credentials": {"api_key": "sk-live-SECRET", "pass": "hunter2"}}
    )
    assert changed is True
    assert "hunter2" not in json.dumps(redacted)
    assert "sk-live-SECRET" not in json.dumps(redacted)


def test_sensitive_list_is_redacted_as_a_unit():
    redacted, changed = redact_args({"secret": [{"value": "sk-live-SECRET"}]})
    assert changed is True
    assert "sk-live-SECRET" not in json.dumps(redacted)


def test_non_string_keys_are_normalised():
    redacted, changed = redact_args({1: "x", b"password": "hunter2"})
    assert changed is True
    assert redacted["1"] == "x"
    assert redacted["password"].startswith("[redacted ")
    json.dumps(redacted)


def test_non_dict_roots_are_redacted_not_stringified():
    redacted, changed = redact_args([{"password": "hunter2"}, "plain"])
    assert changed is True
    assert redacted[0]["password"].startswith("[redacted ")
    assert "hunter2" not in json.dumps(redacted)


def test_sensitive_values_are_collected_for_text_redaction():
    values = sensitive_values({"body": {"html": "sk-live-SECRET"}, "to": "alice@example.com"})
    assert "sk-live-SECRET" in values
    assert "alice@example.com" not in values


def test_redact_text_removes_known_values():
    assert redact_text("secret sk-live-SECRET here", ["sk-live-SECRET"]) == (
        "secret [redacted] here"
    )
    assert redact_text(None, ["sk-live-SECRET"]) is None


@pytest.mark.parametrize(
    "args",
    [
        {"path": "notes.txt", "subject": "\ud800"},
        {1: "x"},
        {b"x": "y"},
        {"\ud800": "v"},
        {"count": float("nan")},
    ],
)
def test_audit_log_stays_strict_json(tmp_path, args):
    path = tmp_path / "audit.jsonl"
    AuditLogger(path).log({"args": args})
    record = json.loads(path.read_text(encoding="utf-8").strip())
    assert "args" in record
