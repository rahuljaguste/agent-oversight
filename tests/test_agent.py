from __future__ import annotations

from types import SimpleNamespace

import pytest

from agent_oversight.agent import TOOL_IMPLS, AppContext, _blocked, build_agent
from agent_oversight.models import Action, Decision, PolicyResult, ReviewResult
from agent_oversight.sandbox import Sandbox
from agent_oversight.tools import TOOL_METADATA

# One representative call per tool. A new tool needs an entry here, which
# forces the reviewer to exercise it.
TOOL_CALLS = {
    "read_file": ("notes.txt",),
    "send_email": ("alice@example.com", "Status", "Body"),
    "transfer_funds": (50, "treasury"),
    "fetch_url": ("https://docs.example.com/guide",),
}


class SpyReviewer:
    def __init__(self, final_decision: Decision = Decision.ALLOW):
        self.final_decision = final_decision
        self.actions: list[Action] = []

    def review(self, action: Action) -> ReviewResult:
        self.actions.append(action)
        policy = PolicyResult(decision=Decision.ALLOW, rule=None, reason="test")
        return ReviewResult(
            action=action,
            policy=policy,
            final_decision=self.final_decision,
        )


class ExplodingSandbox:
    def read_text(self, path: str) -> str:
        raise AssertionError("the sandbox must not run after a denial")


def _context(tmp_path, final_decision=Decision.ALLOW, user="tester"):
    spy = SpyReviewer(final_decision)
    app = AppContext(
        reviewer=spy,
        sandbox=Sandbox(tmp_path),
        user=user,
        action_context={"scope": "test"},
    )
    return SimpleNamespace(context=app), spy


def test_registries_agree():
    assert set(TOOL_IMPLS) == set(TOOL_METADATA)


def test_every_tool_has_a_representative_call():
    assert set(TOOL_CALLS) == set(TOOL_IMPLS)


def test_build_agent_registers_every_declared_tool():
    agent = build_agent()
    assert {tool.name for tool in agent.tools} == set(TOOL_IMPLS)


@pytest.mark.parametrize("tool", sorted(TOOL_IMPLS))
def test_every_tool_is_reviewed_with_metadata(tmp_path, tool):
    ctx, spy = _context(tmp_path)

    TOOL_IMPLS[tool](ctx, *TOOL_CALLS[tool])

    assert len(spy.actions) == 1
    action = spy.actions[0]
    assert action.tool == tool
    assert action.reversible is TOOL_METADATA[tool]["reversible"]
    assert action.impact == TOOL_METADATA[tool]["impact"]
    assert action.user == "tester"
    assert action.context == {"scope": "test"}


def test_denied_tool_does_not_run():
    spy = SpyReviewer(final_decision=Decision.DENY)
    app = AppContext(reviewer=spy, sandbox=ExplodingSandbox(), user="tester")
    ctx = SimpleNamespace(context=app)

    result = TOOL_IMPLS["read_file"](ctx, "notes.txt")

    assert result.startswith("Denied by")
    assert len(spy.actions) == 1


def test_blocked_message_distinguishes_policy_and_approver():
    action = Action(tool="send_email")
    policy_deny = PolicyResult(decision=Decision.DENY, rule="r", reason="policy says no")
    approval_required = PolicyResult(
        decision=Decision.REQUIRE_APPROVAL, rule="r", reason="needs approval"
    )

    policy_message = _blocked(
        ReviewResult(action=action, policy=policy_deny, final_decision=Decision.DENY)
    )
    approver_message = _blocked(
        ReviewResult(
            action=action,
            policy=approval_required,
            final_decision=Decision.DENY,
        )
    )
    error_message = _blocked(
        ReviewResult(
            action=action,
            policy=approval_required,
            final_decision=Decision.DENY,
            error="boom",
        )
    )

    assert policy_message.startswith("Denied by policy:")
    assert approver_message.startswith("Denied by the approver:")
    assert error_message.startswith("Denied by action review: boom")
