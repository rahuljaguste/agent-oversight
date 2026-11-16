from __future__ import annotations

from pathlib import Path

import pytest

from agent_oversight.models import Action, Decision
from agent_oversight.policy import Policy, Rule

ROOT = Path(__file__).resolve().parents[1]
POLICY = Policy.load(ROOT / "policies" / "default.yml")


@pytest.mark.parametrize(
    ("tool", "args", "expected"),
    [
        ("send_email", {"to": "alice@example.com"}, Decision.ALLOW),
        ("send_email", {"to": "alice@evil.example"}, Decision.DENY),
        ("send_email", {"to": "attacker@evil.example, alice@example.com"}, Decision.DENY),
        ("send_email", {"to": "alice@example.com, bob@example.com"}, Decision.ALLOW),
        ("send_email", {"to": "alice@example.com; attacker@evil.example"}, Decision.DENY),
        ("send_email", {"to": "alice@example.com\nattacker@evil.example"}, Decision.DENY),
        ("send_email", {"to": "Alice <alice@evil.example>"}, Decision.DENY),
        ("send_email", {"to": "Alice <alice@example.com>"}, Decision.ALLOW),
        (
            "send_email",
            {"to": "Alice <alice@example.com>, attacker@evil.example"},
            Decision.DENY,
        ),
        ("send_email", {"to": ["alice@example.com", "bob@example.com"]}, Decision.ALLOW),
        ("send_email", {"to": ["alice@example.com", "attacker@evil.example"]}, Decision.DENY),
        ("transfer_funds", {"amount": 250, "to": "treasury"}, Decision.ALLOW),
        ("transfer_funds", {"amount": 5000, "to": "treasury"}, Decision.REQUIRE_APPROVAL),
        ("fetch_url", {"url": "https://docs.example.com/guide"}, Decision.ALLOW),
        ("fetch_url", {"url": "https://evil.example/collect"}, Decision.DENY),
        ("fetch_url", {"url": "https://evil.example/?q=<docs.example.com>"}, Decision.DENY),
        ("fetch_url", {"url": "https:evil.example/path@docs.example.com"}, Decision.DENY),
        ("fetch_url", {"url": "//evil.example/?q=a@docs.example.com"}, Decision.DENY),
        ("fetch_url", {"url": "https://evil.example\\@docs.example.com/"}, Decision.DENY),
        ("fetch_url", {"url": "https://evil.example\\.docs.example.com/"}, Decision.DENY),
        ("read_file", {"path": "notes.txt"}, Decision.ALLOW),
        ("read_file", {"path": "../../etc/passwd"}, Decision.DENY),
        ("read_file", {"path": "/etc/passwd"}, Decision.DENY),
        ("read_file", {"path": "C:\\Windows\\win.ini"}, Decision.DENY),
        ("read_file", {"path": ["/etc/passwd"]}, Decision.DENY),
    ],
)
def test_decisions(tool, args, expected):
    assert POLICY.evaluate(Action(tool=tool, args=args)).decision == expected


def test_irreversible_requires_approval():
    action = Action(
        tool="transfer_funds",
        args={"amount": 50, "to": "treasury"},
        reversible=False,
    )
    result = POLICY.evaluate(action)
    assert result.decision == Decision.REQUIRE_APPROVAL
    assert result.rule == "approve_irreversible"


@pytest.mark.parametrize("amount", [float("nan"), float("inf"), float("-inf")])
def test_non_finite_amount_is_rejected(amount):
    action = Action(tool="transfer_funds", args={"amount": amount, "to": "treasury"})
    with pytest.raises(ValueError):
        POLICY.evaluate(action)


def test_unknown_operator_raises():
    policy = Policy(
        rules=(Rule(name="bad", decision=Decision.DENY, when={"tool": {"nope": 1}}),),
    )
    with pytest.raises(ValueError):
        policy.evaluate(Action(tool="send_email"))


def test_null_condition_never_matches():
    policy = Policy(
        rules=(Rule(name="null", decision=Decision.ALLOW, when={"args.to": None}),),
        default_decision=Decision.DENY,
    )
    assert policy.evaluate(Action(tool="send_email", args={})).decision == Decision.DENY


def test_in_matches_lists_only():
    policy = Policy(
        rules=(
            Rule(
                name="allow_admin",
                decision=Decision.ALLOW,
                when={"args.role": {"in": ["admin", "owner"]}},
            ),
        ),
        default_decision=Decision.DENY,
    )
    assert policy.evaluate(Action(tool="x", args={"role": "admin"})).decision == Decision.ALLOW
    assert policy.evaluate(Action(tool="x", args={"role": "a"})).decision == Decision.DENY


def test_eq_is_type_strict():
    policy = Policy(
        rules=(
            Rule(
                name="verified",
                decision=Decision.ALLOW,
                when={"args.verified": {"eq": True}},
            ),
        ),
        default_decision=Decision.DENY,
    )
    assert policy.evaluate(Action(tool="x", args={"verified": True})).decision == Decision.ALLOW
    assert policy.evaluate(Action(tool="x", args={"verified": 1})).decision == Decision.DENY
    assert policy.evaluate(Action(tool="x", args={"verified": 1.0})).decision == Decision.DENY


def test_in_is_type_strict():
    policy = Policy(
        rules=(
            Rule(
                name="listed_level",
                decision=Decision.ALLOW,
                when={"args.level": {"in": [1]}},
            ),
        ),
        default_decision=Decision.DENY,
    )
    assert policy.evaluate(Action(tool="x", args={"level": 1})).decision == Decision.ALLOW
    assert policy.evaluate(Action(tool="x", args={"level": True})).decision == Decision.DENY


def test_not_in_is_type_strict():
    policy = Policy(
        rules=(
            Rule(
                name="deny_unlisted",
                decision=Decision.DENY,
                when={"args.level": {"not_in": [1]}},
            ),
        ),
        default_decision=Decision.ALLOW,
    )
    # A boolean does not equal 1, so the deny rule still fires.
    assert policy.evaluate(Action(tool="x", args={"level": True})).decision == Decision.DENY
    assert policy.evaluate(Action(tool="x", args={"level": 1})).decision == Decision.ALLOW


def test_contains_is_type_strict_for_lists():
    policy = Policy(
        rules=(
            Rule(
                name="flagged",
                decision=Decision.DENY,
                when={"args.flags": {"contains": 1}},
            ),
        ),
        default_decision=Decision.ALLOW,
    )
    assert policy.evaluate(Action(tool="x", args={"flags": [1]})).decision == Decision.DENY
    assert policy.evaluate(Action(tool="x", args={"flags": [True]})).decision == Decision.ALLOW
    # A non-string needle never matches inside a string.
    assert policy.evaluate(Action(tool="x", args={"flags": "v1"})).decision == Decision.ALLOW


def test_contains_keeps_substring_semantics_on_strings():
    policy = Policy(
        rules=(
            Rule(
                name="flagged",
                decision=Decision.DENY,
                when={"args.flags": {"contains": "1"}},
            ),
        ),
        default_decision=Decision.ALLOW,
    )
    assert policy.evaluate(Action(tool="x", args={"flags": "v1"})).decision == Decision.DENY
    assert policy.evaluate(Action(tool="x", args={"flags": "v2"})).decision == Decision.ALLOW


def test_path_prefix_normalises_and_respects_boundaries():
    policy = Policy(
        rules=(
            Rule(
                name="allow_sandbox",
                decision=Decision.ALLOW,
                when={"args.path": {"path_prefix": "/srv/sandbox"}},
            ),
        ),
        default_decision=Decision.DENY,
    )
    allowed = [Action(tool="read_file", args={"path": "/srv/sandbox/file"})]
    denied = [
        Action(tool="read_file", args={"path": "/srv/sandbox-evil/secret"}),
        Action(tool="read_file", args={"path": "/srv/sandbox/../../etc/passwd"}),
        Action(tool="read_file", args={"path": ["/srv/sandbox/file"]}),
    ]
    assert all(policy.evaluate(action).decision == Decision.ALLOW for action in allowed)
    assert all(policy.evaluate(action).decision == Decision.DENY for action in denied)


def _write_policy(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "policy.yml"
    path.write_text(text, encoding="utf-8")
    return path


@pytest.mark.parametrize(
    "text",
    [
        "",
        "version: 1\ndefault_decision: allow\n",
        "version: 1\ndefault_decision: allow\nrules: []\nrule: []\n",
        "version: 1\nrules: []\n",
        "version: 2\ndefault_decision: allow\nrules: []\n",
        "version: 1\ndefault_decision: allow\nrules:\n  - name: r\n    decision: allow\n"
        "    whn: {}\n",
        "version: 1\ndefault_decision: allow\nrules:\n  - name: r\n    decision: allow\n"
        "    when:\n      args.to:\n        nope: 1\n",
        "version: 1\ndefault_decision: allow\nrules:\n  - name: r\n    decision: allow\n"
        "    when:\n      args.to: {}\n",
        "version: 1\ndefault_decision: allow\nrules:\n  - name: r\n    decision: allow\n"
        "    when:\n      args: {eq: x}\n",
        "version: 1\ndefault_decision: allow\nrules:\n  - name: r\n    decision: allow\n"
        "    when:\n      bogus: 1\n",
        "version: 1\ndefault_decision: allow\nrules:\n  - name: r\n    decision: allow\n"
        "  - name: r\n    decision: deny\n",
        "version: 1\ndefault_decision: allow\nrules:\n  - name: r\n    decision: maybe\n",
        "version: 1\ndefault_decision: allow\nrules:\n  - name: r\n    decision: allow\n"
        "    when:\n      reversible:\n        exists: 1\n",
        "version: 1\ndefault_decision: allow\nrules:\n  - name: r\n    decision: allow\n"
        "    when:\n      args.role: {in: 1}\n",
        "version: 1\ndefault_decision: allow\nrules:\n  - name: r\n    decision: allow\n"
        "    when:\n      args.role: {in: admin}\n",
        "version: 1\ndefault_decision: allow\nrules:\n  - name: r\n    decision: allow\n"
        '    when:\n      reversible: {eq: "false"}\n',
        "version: 1\ndefault_decision: allow\nrules:\n  - name: r\n    decision: allow\n"
        "    tool:\n",
        "version: 1\ndefault_decision: allow\nrules:\n  - name: r\n    decision: allow\n"
        '    tool: ""\n',
        "version: 1\ndefault_decision: allow\nrules:\n  - name: r\n    decision: allow\n"
        "    when:\n      args.to: null\n",
        "version: 1\ndefault_decision: allow\nrules:\n  - name: r\n    decision: allow\n"
        "    when:\n      args.amount: {gt: .nan}\n",
        "version: 1\ndefault_decision: allow\nrules:\n  - name: r\n    decision: allow\n"
        "    when:\n      args.amount: {gt: .inf}\n",
        "version: 1\ndefault_decision: deny\ndefault_decision: allow\nrules: []\n",
        "version: 1\ndefault_decision: allow\nrules:\n  - name: r\n    decision: allow\n"
        "    when:\n      args.amount:\n        gt: 1\n        gt: 2\n",
    ],
)
def test_invalid_policies_are_rejected(tmp_path, text):
    with pytest.raises(ValueError):
        Policy.load(_write_policy(tmp_path, text))


def test_empty_rules_are_allowed_with_explicit_deny(tmp_path):
    policy = Policy.load(_write_policy(tmp_path, "version: 1\ndefault_decision: deny\nrules: []\n"))
    assert policy.evaluate(Action(tool="send_email")).decision == Decision.DENY
