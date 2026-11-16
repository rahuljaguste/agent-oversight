"""Core data types for the action-review layer."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Decision(StrEnum):
    """The outcome of a policy evaluation or a review."""

    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


@dataclass(frozen=True)
class Action:
    """A proposed tool call, before any side effect happens."""

    tool: str
    args: dict[str, Any] = field(default_factory=dict)
    user: str = "default"
    reversible: bool = True
    impact: str = "low"
    context: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class PolicyResult:
    """A policy decision with the rule that produced it."""

    decision: Decision
    rule: str | None = None
    reason: str = ""


@dataclass(frozen=True)
class Approval:
    """An approver's decision and the identity that made it."""

    approved: bool
    approver: str


@dataclass(frozen=True)
class ReviewResult:
    """The final decision after any required human approval."""

    action: Action
    policy: PolicyResult
    final_decision: Decision
    approved_by: str | None = None
    denied_by: str | None = None
    error: str | None = None
    latency_ms: float = 0.0
