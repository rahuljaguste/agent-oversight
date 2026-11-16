"""Human approval strategies for the review layer."""

from __future__ import annotations

import threading
from collections.abc import Callable

from .audit import redact_args
from .models import Action, Approval, PolicyResult

Approver = Callable[[Action, PolicyResult], Approval]

# The Agents SDK runs parallel tool calls in separate threads. Serialise the
# prompt and the answer so two approvals cannot interleave on shared stdin.
_APPROVAL_LOCK = threading.Lock()


def auto_approve(action: Action, result: PolicyResult) -> Approval:
    """Approve every request. Intended for tests and offline evals."""
    return Approval(approved=True, approver="auto")


def auto_deny(action: Action, result: PolicyResult) -> Approval:
    """Deny every request. The safe default when no human is present."""
    return Approval(approved=False, approver="auto")


def cli_approve(action: Action, result: PolicyResult) -> Approval:
    """Ask a human at the terminal to approve one action."""
    safe_args, _ = redact_args(action.args)
    with _APPROVAL_LOCK:
        print(f"\nApproval required for {action.tool}({safe_args})")
        print(f"Rule {result.rule}. {result.reason}")
        answer = input("Approve this action? [y/N] ").strip().lower()
    return Approval(approved=answer in {"y", "yes"}, approver="terminal")
