"""The review layer that sits between the agent and its tools."""

from __future__ import annotations

import inspect
import time

from .approval import Approver, auto_deny
from .audit import AuditLogger, redact_args
from .models import Action, Approval, Decision, PolicyResult, ReviewResult
from .policy import Policy


class ActionReviewer:
    """Evaluate an action, ask for approval when required, and audit the result."""

    def __init__(
        self,
        policy: Policy,
        audit: AuditLogger | None = None,
        approver: Approver | None = None,
    ):
        self.policy = policy
        self.audit = audit
        self.approver = approver or auto_deny

    def review(self, action: Action) -> ReviewResult:
        policy_result, policy_latency_ms, error = self._evaluate(action)

        final = policy_result.decision
        approved_by: str | None = None
        denied_by: str | None = None
        approval_latency_ms = 0.0

        if final == Decision.REQUIRE_APPROVAL:
            approval, approval_latency_ms, approval_error = self._ask(action, policy_result)
            if approval_error is not None:
                final = Decision.DENY
                error = approval_error
            elif approval is None:
                final = Decision.DENY
                error = "Approver returned no decision."
            else:
                final = Decision.ALLOW if approval.approved else Decision.DENY
                if approval.approved:
                    approved_by = approval.approver
                else:
                    denied_by = approval.approver

        redacted_args, args_redacted = redact_args(action.args)
        record = {
            "tool": action.tool,
            "args": redacted_args,
            "args_redacted": args_redacted,
            "user": action.user,
            "reversible": action.reversible,
            "impact": action.impact,
            "policy_decision": policy_result.decision.value,
            "final_decision": final.value,
            "rule": policy_result.rule,
            "reason": policy_result.reason,
            "approved_by": approved_by,
            "denied_by": denied_by,
            "error": error,
            "policy_latency_ms": round(policy_latency_ms, 3),
            "approval_latency_ms": round(approval_latency_ms, 3),
        }

        if self.audit:
            try:
                self.audit.log(record)
            except OSError as exc:
                final = Decision.DENY
                error = f"Audit write failed: {exc}"

        return ReviewResult(
            action=action,
            policy=policy_result,
            final_decision=final,
            approved_by=approved_by,
            denied_by=denied_by,
            error=error,
            latency_ms=policy_latency_ms,
        )

    def _evaluate(self, action: Action) -> tuple[PolicyResult, float, str | None]:
        started = time.perf_counter()
        try:
            result = self.policy.evaluate(action)
        except Exception as exc:  # fail closed on any policy error
            result = PolicyResult(
                decision=Decision.DENY,
                rule=None,
                reason=f"Policy evaluation failed: {exc}",
            )
            error: str | None = str(exc)
        else:
            error = None
        latency_ms = (time.perf_counter() - started) * 1000
        return result, latency_ms, error

    def _ask(
        self, action: Action, policy_result: PolicyResult
    ) -> tuple[Approval | None, float, str | None]:
        started = time.perf_counter()
        try:
            approval = self.approver(action, policy_result)
        except Exception as exc:  # fail closed on any approver error
            latency_ms = (time.perf_counter() - started) * 1000
            return None, latency_ms, f"Approver error: {exc}"

        latency_ms = (time.perf_counter() - started) * 1000
        if inspect.iscoroutine(approval):
            approval.close()
            message = "Approver returned a coroutine; async approvers are unsupported."
            return None, latency_ms, message
        if not isinstance(approval, Approval):
            return (
                None,
                latency_ms,
                f"Approver returned {type(approval).__name__}, expected Approval.",
            )
        return approval, latency_ms, None
