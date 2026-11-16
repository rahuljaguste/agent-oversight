"""The review layer that sits between the agent and its tools."""

from __future__ import annotations

import inspect
import time
from copy import deepcopy
from dataclasses import replace

from .approval import Approver, auto_deny
from .audit import AuditLogger, redact_args, redact_text, sensitive_values
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
        snapshot = self._snapshot(action)
        policy_result, policy_latency_ms, error = self._evaluate(snapshot)

        final = policy_result.decision
        approved_by: str | None = None
        denied_by: str | None = None
        approval_latency_ms = 0.0

        if final == Decision.REQUIRE_APPROVAL:
            approver_action = self._snapshot(snapshot)
            approval, approval_latency_ms, approval_error = self._ask(
                approver_action, policy_result
            )
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

        try:
            sensitive = sensitive_values(snapshot.args) + sensitive_values(snapshot.context)
            redacted_args, args_redacted = redact_args(snapshot.args)
            reason = redact_text(policy_result.reason, sensitive) or ""
            error_text = redact_text(error, sensitive)
        except Exception as exc:  # fail closed if the record cannot be made auditable
            final = Decision.DENY
            redacted_args = {"_redaction_failed": "arguments unavailable"}
            args_redacted = True
            reason = ""
            error_text = f"Redaction failed: {type(exc).__name__}"

        record = {
            "tool": snapshot.tool,
            "args": redacted_args,
            "args_redacted": args_redacted,
            "user": snapshot.user,
            "reversible": snapshot.reversible,
            "impact": snapshot.impact,
            "policy_decision": policy_result.decision.value,
            "final_decision": final.value,
            "rule": policy_result.rule,
            "reason": reason,
            "approved_by": approved_by,
            "denied_by": denied_by,
            "error": error_text,
            "policy_latency_ms": round(policy_latency_ms, 3),
            "approval_latency_ms": round(approval_latency_ms, 3),
        }

        if self.audit:
            try:
                self.audit.log(record)
            except Exception as exc:  # fail closed if the record cannot be written
                final = Decision.DENY
                error_text = f"Audit write failed: {type(exc).__name__}"

        return ReviewResult(
            action=snapshot,
            policy=replace(policy_result, reason=reason),
            final_decision=final,
            approved_by=approved_by,
            denied_by=denied_by,
            error=error_text,
            latency_ms=policy_latency_ms,
        )

    def _snapshot(self, action: Action) -> Action:
        try:
            return replace(
                action,
                args=deepcopy(action.args),
                context=deepcopy(action.context),
            )
        except Exception:
            # Only reachable for non-copyable values, which JSON arguments cannot
            # produce; the fallback copies the top level only.
            return replace(action, args=dict(action.args), context=dict(action.context))

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
        if not isinstance(approval.approved, bool):
            return None, latency_ms, "Approver returned a non-boolean decision."
        if not isinstance(approval.approver, str) or not approval.approver.strip():
            return None, latency_ms, "Approver returned an empty identity."
        return approval, latency_ms, None
