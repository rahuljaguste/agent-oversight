"""An OpenAI Agents SDK demo agent with reviewed tools."""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from agents import (
    Agent,
    OpenAIProvider,
    RunConfig,
    RunContextWrapper,
    Runner,
    function_tool,
)

from .approval import auto_approve, cli_approve
from .audit import AuditLogger
from .models import Decision, ReviewResult
from .policy import Policy
from .resources import default_policy_path
from .review import ActionReviewer
from .sandbox import Sandbox
from .tools import build_action


def _run_config() -> RunConfig | None:
    """Use Chat Completions and disable tracing for a custom OpenAI-compatible endpoint."""
    if not os.getenv("OPENAI_BASE_URL"):
        return None

    disable_tracing = os.getenv("OPENAI_AGENTS_DISABLE_TRACING", "").lower() not in {
        "0",
        "false",
    }
    return RunConfig(
        model_provider=OpenAIProvider(use_responses=False),
        tracing_disabled=disable_tracing,
    )


@dataclass
class AppContext:
    reviewer: ActionReviewer
    sandbox: Sandbox
    user: str = "demo"
    action_context: dict = field(default_factory=dict)


def _blocked(review: ReviewResult) -> str:
    if review.error:
        return f"Denied by action review: {review.error}"
    if review.policy.decision == Decision.DENY:
        return f"Denied by policy: {review.policy.reason}"
    return f"Denied by the approver: {review.policy.reason}"


def _review(ctx: RunContextWrapper[AppContext], tool: str, args: dict) -> ReviewResult:
    action = build_action(
        tool,
        args,
        user=ctx.context.user,
        context=ctx.context.action_context,
    )
    return ctx.context.reviewer.review(action)


def _read_file(ctx: RunContextWrapper[AppContext], path: str) -> str:
    """Read a text file from the sandboxed workspace."""
    review = _review(ctx, "read_file", {"path": path})
    if review.final_decision != Decision.ALLOW:
        return _blocked(review)
    try:
        return ctx.context.sandbox.read_text(path)
    except (OSError, ValueError) as exc:
        return f"Read failed: {exc}"


def _send_email(ctx: RunContextWrapper[AppContext], to: str, subject: str, body: str) -> str:
    """Send a mock email to a recipient."""
    review = _review(ctx, "send_email", {"to": to, "subject": subject, "body": body})
    if review.final_decision != Decision.ALLOW:
        return _blocked(review)
    return f"Mock email sent to {to} with subject {subject!r}."


def _transfer_funds(ctx: RunContextWrapper[AppContext], amount: float, to: str) -> str:
    """Transfer mock funds to a recipient."""
    review = _review(ctx, "transfer_funds", {"amount": amount, "to": to})
    if review.final_decision != Decision.ALLOW:
        return _blocked(review)
    return f"Mock transfer of {amount} to {to}."


def _fetch_url(ctx: RunContextWrapper[AppContext], url: str) -> str:
    """Fetch a mock URL from an allowlisted domain."""
    review = _review(ctx, "fetch_url", {"url": url})
    if review.final_decision != Decision.ALLOW:
        return _blocked(review)
    return f"Mock fetch of {url} returned 200 OK."


# Every tool the agent can call must be registered here. Each implementation
# starts with _review, and the tests iterate this registry to prove it.
TOOL_IMPLS: dict[str, Callable[..., str]] = {
    "read_file": _read_file,
    "send_email": _send_email,
    "transfer_funds": _transfer_funds,
    "fetch_url": _fetch_url,
}


def build_agent() -> Agent:
    """Build the demo agent with the reviewed tools."""
    return Agent(
        name="Action-review demo agent",
        instructions=(
            "You are a helpful assistant with tools. Use the tools when the user asks. "
            "Every tool call is reviewed before it runs. If a tool returns a blocked message, "
            "explain that the action needs approval or was denied."
        ),
        tools=[function_tool(impl, name_override=name) for name, impl in TOOL_IMPLS.items()],
    )


def run_demo(
    prompt: str,
    policy_path: str | Path | None = None,
    audit_path: str | Path | None = None,
    sandbox_path: str | Path | None = None,
    auto: bool = False,
) -> str:
    """Run the SDK agent once with a reviewed tool set."""
    policy = Policy.load(policy_path or default_policy_path())
    approver = auto_approve if auto else cli_approve
    audit_path = audit_path or Path.cwd() / "runs" / "audit.jsonl"
    sandbox_path = sandbox_path or Path.cwd() / "runs" / "sandbox"

    reviewer = ActionReviewer(policy, AuditLogger(audit_path), approver=approver)
    context = AppContext(
        reviewer=reviewer,
        sandbox=Sandbox(sandbox_path),
        user="demo",
    )
    result = Runner.run_sync(
        build_agent(),
        prompt,
        context=context,
        run_config=_run_config(),
    )
    return result.final_output
