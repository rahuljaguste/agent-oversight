"""Tool metadata shared by the agent, the CLI and the eval harness."""

from __future__ import annotations

from typing import Any

from .models import Action

# Declared per tool so a live action carries the same semantics as a scenario.
# Sending and transferring cannot be undone; reading and fetching can.
TOOL_METADATA: dict[str, dict[str, Any]] = {
    "read_file": {"reversible": True, "impact": "low", "args": {"path"}},
    "send_email": {
        "reversible": False,
        "impact": "medium",
        "args": {"to", "subject", "body"},
    },
    "transfer_funds": {
        "reversible": False,
        "impact": "high",
        "args": {"amount", "to"},
    },
    "fetch_url": {"reversible": True, "impact": "low", "args": {"url"}},
}


def build_action(
    tool: str,
    args: dict[str, Any] | None = None,
    *,
    user: str = "default",
    context: dict[str, Any] | None = None,
    reversible: bool | None = None,
    impact: str | None = None,
) -> Action:
    """Build an action, filling reversibility and impact from tool metadata."""
    metadata = TOOL_METADATA.get(tool, {})
    return Action(
        tool=tool,
        args=args or {},
        user=user,
        reversible=metadata.get("reversible", True) if reversible is None else reversible,
        impact=metadata.get("impact", "low") if impact is None else impact,
        context=context or {},
    )
