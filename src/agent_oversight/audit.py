"""Append-only JSONL audit logging."""

from __future__ import annotations

import json
import math
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# Argument names whose values must never reach durable storage.
_SENSITIVE_ARG_KEYS = frozenset(
    {
        "api_key",
        "apikey",
        "authorization",
        "body",
        "card_number",
        "content",
        "credential",
        "credentials",
        "password",
        "private_key",
        "secret",
        "ssn",
        "token",
    }
)


def _redact(value: Any, key: str | None = None) -> tuple[Any, bool]:
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        changed = False
        for child_key, child_value in value.items():
            redacted[child_key], child_changed = _redact(child_value, child_key)
            changed = changed or child_changed
        return redacted, changed

    if isinstance(value, (list, tuple)):
        redacted_list: list[Any] = []
        changed = False
        for child_value in value:
            child_redacted, child_changed = _redact(child_value, key)
            redacted_list.append(child_redacted)
            changed = changed or child_changed
        return redacted_list, changed

    if key is not None and key.lower() in _SENSITIVE_ARG_KEYS:
        return f"[redacted {len(str(value))} chars]", True

    return value, False


def redact_args(args: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    """Redact secret-bearing argument values before they reach the audit log."""
    redacted, changed = _redact(args)
    return redacted, changed


def _json_safe(value: Any) -> Any:
    """Replace non-finite floats, which strict JSON parsers reject."""
    if isinstance(value, float) and not math.isfinite(value):
        return str(value)
    if isinstance(value, dict):
        return {key: _json_safe(child) for key, child in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(child) for child in value]
    return value


class AuditLogger:
    """Write one JSON object per line to an audit file."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def log(self, event: dict[str, Any]) -> None:
        record = {
            "timestamp": datetime.now(UTC).isoformat(),
            **_json_safe(event),
        }
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(
                json.dumps(record, ensure_ascii=False, default=str, allow_nan=False) + "\n"
            )
