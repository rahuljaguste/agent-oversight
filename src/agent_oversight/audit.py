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
        "pass",
        "password",
        "private_key",
        "pwd",
        "secret",
        "session",
        "ssn",
        "token",
    }
)


def _normalise_key(key: Any) -> str:
    if isinstance(key, str):
        return key
    if isinstance(key, bytes):
        return key.decode("utf-8", "replace")
    return str(key)


def _redact(value: Any, key: str | None = None) -> tuple[Any, bool]:
    if key is not None and key.lower() in _SENSITIVE_ARG_KEYS:
        return f"[redacted {len(str(value))} chars]", True

    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        changed = False
        for child_key, child_value in value.items():
            normalised_key = _normalise_key(child_key)
            changed = changed or normalised_key != child_key
            redacted[normalised_key], child_changed = _redact(child_value, normalised_key)
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

    return value, False


def redact_args(args: Any) -> tuple[Any, bool]:
    """Redact secret-bearing argument values before they reach the audit log."""
    if not isinstance(args, dict):
        return {"_invalid_args": _normalise_key(args)}, True
    return _redact(args)


def sensitive_values(args: Any) -> list[str]:
    """Collect scalar values stored under sensitive argument names."""
    values: list[str] = []

    def walk(value: Any, key: str | None = None, sensitive: bool = False) -> None:
        if sensitive or (key is not None and key.lower() in _SENSITIVE_ARG_KEYS):
            if isinstance(value, dict):
                for child_key, child_value in value.items():
                    walk(child_value, _normalise_key(child_key), sensitive=True)
            elif isinstance(value, (list, tuple)):
                for child_value in value:
                    walk(child_value, key, sensitive=True)
            else:
                text = str(value)
                if text:
                    values.append(text)
            return

        if isinstance(value, dict):
            for child_key, child_value in value.items():
                walk(child_value, _normalise_key(child_key))
        elif isinstance(value, (list, tuple)):
            for child_value in value:
                walk(child_value, key)

    walk(args)
    return values


def redact_text(text: str | None, values: list[str]) -> str | None:
    """Remove known sensitive values embedded in free-form error text."""
    if not text:
        return text
    for value in sorted({item for item in values if len(item) >= 4}, key=len, reverse=True):
        text = text.replace(value, "[redacted]")
    return text


def _clean_string(text: str) -> str:
    """Replace lone surrogates, which UTF-8 cannot encode."""
    return text.encode("utf-8", "replace").decode("utf-8")


def _json_safe(value: Any) -> Any:
    """Make a value strict-JSON-safe: finite floats, string keys, valid UTF-8."""
    if isinstance(value, float) and not math.isfinite(value):
        return str(value)
    if isinstance(value, str):
        return _clean_string(value)
    if isinstance(value, dict):
        return {_normalise_key(key): _json_safe(child) for key, child in value.items()}
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
