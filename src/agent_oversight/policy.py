"""A small YAML policy engine for tool-call review."""

from __future__ import annotations

import math
import posixpath
import re
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlparse

import yaml

from .models import Action, Decision, PolicyResult

_ALLOWED_POLICY_KEYS = {"version", "default_decision", "rules"}
_ALLOWED_RULE_KEYS = {"name", "decision", "tool", "when", "reason"}
_SCALAR_ROOTS = {"tool", "user", "reversible", "impact"}
_MAPPING_ROOTS = {"args", "context"}
_OPERATORS = {
    "exists",
    "eq",
    "equals",
    "neq",
    "not_equals",
    "gt",
    "gte",
    "lt",
    "lte",
    "in",
    "not_in",
    "contains",
    "not_contains",
    "domain",
    "not_domain",
    "path_prefix",
    "not_path_prefix",
    "path_escape",
}
_ADDRESS_SEPARATORS = re.compile(r"[,;\s]+")
_WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:[\\/]")


@dataclass(frozen=True)
class Rule:
    """One ordered policy rule."""

    name: str
    decision: Decision
    tool: str | None = None
    when: dict[str, Any] = field(default_factory=dict)
    reason: str = ""


@dataclass(frozen=True)
class Policy:
    """An ordered rule set with a default decision."""

    rules: tuple[Rule, ...]
    default_decision: Decision = Decision.ALLOW
    version: int = 1

    @classmethod
    def load(cls, path: str | Path) -> Policy:
        """Load and validate a policy from a YAML file."""
        path = Path(path)
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        if raw is None:
            raise ValueError("Policy file is empty.")
        if not isinstance(raw, dict):
            raise ValueError("Policy file must contain a mapping.")

        unknown = set(raw) - _ALLOWED_POLICY_KEYS
        if unknown:
            raise ValueError(f"Unknown policy keys: {sorted(unknown)}.")

        if "default_decision" not in raw:
            raise ValueError("Policy must set 'default_decision'.")
        default_raw = str(raw["default_decision"]).lower()
        try:
            default_decision = Decision(default_raw)
        except ValueError as exc:
            raise ValueError(f"Unknown default_decision: {default_raw!r}") from exc

        version = raw.get("version", 1)
        if isinstance(version, bool) or not isinstance(version, int) or version != 1:
            raise ValueError(f"Unsupported policy version: {version!r}.")

        if "rules" not in raw:
            raise ValueError("Policy must define 'rules'.")
        rules_raw = raw["rules"]
        if not isinstance(rules_raw, list):
            raise ValueError("'rules' must be a list.")

        rules: list[Rule] = []
        names: set[str] = set()
        for item in rules_raw:
            if not isinstance(item, dict):
                raise ValueError("Each rule must be a mapping.")
            if "name" not in item or "decision" not in item:
                raise ValueError("Each rule needs a 'name' and a 'decision'.")

            unknown = set(item) - _ALLOWED_RULE_KEYS
            if unknown:
                raise ValueError(f"Unknown keys in rule {item['name']!r}: {sorted(unknown)}.")

            name = item["name"]
            if not isinstance(name, str) or not name.strip():
                raise ValueError("Rule names must be non-empty strings.")
            if name in names:
                raise ValueError(f"Duplicate rule name: {name!r}.")
            names.add(name)

            decision_raw = str(item["decision"]).lower()
            try:
                decision = Decision(decision_raw)
            except ValueError as exc:
                raise ValueError(
                    f"Unknown decision in rule {name!r}: {item['decision']!r}"
                ) from exc

            tool = item.get("tool")
            if tool is not None and not isinstance(tool, str):
                raise ValueError(f"'tool' must be a string in rule {name!r}.")

            when = item.get("when", {})
            if not isinstance(when, dict):
                raise ValueError(f"'when' must be a mapping in rule {name!r}.")
            _validate_when(when, name)

            reason = item.get("reason", "")
            if not isinstance(reason, str):
                raise ValueError(f"'reason' must be a string in rule {name!r}.")

            rules.append(
                Rule(
                    name=name,
                    decision=decision,
                    tool=tool,
                    when=when,
                    reason=reason,
                )
            )

        return cls(
            rules=tuple(rules),
            default_decision=default_decision,
            version=version,
        )

    def evaluate(self, action: Action) -> PolicyResult:
        """Return the first matching rule, or the default decision."""
        for rule in self.rules:
            if rule.tool is not None and rule.tool != action.tool:
                continue
            if all(_matches(action, path, condition) for path, condition in rule.when.items()):
                return PolicyResult(
                    decision=rule.decision,
                    rule=rule.name,
                    reason=rule.reason,
                )
        return PolicyResult(
            decision=self.default_decision,
            rule=None,
            reason="No rule matched.",
        )


def _validate_when(when: dict[str, Any], rule_name: str) -> None:
    """Reject unknown paths and operators at load time, not at decision time."""
    for path, condition in when.items():
        if not isinstance(path, str) or not path:
            raise ValueError(f"Invalid condition path in rule {rule_name!r}.")

        parts = path.split(".")
        if any(not part for part in parts):
            raise ValueError(f"Invalid condition path {path!r} in rule {rule_name!r}.")

        root = parts[0]
        if root in _SCALAR_ROOTS:
            if len(parts) != 1:
                raise ValueError(
                    f"Condition path {path!r} must name a scalar in rule {rule_name!r}."
                )
        elif root in _MAPPING_ROOTS:
            if len(parts) < 2:
                raise ValueError(f"Condition path {path!r} must name a key in rule {rule_name!r}.")
        else:
            raise ValueError(f"Unknown condition root {root!r} in rule {rule_name!r}.")

        if not isinstance(condition, dict):
            continue
        if not condition:
            raise ValueError(f"Empty condition for {path!r} in rule {rule_name!r}.")

        unknown = set(condition) - _OPERATORS
        if unknown:
            raise ValueError(f"Unknown operators {sorted(unknown)} in rule {rule_name!r}.")

        for operator, expected in condition.items():
            if operator in {"exists", "path_escape"} and not isinstance(expected, bool):
                raise ValueError(f"'{operator}' expects a boolean in rule {rule_name!r}.")
            if operator in {"in", "not_in"} and not isinstance(expected, (list, tuple, str)):
                raise ValueError(f"'{operator}' expects a list or string in rule {rule_name!r}.")
            if operator in {
                "path_prefix",
                "not_path_prefix",
                "domain",
                "not_domain",
            } and not isinstance(expected, str):
                raise ValueError(f"'{operator}' expects a string in rule {rule_name!r}.")
            if operator in {"gt", "gte", "lt", "lte"} and (
                isinstance(expected, bool) or not isinstance(expected, (int, float))
            ):
                raise ValueError(f"'{operator}' expects a number in rule {rule_name!r}.")


def _value(action: Action, path: str) -> Any:
    """Read a dotted path from an action."""
    parts = path.split(".")
    if not parts or not parts[0]:
        return None

    root = parts[0]
    if root == "args":
        value: Any = action.args
        parts = parts[1:]
    elif root == "context":
        value = action.context
        parts = parts[1:]
    else:
        value = getattr(action, root, None)
        parts = parts[1:]

    for part in parts:
        if isinstance(value, dict):
            value = value.get(part)
        else:
            value = getattr(value, part, None)
    return value


def _matches(action: Action, path: str, condition: Any) -> bool:
    """Evaluate one condition against one action field."""
    value = _value(action, path)
    if isinstance(condition, dict):
        return all(_apply(value, operator, expected) for operator, expected in condition.items())
    return value == condition


def _apply(value: Any, operator: str, expected: Any) -> bool:
    """Apply one policy operator."""
    if operator == "exists":
        return (value is not None) == bool(expected)

    if value is None:
        return False

    if operator in {"eq", "equals"}:
        return value == expected
    if operator in {"neq", "not_equals"}:
        return value != expected
    if operator == "gt":
        return _number(value) > _number(expected)
    if operator == "gte":
        return _number(value) >= _number(expected)
    if operator == "lt":
        return _number(value) < _number(expected)
    if operator == "lte":
        return _number(value) <= _number(expected)
    if operator == "in":
        try:
            return value in expected
        except TypeError:
            return False
    if operator == "not_in":
        try:
            return value not in expected
        except TypeError:
            return False
    if operator == "contains":
        return _contains(value, expected)
    if operator == "not_contains":
        return not _contains(value, expected)
    if operator in {"domain", "not_domain"}:
        matched = _all_domains_match(value, expected)
        return matched if operator == "domain" else not matched
    if operator == "path_prefix":
        return _path_prefix(value, expected)
    if operator == "not_path_prefix":
        return not _path_prefix(value, expected)
    if operator == "path_escape":
        return _path_escapes(value) == bool(expected)

    raise ValueError(f"Unknown policy operator: {operator!r}")


def _contains(value: Any, expected: Any) -> bool:
    try:
        return expected in value
    except TypeError:
        return False


def _number(value: Any) -> float:
    if isinstance(value, bool):
        raise ValueError(f"Expected a number, got {value!r}.")
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Expected a number, got {value!r}.") from exc
    if not math.isfinite(number):
        raise ValueError(f"Expected a finite number, got {value!r}.")
    return number


def _all_domains_match(value: Any, expected: Any) -> bool:
    """Match only when every address or URL in the value is in the domain."""
    domains = _domains(value)
    if not domains:
        return False
    target = str(expected).strip().lower().lstrip("@").rstrip(".")
    return all(domain == target or domain.endswith("." + target) for domain in domains)


def _domains(value: Any) -> list[str]:
    """Split a recipient or URL field into every domain it names."""
    text = str(value).strip()
    if not text:
        return []

    bracketed = re.findall(r"<([^>]+)>", text)
    parts = bracketed or [part for part in _ADDRESS_SEPARATORS.split(text) if part]
    domains: list[str] = []
    for part in parts:
        domain = _domain(part)
        if domain:
            domains.append(domain)
    return domains


def _domain(value: Any) -> str:
    """Extract a host or email domain from one address or URL."""
    text = str(value).strip().lower()
    if not text:
        return ""
    if "@" in text and "://" not in text:
        return text.rsplit("@", 1)[1].strip().rstrip(".")
    try:
        parsed = urlparse(text if "://" in text else f"//{text}")
    except ValueError:
        return ""
    return (parsed.hostname or "").rstrip(".")


def _path_prefix(value: Any, expected: Any) -> bool:
    """Match a normalised path prefix on a segment boundary."""
    raw_value = str(value).strip()
    raw_prefix = str(expected).strip()
    if not raw_value or not raw_prefix:
        return False

    candidate = posixpath.normpath(raw_value.replace("\\", "/"))
    prefix = posixpath.normpath(raw_prefix.replace("\\", "/").rstrip("/"))
    return candidate == prefix or candidate.startswith(prefix + "/")


def _path_escapes(value: Any) -> bool:
    """Return True for absolute paths, traversal and other escapes."""
    text = str(value).strip()
    if not text or "\x00" in text:
        return True
    if text.startswith("~"):
        return True
    if _WINDOWS_DRIVE.match(text):
        return True

    path = PurePosixPath(text.replace("\\", "/"))
    if path.is_absolute():
        return True
    return ".." in path.parts
