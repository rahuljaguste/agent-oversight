"""A small YAML policy engine for tool-call review."""

from __future__ import annotations

import math
import posixpath
import re
from collections.abc import Hashable
from dataclasses import dataclass, field
from email.utils import getaddresses
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlparse

import yaml
from yaml.constructor import ConstructorError

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
_URL_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
_BARE_DOMAIN = re.compile(r"^[A-Za-z0-9.-]+$")
_WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:[\\/]")
_TOKEN_SPLIT = re.compile(r"[,;\s]+")


class _StrictSafeLoader(yaml.SafeLoader):
    """SafeLoader that rejects duplicate mapping keys instead of keeping the last."""

    def construct_mapping(self, node, deep=False):  # type: ignore[no-untyped-def]
        if isinstance(node, yaml.MappingNode):
            self.flatten_mapping(node)

        mapping = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, Hashable):
                raise ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    "found an unhashable key",
                    key_node.start_mark,
                )
            if key in mapping:
                raise ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    f"found duplicate key {key!r}",
                    key_node.start_mark,
                )
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


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
        try:
            raw = yaml.load(path.read_text(encoding="utf-8"), Loader=_StrictSafeLoader)
        except yaml.YAMLError as exc:
            raise ValueError(f"Invalid policy YAML: {exc}") from exc

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

            name_raw = item["name"]
            if not isinstance(name_raw, str) or not name_raw.strip():
                raise ValueError("Rule names must be non-empty strings.")
            name = name_raw.strip()
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

            tool: str | None = None
            if "tool" in item:
                tool_raw = item["tool"]
                if not isinstance(tool_raw, str) or not tool_raw.strip():
                    raise ValueError(f"'tool' must be a non-empty string in rule {name!r}.")
                tool = tool_raw.strip()

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
    """Reject unknown paths, operators and value types at load time."""
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

        if condition is None:
            raise ValueError(
                f"Condition {path!r} is null in rule {rule_name!r}; use 'exists: false'."
            )

        if not isinstance(condition, dict):
            _validate_scalar(root, condition, path, rule_name)
            continue
        if not condition:
            raise ValueError(f"Empty condition for {path!r} in rule {rule_name!r}.")

        unknown = set(condition) - _OPERATORS
        if unknown:
            raise ValueError(f"Unknown operators {sorted(unknown)} in rule {rule_name!r}.")

        for operator, expected in condition.items():
            _validate_operator(root, operator, expected, path, rule_name)


def _validate_scalar(root: str, expected: Any, path: str, rule_name: str) -> None:
    if isinstance(expected, (dict, list, tuple)):
        raise ValueError(f"Condition {path!r} must be a scalar in rule {rule_name!r}.")
    if isinstance(expected, float) and not math.isfinite(expected):
        raise ValueError(f"Condition {path!r} must be finite in rule {rule_name!r}.")
    if root == "reversible" and not isinstance(expected, bool):
        raise ValueError(f"'reversible' expects a boolean in rule {rule_name!r}.")
    if root in {"impact", "user", "tool"} and not isinstance(expected, str):
        raise ValueError(f"{path!r} expects a string in rule {rule_name!r}.")


def _validate_operator(root: str, operator: str, expected: Any, path: str, rule_name: str) -> None:
    if operator in {"exists", "path_escape"} and not isinstance(expected, bool):
        raise ValueError(f"'{operator}' expects a boolean in rule {rule_name!r}.")

    if operator in {"eq", "equals", "neq", "not_equals"}:
        _validate_scalar(root, expected, path, rule_name)

    if operator in {"in", "not_in"} and not isinstance(expected, (list, tuple)):
        raise ValueError(f"'{operator}' expects a list in rule {rule_name!r}.")

    if operator in {"contains", "not_contains"} and isinstance(expected, (dict, type(None))):
        raise ValueError(f"'{operator}' expects a string or a list in rule {rule_name!r}.")

    if operator in {"path_prefix", "not_path_prefix", "domain", "not_domain"}:
        if not isinstance(expected, str) or not expected.strip():
            raise ValueError(f"'{operator}' expects a non-empty string in rule {rule_name!r}.")

    if operator in {"gt", "gte", "lt", "lte"}:
        if isinstance(expected, bool) or not isinstance(expected, (int, float)):
            raise ValueError(f"'{operator}' expects a number in rule {rule_name!r}.")
        if not math.isfinite(float(expected)):
            raise ValueError(f"'{operator}' expects a finite number in rule {rule_name!r}.")


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
    if condition is None:
        return False

    value = _value(action, path)
    if isinstance(condition, dict):
        return all(_apply(value, operator, expected) for operator, expected in condition.items())
    return _equals(value, condition)


def _apply(value: Any, operator: str, expected: Any) -> bool:
    """Apply one policy operator."""
    if operator == "exists":
        return (value is not None) == bool(expected)

    if value is None:
        return False

    if operator in {"eq", "equals"}:
        return _equals(value, expected)
    if operator in {"neq", "not_equals"}:
        return not _equals(value, expected)
    if operator == "gt":
        return _number(value) > _number(expected)
    if operator == "gte":
        return _number(value) >= _number(expected)
    if operator == "lt":
        return _number(value) < _number(expected)
    if operator == "lte":
        return _number(value) <= _number(expected)
    if operator in {"in", "not_in"}:
        if not isinstance(expected, (list, tuple, set, frozenset)):
            raise ValueError("'in' expects a list.")
        try:
            return value in expected if operator == "in" else value not in expected
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


def _equals(value: Any, expected: Any) -> bool:
    """Compare without Python's bool/int equivalence."""
    if isinstance(expected, bool):
        return isinstance(value, bool) and value is expected
    if isinstance(expected, (int, float)):
        return isinstance(value, (int, float)) and not isinstance(value, bool) and value == expected
    return value == expected


def _contains(value: Any, expected: Any) -> bool:
    try:
        return expected in value
    except TypeError:
        return False


def _number(value: Any) -> float:
    if isinstance(value, bool):
        raise ValueError("Expected a number.")
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("Expected a number.") from exc
    if not math.isfinite(number):
        raise ValueError("Expected a finite number.")
    return number


def _all_domains_match(value: Any, expected: Any) -> bool:
    """Match only when every address or URL in the value is in the domain."""
    domains = _domains(value)
    if not domains:
        return False
    target = str(expected).strip().lower().lstrip("@").rstrip(".")
    if not target:
        return False
    return all(domain == target or domain.endswith("." + target) for domain in domains)


def _domains(value: Any) -> list[str] | None:
    """Parse every address or URL in a field; None means ambiguous."""
    if isinstance(value, (list, tuple)):
        domains: list[str] = []
        for item in value:
            item_domains = _domains(item)
            if item_domains is None:
                return None
            domains.extend(item_domains)
        return domains

    if not isinstance(value, str):
        return None

    text = value.strip()
    if not text:
        return []

    if text.lower().startswith("mailto:"):
        return _email_domains(text[len("mailto:") :])

    if _looks_like_url(text):
        return _url_domains(text)

    return _email_domains(text)


def _email_domains(text: str) -> list[str] | None:
    try:
        parsed = getaddresses([text])
    except Exception:
        return None

    addresses = [address for _name, address in parsed if address]
    if not addresses:
        return []

    if text.count("@") > sum(1 for address in addresses if "@" in address):
        return None

    domains: list[str] = []
    for address in addresses:
        domain = _address_domain(address)
        if domain is None:
            return None
        domains.append(domain)
    return domains


def _address_domain(address: str) -> str | None:
    address = address.strip().lower()
    if not address:
        return None
    if "@" in address:
        domain = address.rsplit("@", 1)[1].strip().rstrip(".")
        return domain or None
    if _BARE_DOMAIN.fullmatch(address) and "." in address:
        return address.rstrip(".")
    return None


def _looks_like_url(text: str) -> bool:
    lowered = text.strip().lower()
    return "://" in lowered or lowered.startswith("//") or bool(_URL_SCHEME.match(lowered))


def _url_domains(text: str) -> list[str] | None:
    if "\\" in text:
        return None

    domains: list[str] = []
    for token in (part for part in _TOKEN_SPLIT.split(text) if part):
        try:
            parsed = urlparse(token)
        except ValueError:
            return None
        if not parsed.scheme and not token.startswith("//"):
            return None
        host = parsed.hostname
        if not host:
            return None
        domains.append(host.lower().rstrip("."))
    return domains


def _domain(value: Any) -> str:
    """Extract a single domain, or return an empty string when ambiguous."""
    domains = _domains(value)
    if not domains or len(domains) != 1:
        return ""
    return domains[0]


def _path_prefix(value: Any, expected: Any) -> bool:
    """Match a normalised path prefix on a segment boundary."""
    if not isinstance(value, str) or not isinstance(expected, str):
        return False

    raw_value = value.strip()
    raw_prefix = expected.strip()
    if not raw_value or not raw_prefix:
        return False

    candidate = posixpath.normpath(raw_value.replace("\\", "/"))
    prefix = posixpath.normpath(raw_prefix.replace("\\", "/").rstrip("/"))
    return candidate == prefix or candidate.startswith(prefix + "/")


def _path_escapes(value: Any) -> bool:
    """Return True for non-strings, absolute paths, traversal and other escapes."""
    if not isinstance(value, str):
        return True

    text = value.strip()
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
