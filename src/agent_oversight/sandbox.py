"""A small path sandbox for mock tools."""

from __future__ import annotations

from pathlib import Path


class Sandbox:
    """Resolve relative paths under a fixed root and refuse escapes."""

    def __init__(self, root: str | Path):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def resolve(self, path: str) -> Path:
        candidate = (self.root / path).resolve()
        if candidate != self.root and self.root not in candidate.parents:
            raise ValueError(f"Path escapes the sandbox: {path}")
        return candidate

    def read_text(self, path: str) -> str:
        return self.resolve(path).read_text(encoding="utf-8")
