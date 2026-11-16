"""A small path sandbox for mock tools."""

from __future__ import annotations

import os
from pathlib import Path


class Sandbox:
    """Resolve paths under a fixed root and refuse escapes and hardlinks."""

    def __init__(self, root: str | Path):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def resolve(self, path: str) -> Path:
        if not isinstance(path, str):
            raise ValueError("Path must be a string.")
        if "\x00" in path:
            raise ValueError("Path contains a null byte.")

        candidate = (self.root / path).resolve()
        if candidate != self.root and self.root not in candidate.parents:
            raise ValueError(f"Path escapes the sandbox: {path}")
        return candidate

    def read_text(self, path: str) -> str:
        resolved = self.resolve(path)
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(resolved, flags)
        try:
            opened = os.fstat(fd)
            if opened.st_nlink > 1:
                raise ValueError(f"Refusing a multiply-linked file: {path}")
            current = os.stat(resolved)
            if (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino):
                raise ValueError(f"Path changed while opening: {path}")
            with os.fdopen(fd, "r", encoding="utf-8") as handle:
                fd = -1
                return handle.read()
        finally:
            if fd >= 0:
                os.close(fd)
