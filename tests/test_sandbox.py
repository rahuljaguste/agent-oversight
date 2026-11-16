from __future__ import annotations

import pytest

from agent_oversight.sandbox import Sandbox


def test_read_inside_root(tmp_path):
    (tmp_path / "notes.txt").write_text("hello", encoding="utf-8")
    assert Sandbox(tmp_path).read_text("notes.txt") == "hello"


@pytest.mark.parametrize(
    "path",
    ["../outside.txt", "/etc/passwd", "a/../../outside.txt"],
)
def test_escape_is_rejected(tmp_path, path):
    with pytest.raises(ValueError):
        Sandbox(tmp_path).resolve(path)


def test_symlink_escape_is_rejected(tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("secret", encoding="utf-8")
    root = tmp_path / "root"
    root.mkdir()
    (root / "link").symlink_to(outside)

    with pytest.raises(ValueError):
        Sandbox(root).read_text("link")
