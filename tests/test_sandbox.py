from __future__ import annotations

import os

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


def test_non_string_path_is_rejected(tmp_path):
    with pytest.raises(ValueError):
        Sandbox(tmp_path).read_text(["/etc/passwd"])


def test_symlink_escape_is_rejected(tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("secret", encoding="utf-8")
    root = tmp_path / "root"
    root.mkdir()
    (root / "link").symlink_to(outside)

    with pytest.raises(ValueError):
        Sandbox(root).read_text("link")


def test_symlink_inside_root_is_allowed(tmp_path):
    target = tmp_path / "target.txt"
    target.write_text("hello", encoding="utf-8")
    (tmp_path / "link").symlink_to(target)

    assert Sandbox(tmp_path).read_text("link") == "hello"


def test_hardlink_escape_is_rejected(tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("secret", encoding="utf-8")
    root = tmp_path / "root"
    root.mkdir()
    try:
        os.link(outside, root / "link")
    except OSError as exc:
        pytest.skip(f"hardlinks are unavailable: {exc}")

    with pytest.raises(ValueError):
        Sandbox(root).read_text("link")
