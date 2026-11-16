from __future__ import annotations

from agent_oversight.resources import default_policy_path


def test_default_policy_path_is_a_real_file():
    path = default_policy_path()
    assert path.is_file()
    assert path.name == "default.yml"
