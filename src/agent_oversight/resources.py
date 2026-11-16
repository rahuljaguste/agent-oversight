"""Locate packaged and repository resources."""

from __future__ import annotations

from importlib import resources
from pathlib import Path


def default_policy_path() -> Path:
    """Return the default policy from the repository or the installed package."""
    repository = Path(__file__).resolve().parents[2] / "policies" / "default.yml"
    if repository.is_file():
        return repository

    resource = resources.files("agent_oversight").joinpath("policies/default.yml")
    if resource.is_file():
        return Path(str(resource))

    raise FileNotFoundError(
        "Could not find policies/default.yml in the repository or the installed package."
    )
