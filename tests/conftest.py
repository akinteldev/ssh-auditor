"""Shared pytest fixtures for ssh-auditor tests."""

from __future__ import annotations

import pathlib
import pytest


@pytest.fixture()
def fixtures_dir() -> pathlib.Path:
    """Path to the tests/fixtures directory."""
    return pathlib.Path(__file__).parent / "fixtures"


@pytest.fixture()
def good_config_path(fixtures_dir: pathlib.Path) -> str:
    return str(fixtures_dir / "sshd_config_good.conf")


@pytest.fixture()
def bad_config_path(fixtures_dir: pathlib.Path) -> str:
    return str(fixtures_dir / "sshd_config_bad.conf")


@pytest.fixture()
def mixed_config_path(fixtures_dir: pathlib.Path) -> str:
    return str(fixtures_dir / "sshd_config_mixed.conf")
