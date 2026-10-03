from __future__ import annotations

import pytest

from aide.version import package_version
from tools.check_version_consistency import check


def test_active_versions_derive_from_version_file():
    check()
    from pathlib import Path

    assert (
        package_version()
        == (Path(__file__).resolve().parents[1] / "VERSION").read_text().strip()
    )


def test_stale_sandbox_tag_is_rejected(tmp_path):
    (tmp_path / "aide/utils").mkdir(parents=True)
    (tmp_path / "VERSION").write_text("1.3.6\n")
    (tmp_path / "setup.py").write_text('version=Path("VERSION").read_text()')
    (tmp_path / "Makefile").write_text(
        "VERSION := $(shell cat VERSION)\n"
        "SANDBOX_IMAGE = aideml-rsi-sandbox:$(VERSION)\n"
        "docker build -t aideml-rsi-sandbox:1.3.3 .\n"
    )
    (tmp_path / "aide/utils/config.yaml").write_text("sandbox: null\n")
    with pytest.raises(ValueError, match="stale sandbox version"):
        check(tmp_path)
