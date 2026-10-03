"""A changed source, authority file, or lock makes generated identity stale."""

from __future__ import annotations

import pytest

from tools import generate_release_manifests as manifests


@pytest.fixture
def isolated_tree(tmp_path, monkeypatch):
    files = {
        "VERSION": "1.3.5\n",
        "README.md": "original source\n",
        "aide/rsi/sandbox.py": "sandbox original\n",
        ".github/workflows/python-publish.yml": "publish original\n",
        "Dockerfile": "FROM original\n",
        "requirements-rsi-ci.lock": "locked original\n",
    }
    for relative, content in files.items():
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
    monkeypatch.setattr(manifests, "ROOT", tmp_path)
    monkeypatch.setattr(
        manifests,
        "_current_statistical_protocol",
        lambda: ("test-protocol", "a" * 64),
    )
    assert manifests.main([]) == 0
    assert manifests.main(["--check"]) == 0
    return tmp_path


@pytest.mark.parametrize(
    "relative",
    [
        "README.md",
        "aide/rsi/sandbox.py",
        "requirements-rsi-ci.lock",
        ".github/workflows/python-publish.yml",
        "Dockerfile",
    ],
)
def test_change_invalidates_then_regeneration_matches(isolated_tree, relative):
    target = isolated_tree / relative
    target.write_text(target.read_text() + "changed\n")
    assert manifests.main(["--check"]) == 1
    assert manifests.main([]) == 0
    assert manifests.main(["--check"]) == 0
