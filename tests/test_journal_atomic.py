"""Crash behavior of the actual AIDE journal serializer."""

import json
from pathlib import Path

import pytest

from aide.journal import Journal, Node
from aide.utils import atomic, serialize


def test_interrupted_journal_save_keeps_loadable_previous_snapshot(tmp_path, monkeypatch):
    path = tmp_path / "journal.json"
    serialize.dump_json(Journal([Node(code="print('previous')")]), path)

    def interrupted_replace(source, destination):
        assert json.loads(Path(source).read_text())["nodes"][0]["code"] == "print('next')"
        raise OSError("simulated interruption")

    monkeypatch.setattr(atomic.os, "replace", interrupted_replace)
    with pytest.raises(OSError, match="simulated interruption"):
        serialize.dump_json(Journal([Node(code="print('next')")]), path)

    assert serialize.load_json(path, Journal).nodes[0].code == "print('previous')"
    assert not list(tmp_path.glob("journal.json.*.tmp"))
