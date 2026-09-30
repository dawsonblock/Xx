import json
from pathlib import Path

from aide.rsi.world import world_from_journal_json


def test_dependency_light_journal_loader(tmp_path: Path):
    raw = {
        "metric_maximize": True,
        "nodes": [
            {
                "id": "n0",
                "step": 0,
                "plan": "draft",
                "analysis": "ok",
                "metric": {"value": 1.0, "maximize": True, "is_worst": False},
                "is_buggy": False,
            },
            {
                "id": "n1",
                "step": 1,
                "plan": "improve",
                "analysis": "better",
                "metric": {"value": 1.2, "maximize": True, "is_worst": False},
                "is_buggy": False,
            },
        ],
        "node2parent": {"n1": "n0"},
    }
    p = tmp_path / "journal.json"
    p.write_text(json.dumps(raw))
    w = world_from_journal_json(p)
    assert w.nodes["n1"].parent_id == "n0"
    assert w.nodes["n1"].depth == 2
    assert w.best_recorded_score() == 1.2
