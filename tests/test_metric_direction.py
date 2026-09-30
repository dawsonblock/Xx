"""Tests for task-level metric direction handling.

Follow-up to #91 / #92: the journal direction should come from the task
(config override or task-description inference) rather than be latched from
the first node's per-node verdict, and the originally-reported per-node
directions should be preserved in journal.json.
"""

import json
import logging

from omegaconf import OmegaConf

import aide.agent as agent_module
from aide.agent import TaskMetric, add_task_metric, determine_task_metric
from aide.journal import Journal, Node
from aide.utils import serialize
from aide.utils.config import AgentConfig
from aide.utils.metric import MetricValue


def _node(value, maximize):
    return Node(
        code="",
        metric=MetricValue(value, maximize=maximize),
        is_buggy=False,
    )


def _acfg(metric_maximize=None):
    return OmegaConf.create(
        {
            "metric_maximize": metric_maximize,
            "feedback": {"model": "test-model", "temp": 0.5},
        }
    )


def test_task_level_direction_wins_over_conflicting_first_node_verdict():
    journal = Journal(metric_maximize=False)
    journal.append(_node(0.9, maximize=True))
    journal.append(_node(0.2, maximize=False))

    assert journal.metric_maximize is False
    assert [node.metric.maximize for node in journal.nodes] == [True, False]
    assert journal.get_best_node().metric.value == 0.2


def test_none_direction_is_ranked_without_warning(caplog):
    journal = Journal(metric_maximize=True)
    with caplog.at_level(logging.WARNING, logger="aide"):
        journal.append(_node(0.5, maximize=None))

    assert "disagrees with journal direction" not in caplog.text
    assert journal.nodes[0].metric.maximize is None
    assert journal.get_best_node() is journal.nodes[0]


def test_reported_direction_persisted_in_journal_json(tmp_path):
    journal = Journal(metric_maximize=True)
    journal.append(_node(0.9, maximize=True))
    journal.append(_node(0.85, maximize=False))

    path = tmp_path / "journal.json"
    serialize.dump_json(journal, path)
    data = json.loads(path.read_text())

    assert data["metric_maximize"] is True
    metrics = [node["metric"] for node in data["nodes"]]
    assert [metric["maximize"] for metric in metrics] == [True, False]
    assert all("reported_maximize" not in metric for metric in metrics)


def test_none_direction_survives_journal_round_trip():
    journal = Journal(metric_maximize=True)
    journal.append(_node(0.5, maximize=None))

    loaded = serialize.loads_json(serialize.dumps_json(journal), Journal)

    assert loaded.metric_maximize is True
    assert loaded.nodes[0].metric.maximize is None
    assert loaded.get_best_node() is loaded.nodes[0]


def test_config_override_skips_llm_call(monkeypatch):
    def fail_query(*args, **kwargs):
        raise AssertionError("query must not be called when the override is set")

    monkeypatch.setattr(agent_module, "query", fail_query)

    minimize = determine_task_metric("some task", _acfg(False))
    maximize = determine_task_metric("some task", _acfg(True))

    assert minimize == TaskMetric(None, False)
    assert maximize == TaskMetric(None, True)
    assert "minimize" in add_task_metric("some task", minimize)
    assert "maximize" in add_task_metric("some task", maximize)


def test_metric_and_direction_inferred_from_task_description(monkeypatch):
    captured = {}

    def fake_query(**kwargs):
        captured.update(kwargs)
        return {"metric_name": "RMSE", "lower_is_better": True}

    monkeypatch.setattr(agent_module, "query", fake_query)

    task_metric = determine_task_metric("Predict house prices; report RMSE.", _acfg())

    assert task_metric == TaskMetric("RMSE", False)
    assert captured["func_spec"].name == "submit_task_metric"
    augmented = add_task_metric({"Task": "Predict house prices."}, task_metric)
    assert "RMSE" in augmented["Task evaluation"]
    assert "minimize" in augmented["Task evaluation"]


def test_inferred_metric_is_used_by_later_solutions(monkeypatch):
    def fake_query(**kwargs):
        return {"metric_name": "log loss", "lower_is_better": True}

    monkeypatch.setattr(agent_module, "query", fake_query)

    task_metric = determine_task_metric("Solve a classification task.", _acfg())
    task_desc = add_task_metric("Solve a classification task.", task_metric)
    journal = Journal(metric_maximize=task_metric.maximize)
    journal.append(_node(0.5, maximize=False))
    journal.append(_node(0.2, maximize=False))

    assert "log loss" in task_desc
    assert "minimize" in task_desc
    assert journal.get_best_node().metric.value == 0.2


def test_old_agent_config_defaults_metric_override_to_none():
    old_config = OmegaConf.load("aide/utils/config.yaml").agent
    del old_config.metric_maximize

    merged = OmegaConf.merge(OmegaConf.structured(AgentConfig), old_config)

    assert merged.metric_maximize is None


def test_inference_failure_falls_back_to_none(monkeypatch):
    def fake_query(**kwargs):
        raise RuntimeError("backend unavailable")

    monkeypatch.setattr(agent_module, "query", fake_query)

    assert determine_task_metric("some task", _acfg()) is None
