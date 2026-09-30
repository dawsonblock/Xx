import json
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from aide.agent import Agent
from aide.execution_types import ExecutionResult
from aide.journal import Node
from aide.rsi.artifacts import store_candidate
from aide.rsi.canary import RealCanaryGate
from aide.rsi.evidence import has_trusted_evaluation
from aide.rsi.trusted_evaluator import (
    TrustedEvaluator,
    TrustedEvaluatorError,
    _stable_digest,
    file_sha256,
    tree_sha256,
)
from aide.utils.metric import WorstMetricValue

TEST_KEY = "test-only-hmac-key-with-at-least-32-bytes"


def _write_evaluator_bundle(
    bundle: Path,
    *,
    exit_code: int = 0,
    forge_predictions: bool = False,
    flood_output: bool = False,
    spawn_grandchild: bool = False,
    grandchild_marker: Path | None = None,
) -> None:
    bundle.mkdir()
    grandchild_path = json.dumps(str(grandchild_marker or ""))
    script = f"""import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from helper import VALUE

parser = argparse.ArgumentParser()
parser.add_argument("--request", required=True)
parser.add_argument("--response", required=True)
args = parser.parse_args()
if "AIDE_RSI_EVALUATION_HMAC_KEY" in os.environ:
    raise SystemExit(9)
if not sys.dont_write_bytecode or os.environ.get("PYTHONDONTWRITEBYTECODE") != "1":
    raise SystemExit(11)
request = json.loads(Path(args.request).read_text())
if Path(request["candidate_path"]).read_text() == "":
    raise SystemExit(10)
if {flood_output}:
    import time
    with (Path(request["output_dir"]) / "flood.bin").open("wb") as flood:
        for _ in range(100):
            flood.write(b"x" * (128 * 1024))
            flood.flush()
            time.sleep(0.02)
if {spawn_grandchild}:
    code = "import time; from pathlib import Path; time.sleep(0.3); Path(" + {grandchild_path} + ").write_text('survived')"
    subprocess.Popen([sys.executable, "-c", code])
result = {{key: request[key] for key in (
    "candidate_sha256", "task_sha256", "evaluator_sha256",
    "evaluator_config_sha256", "dataset_sha256", "split_sha256",
    "environment_sha256", "metric_id", "metric_maximize",
)}}
predictions_path = Path(request["output_dir"]) / "predictions.jsonl"
predictions_path.write_text("{{}}\\n")
predictions_sha256 = (
    "a" * 64 if {forge_predictions} else
    hashlib.sha256(predictions_path.read_bytes()).hexdigest()
)
result.update(schema_version=1, score=VALUE, predictions_sha256=predictions_sha256)
Path(args.response).write_text(json.dumps(result))
raise SystemExit({exit_code})
"""
    (bundle / "evaluate.py").write_text(script)
    (bundle / "helper.py").write_text("VALUE = 0.875\n")


def _make_evaluator(
    tmp_path: Path,
    monkeypatch,
    *,
    exit_code: int = 0,
    forge_predictions: bool = False,
    flood_output: bool = False,
    spawn_grandchild: bool = False,
):
    monkeypatch.setenv("AIDE_RSI_EVALUATION_HMAC_KEY", TEST_KEY)
    bundle = tmp_path / "evaluator"
    _write_evaluator_bundle(
        bundle,
        exit_code=exit_code,
        forge_predictions=forge_predictions,
        flood_output=flood_output,
        spawn_grandchild=spawn_grandchild,
        grandchild_marker=tmp_path / "grandchild-survived",
    )
    for path in bundle.iterdir():
        path.chmod(0o444)
    bundle.chmod(0o555)
    config_path = tmp_path / "task-config.json"
    config_path.write_text('{"metric":"accuracy"}\n')
    dataset = tmp_path / "hidden-data"
    dataset.mkdir()
    labels = dataset / "labels.csv"
    labels.write_text("label\n1\n0\n")
    labels.chmod(0o444)
    dataset.chmod(0o555)
    split = tmp_path / "split.json"
    split.write_text('{"partition":"qualification-v1"}\n')
    environment_manifest = tmp_path / "requirements.lock"
    environment_manifest.write_text("numpy==2.0.0\n")
    config = SimpleNamespace(
        enabled=True,
        bundle_dir=str(bundle),
        bundle_sha256=tree_sha256(bundle),
        entrypoint="evaluate.py",
        config_path=str(config_path),
        config_sha256=file_sha256(config_path),
        dataset_dir=str(dataset),
        dataset_sha256=tree_sha256(dataset),
        split_manifest=str(split),
        split_sha256=file_sha256(split),
        environment_manifest=str(environment_manifest),
        environment_manifest_sha256=file_sha256(environment_manifest),
        metric_id="accuracy",
        metric_maximize=True,
        timeout_s=10,
        max_output_mb=1,
    )
    artifacts = tmp_path / "artifacts"
    evaluator = TrustedEvaluator(
        config, task_description={"Task goal": "test"}, artifact_root=artifacts
    )
    candidate = "print('candidate')\n"
    candidate_sha256 = store_candidate(candidate, artifacts)
    return evaluator, candidate_sha256, config


def test_pinned_evaluator_runs_without_host_attestation_key_and_signs_record(
    tmp_path: Path, monkeypatch
):
    evaluator, candidate_sha256, _ = _make_evaluator(tmp_path, monkeypatch)
    node = Node(
        code="print('candidate')\n",
        rsi_provenance={
            "candidate_sha256": candidate_sha256,
            "evaluation_authority": "feedback_model_interpreted_candidate_output",
        },
    )
    agent = object.__new__(Agent)

    agent.evaluate_generated_node(
        node,
        lambda code, reset: ExecutionResult(["candidate ran"], 0.1, None),
        trusted_evaluator=evaluator,
        candidate_sha256=candidate_sha256,
    )

    assert node.metric.value == pytest.approx(0.875)
    assert node.metric.maximize is True
    assert node.is_buggy is False
    assert node.rsi_provenance["evaluation_authority"] == "trusted_external"
    assert node.rsi_provenance["task_sha256"] == evaluator.task_sha256
    assert has_trusted_evaluation(node, maximize=True)
    assert not (evaluator.bundle_dir / "__pycache__").exists()
    prediction_artifact = (
        evaluator.artifact_root
        / "predictions"
        / "sha256"
        / node.rsi_provenance["predictions_sha256"][:2]
        / f'{node.rsi_provenance["predictions_sha256"]}.jsonl'
    )
    record_digest = node.rsi_provenance["evaluation_record_sha256"]
    record_artifact = (
        evaluator.artifact_root
        / "evaluations"
        / "sha256"
        / record_digest[:2]
        / f"{record_digest}.json"
    )
    assert prediction_artifact.read_text() == "{}\n"
    record = json.loads(record_artifact.read_text())
    assert record["score"] == pytest.approx(0.875)
    assert record["provenance"]["attestation_hmac_sha256"]
    journal = SimpleNamespace(metric_maximize=True, nodes=[node])
    assert RealCanaryGate().evaluate_pair(journal, journal).passed


def test_pinned_evaluator_failure_does_not_fall_back_to_feedback_metric(
    tmp_path: Path, monkeypatch
):
    evaluator, candidate_sha256, _ = _make_evaluator(tmp_path, monkeypatch, exit_code=5)
    node = Node(code="print('candidate')\n")
    agent = object.__new__(Agent)

    agent.evaluate_generated_node(
        node,
        lambda code, reset: ExecutionResult(["candidate ran"], 0.1, None),
        trusted_evaluator=evaluator,
        candidate_sha256=candidate_sha256,
    )

    assert isinstance(node.metric, WorstMetricValue)
    assert node.is_buggy is True
    assert node.rsi_provenance["evaluation_authority"] == "trusted_evaluator_failed"
    assert not has_trusted_evaluation(node)


def test_forged_prediction_digest_cannot_be_attested(tmp_path: Path, monkeypatch):
    evaluator, candidate_sha256, _ = _make_evaluator(
        tmp_path, monkeypatch, forge_predictions=True
    )
    with pytest.raises(
        TrustedEvaluatorError,
        match="prediction digest does not match output",
    ):
        evaluator.evaluate(candidate_sha256)


def test_evaluator_scratch_output_is_bounded(tmp_path: Path, monkeypatch):
    evaluator, candidate_sha256, _ = _make_evaluator(
        tmp_path, monkeypatch, flood_output=True
    )
    with pytest.raises(TrustedEvaluatorError, match="scratch output limit"):
        evaluator.evaluate(candidate_sha256)


def test_evaluator_grandchildren_are_terminated(tmp_path: Path, monkeypatch):
    evaluator, candidate_sha256, _ = _make_evaluator(
        tmp_path, monkeypatch, spawn_grandchild=True
    )
    evaluator.evaluate(candidate_sha256)
    marker = tmp_path / "grandchild-survived"
    deadline = time.monotonic() + 1
    while time.monotonic() < deadline and not marker.exists():
        time.sleep(0.02)
    assert not marker.exists()


def test_trusted_evaluator_requires_read_only_hidden_data(tmp_path: Path, monkeypatch):
    evaluator, _, config = _make_evaluator(tmp_path, monkeypatch)
    dataset = Path(config.dataset_dir)
    labels = dataset / "labels.csv"
    labels.chmod(0o644)
    dataset.chmod(0o755)

    try:
        with pytest.raises(TrustedEvaluatorError, match="read-only tree"):
            TrustedEvaluator(
                config,
                task_description={"Task goal": "test"},
                artifact_root=evaluator.artifact_root,
            )
    finally:
        labels.chmod(0o444)
        dataset.chmod(0o555)


def test_trusted_evaluator_requires_read_only_bundle(tmp_path: Path, monkeypatch):
    evaluator, _, config = _make_evaluator(tmp_path, monkeypatch)
    (evaluator.bundle_dir / "helper.py").chmod(0o644)

    with pytest.raises(
        TrustedEvaluatorError, match="evaluator bundle must be a read-only tree"
    ):
        TrustedEvaluator(
            config,
            task_description={"Task goal": "test"},
            artifact_root=evaluator.artifact_root,
        )


def test_evaluator_identity_binds_task_description_and_pinned_inputs(
    tmp_path: Path, monkeypatch
):
    evaluator, _, _ = _make_evaluator(tmp_path, monkeypatch)
    assert evaluator.task_sha256 == _stable_digest({"Task goal": "test"})
    assert evaluator.identity == _stable_digest(evaluator._identity_fields())


def test_evaluator_identity_binds_resource_limits(tmp_path: Path, monkeypatch):
    evaluator, _, config = _make_evaluator(tmp_path, monkeypatch)
    config.max_output_mb += 1
    changed = TrustedEvaluator(
        config,
        task_description={"Task goal": "test"},
        artifact_root=evaluator.artifact_root,
    )
    assert changed.identity != evaluator.identity
