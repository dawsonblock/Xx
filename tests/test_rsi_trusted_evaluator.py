import json
import os
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from aide.execution_types import ExecutionResult
from aide.journal import Node
from aide.rsi.artifacts import store_candidate
from aide.rsi.canary import RealCanaryGate
from aide.rsi.evidence import has_trusted_evaluation
from aide.rsi.reference_evaluator import (
    ReferenceEvaluatorError,
    sample_content_sha256,
    sample_identity_records,
    sample_identity_sha256,
)
from aide.rsi.runner import (
    _build_canary_panel,
    _stored_evaluator_identity,
    _validate_trusted_evaluator_roles,
)
from aide.rsi.trusted_evaluator import (
    REFERENCE_EVALUATOR_ENTRYPOINT,
    TrustedEvaluator,
    TrustedEvaluatorError,
    _effective_resource_limit,
    _kill_process_group,
    _stable_digest,
    canonical_evaluation_sample_ids,
    evaluation_sample_overlap,
    file_sha256,
    tree_sha256,
)
from aide.utils.metric import WorstMetricValue

TEST_KEY = "test-only-hmac-key-with-at-least-32-bytes"


def test_outer_cleanup_kills_registered_nested_candidate_group(tmp_path: Path):
    parent = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        start_new_session=True,
    )
    child = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        start_new_session=True,
    )
    registry = tmp_path / "candidate-process-groups.json"
    registry.write_text(json.dumps([child.pid]))
    _kill_process_group(parent, additional_process_groups_path=registry)
    assert parent.poll() is not None
    assert not registry.exists()
    assert child.wait(timeout=2) is not None


def _write_evaluator_bundle(
    bundle: Path,
    *,
    exit_code: int = 0,
    forge_predictions: bool = False,
    flood_output: bool = False,
    spawn_grandchild: bool = False,
    grandchild_marker: Path | None = None,
    tamper_candidate: bool = False,
    probe_outside_path: Path | None = None,
    probe_network_port: int | None = None,
) -> None:
    bundle.mkdir()
    grandchild_path = json.dumps(str(grandchild_marker or ""))
    probe_path = json.dumps(str(probe_outside_path or ""))
    network_port = probe_network_port or 0
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
if {tamper_candidate}:
    Path(request["candidate_path"]).chmod(0o644)
    Path(request["candidate_path"]).write_text("tampered candidate\\n")
score = VALUE
if {probe_path}:
    try:
        Path({probe_path}).read_text()
    except OSError:
        pass
    else:
        score = 0.0
if {network_port}:
    import socket
    try:
        with socket.create_connection(("127.0.0.1", {network_port}), timeout=0.25):
            score = 0.0
    except OSError:
        pass
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
result.update(schema_version=1, score=score, predictions_sha256=predictions_sha256)
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
    tamper_candidate: bool = False,
    probe_outside_path: Path | None = None,
    probe_network_port: int | None = None,
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
        tamper_candidate=tamper_candidate,
        probe_outside_path=probe_outside_path,
        probe_network_port=probe_network_port,
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


def _make_reference_process_builder(tmp_path: Path, monkeypatch):
    evaluator, candidate_sha256, _config = _make_evaluator(tmp_path, monkeypatch)
    source_root = tmp_path / "reference-source"

    def stage_reference_package(_source, destination):
        entrypoint = destination / "aide/rsi/reference_evaluator.py"
        entrypoint.parent.mkdir(parents=True, exist_ok=True)
        entrypoint.write_text("# pinned reference evaluator test artifact\n")

    monkeypatch.setattr(
        "aide.rsi.trusted_evaluator._python_source_tree_sha256",
        lambda _path: "a" * 64,
    )
    monkeypatch.setattr(
        "aide.rsi.trusted_evaluator._stage_reference_package",
        stage_reference_package,
    )
    evaluator.reference_evaluator = True
    evaluator.reference_package_root = source_root
    evaluator.reference_source_sha256 = "a" * 64
    evaluator.sandbox_backend = "bubblewrap"
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    (scratch / "predictions").mkdir()
    candidate = tmp_path / "candidate.py"
    candidate.write_text("print('candidate')\n")
    request = {"candidate_sha256": candidate_sha256}
    return evaluator, candidate_sha256, scratch, candidate, request


def test_reference_evaluator_uses_host_paths_on_linux(tmp_path: Path, monkeypatch):
    evaluator, candidate_sha256, scratch, candidate, request = (
        _make_reference_process_builder(tmp_path, monkeypatch)
    )
    monkeypatch.setattr(
        "aide.rsi.trusted_evaluator.shutil.which", lambda name: "/usr/bin/bwrap"
    )

    command, _environment, child_request = evaluator._evaluator_process(
        temp_dir=scratch,
        candidate_path=candidate,
        request=request,
    )

    assert command[0] == sys.executable
    assert "--unshare-all" not in command
    assert "/evaluator" not in command
    assert "/scratch/request.json" not in command
    assert child_request["candidate_sha256"] == candidate_sha256
    assert child_request["candidate_path"] == str(candidate.resolve())
    assert child_request["dataset_dir"] == str(evaluator.dataset_dir.resolve())
    assert child_request["evaluator_config_path"] == str(
        evaluator.config_path.resolve()
    )
    assert child_request["split_manifest_path"] == str(evaluator.split_path.resolve())
    assert child_request["output_dir"] == str((scratch / "predictions").resolve())


def test_reference_evaluator_does_not_reference_bwrap_only_paths(
    tmp_path: Path, monkeypatch
):
    evaluator, _digest, scratch, candidate, request = _make_reference_process_builder(
        tmp_path, monkeypatch
    )
    monkeypatch.setattr(
        "aide.rsi.trusted_evaluator.shutil.which", lambda name: "/usr/bin/bwrap"
    )

    command, _environment, child_request = evaluator._evaluator_process(
        temp_dir=scratch,
        candidate_path=candidate,
        request=request,
    )

    namespace_paths = {
        "/evaluator",
        "/candidate.py",
        "/hidden-data",
        "/task-config.json",
        "/split-manifest.json",
        "/scratch",
        "/scratch/request.json",
        "/scratch/response.json",
    }
    assert not namespace_paths.intersection(command)
    assert not namespace_paths.intersection(child_request.values())


def test_reference_evaluator_missing_artifact_fails_closed(tmp_path: Path, monkeypatch):
    evaluator, _digest, scratch, candidate, request = _make_reference_process_builder(
        tmp_path, monkeypatch
    )
    monkeypatch.setattr(
        "aide.rsi.trusted_evaluator._stage_reference_package",
        lambda _source, _destination: None,
    )

    with pytest.raises(
        TrustedEvaluatorError, match="required evaluator path is missing"
    ):
        evaluator._evaluator_process(
            temp_dir=scratch,
            candidate_path=candidate,
            request=request,
        )


def test_seatbelt_evaluator_resolves_symlinked_python_prefixes(tmp_path, monkeypatch):
    evaluator, _digest, scratch, candidate, request = _make_reference_process_builder(
        tmp_path, monkeypatch
    )
    evaluator.reference_evaluator = False
    evaluator.sandbox_backend = "seatbelt"
    real_prefix = tmp_path / "python-prefix"
    real_prefix.mkdir()
    prefix_link = tmp_path / "python-prefix-link"
    prefix_link.symlink_to(real_prefix, target_is_directory=True)
    real_base = tmp_path / "python-base"
    real_base.mkdir()
    base_link = tmp_path / "python-base-link"
    base_link.symlink_to(real_base, target_is_directory=True)
    monkeypatch.setattr("aide.rsi.trusted_evaluator.sys.prefix", str(prefix_link))
    monkeypatch.setattr("aide.rsi.trusted_evaluator.sys.base_prefix", str(base_link))
    monkeypatch.setattr(
        "aide.rsi.trusted_evaluator.shutil.which", lambda name: "/usr/bin/sandbox-exec"
    )

    command, _environment, _child_request = evaluator._evaluator_process(
        temp_dir=scratch,
        candidate_path=candidate,
        request=request,
    )

    assert f"PY_PREFIX={real_prefix.resolve()}" in command
    assert f"PY_BASE={real_base.resolve()}" in command


def test_pinned_evaluator_runs_without_host_attestation_key_and_signs_record(
    tmp_path: Path, monkeypatch
):
    from aide.agent import Agent

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
    assert record["metric_value"] == pytest.approx(0.875)
    assert record["candidate_sha256"] == candidate_sha256
    assert has_trusted_evaluation(
        node,
        maximize=True,
        artifact_root=evaluator.artifact_root,
        require_artifacts=True,
    )
    record_artifact.unlink()
    assert not has_trusted_evaluation(
        node,
        maximize=True,
        artifact_root=evaluator.artifact_root,
        require_artifacts=True,
    )
    journal = SimpleNamespace(metric_maximize=True, nodes=[node])
    assert RealCanaryGate().evaluate_pair(journal, journal).passed


def test_pinned_evaluator_failure_does_not_fall_back_to_feedback_metric(
    tmp_path: Path, monkeypatch
):
    from aide.agent import Agent

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


def test_dataset_is_rehashed_before_each_authoritative_evaluation(
    tmp_path: Path, monkeypatch
):
    evaluator, candidate_sha256, _ = _make_evaluator(tmp_path, monkeypatch)
    labels = evaluator.dataset_dir / "labels.csv"
    labels.chmod(0o644)
    labels.write_text("label\n1\n0\nchanged\n")
    labels.chmod(0o444)
    with pytest.raises(TrustedEvaluatorError, match="dataset_sha256"):
        evaluator.evaluate(candidate_sha256)


def test_first_party_reference_evaluator_is_wired_through_trusted_runner(
    tmp_path: Path, monkeypatch
):
    evaluator, _, config = _make_evaluator(tmp_path, monkeypatch)
    dataset = Path(config.dataset_dir)
    dataset.chmod(0o755)
    (dataset / "labels.csv").chmod(0o644)
    (dataset / "labels.csv").write_text("id,label\na,1\nb,0\n")
    features = dataset / "features.csv"
    features.write_text("id,x\na,1\nb,0\n")
    features.chmod(0o444)
    (dataset / "labels.csv").chmod(0o444)
    dataset.chmod(0o555)
    split = Path(config.split_manifest)
    split.write_text('{"evaluation_sample_ids":["a","b"]}\n')
    config_path = Path(config.config_path)
    config_path.write_text(
        json.dumps(
            {
                "labels_file": "labels.csv",
                "public_files": ["features.csv"],
                "scoring": {"id_column": "id", "label_column": "label"},
            }
        )
        + "\n"
    )
    config.entrypoint = REFERENCE_EVALUATOR_ENTRYPOINT
    config.dataset_sha256 = tree_sha256(dataset)
    config.split_sha256 = file_sha256(split)
    config.config_sha256 = file_sha256(config_path)
    evaluator = TrustedEvaluator(
        config,
        task_description={"Task goal": "read public features and emit predictions"},
        artifact_root=Path(config.dataset_dir).parent / "artifacts",
    )
    candidate_sha256 = store_candidate(
        "import csv, json\n"
        "for row in csv.DictReader(open('input/features.csv')):\n"
        "    print(json.dumps({'id': row['id'], 'prediction': int(row['x'])}))\n",
        evaluator.artifact_root,
    )
    try:
        result = evaluator.evaluate(candidate_sha256)
    except TrustedEvaluatorError as exc:
        if "candidate sandbox" in str(exc) or "strict" in str(exc):
            pytest.skip(f"strict nested candidate sandbox unavailable: {exc}")
        raise
    assert result.score == pytest.approx(1.0)


def test_canary_panel_builder_preserves_reference_sample_identity_rows(
    tmp_path: Path, monkeypatch
):
    from aide.agent import TaskMetric, add_task_metric

    _evaluator, _, evaluator_config = _make_evaluator(tmp_path, monkeypatch)
    dataset = Path(evaluator_config.dataset_dir)
    dataset.chmod(0o755)
    labels = dataset / "labels.csv"
    labels.chmod(0o644)
    features = dataset / "features.csv"
    public_data = tmp_path / "public-data"
    public_data.mkdir()
    (public_data / "features.csv").write_text("id,x\na,0\nz,0\n")
    (public_data / "features.csv").chmod(0o444)

    split = Path(evaluator_config.split_manifest)
    split.write_text('{"evaluation_sample_ids":["z","a"]}\n')
    config_path = Path(evaluator_config.config_path)
    pinned_config = {
        "labels_file": "labels.csv",
        "public_files": ["features.csv"],
        "scoring": {"id_column": "id", "label_column": "label"},
    }
    config_path.write_text(json.dumps(pinned_config) + "\n")

    # Pick a stable pair whose hash order differs from sample-ID order. This
    # makes independently sorting IDs and hash sets observably incorrect.
    chosen_records = None
    for value_a in range(1, 20):
        for value_z in range(21, 40):
            features.write_text(f"id,x\na,{value_a}\nz,{value_z}\n")
            labels.write_text("id,label\na,1\nz,0\n")
            features.chmod(0o444)
            labels.chmod(0o444)
            dataset.chmod(0o555)
            records = sample_identity_records(dataset, pinned_config, ("z", "a"))
            if tuple(item.public_input_sha256 for item in records) != tuple(
                sorted(item.public_input_sha256 for item in records)
            ):
                chosen_records = records
                break
            dataset.chmod(0o755)
            features.chmod(0o644)
            labels.chmod(0o644)
        if chosen_records is not None:
            break
    assert chosen_records is not None

    evaluator_config.entrypoint = REFERENCE_EVALUATOR_ENTRYPOINT
    evaluator_config.dataset_sha256 = tree_sha256(dataset)
    evaluator_config.split_sha256 = file_sha256(split)
    evaluator_config.config_sha256 = file_sha256(config_path)
    evaluator_config.metric_id = "accuracy"
    evaluator_config.metric_maximize = True

    class CapturedPanel:
        def __init__(
            self, *, epoch, tasks, protocol_sha256, benchmark_family_manifest_sha256
        ):
            self.epoch = epoch
            self.tasks = tuple(tasks)
            self.protocol_sha256 = protocol_sha256
            self.benchmark_family_manifest_sha256 = benchmark_family_manifest_sha256

    monkeypatch.setattr("aide.rsi.runner.CanaryPanel", CapturedPanel)
    monkeypatch.setattr(
        "aide.rsi.benchmark.validate_panel_assignments", lambda manifest, panel: None
    )
    benchmark_path = tmp_path / "benchmark.json"
    benchmark_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "manifest_type": "benchmark_families",
                "review_status": "UNREVIEWED",
                "families": [
                    {
                        "family_id": "family-01",
                        "task_ids": ["task-01"],
                        "domain": "test fixture",
                        "dataset_provenance": "fixture-data",
                        "generator_provenance": "fixture-generator",
                        "shared_data": [],
                        "shared_evaluator_components": [],
                        "known_correlations": [],
                        "independence_group_id": "group-01",
                        "independence_rationale": "test fixture only",
                        "review_status": "UNREVIEWED",
                    }
                ],
            }
        )
    )
    description = tmp_path / "task.txt"
    description.write_text("Predict the hidden binary label from x.\n")
    panel_task_config = SimpleNamespace(
        task_id="task-01",
        task_family="family-01",
        task_stratum="classification",
        task_description_file=str(description),
        public_data_dir=str(public_data),
        public_data_sha256=tree_sha256(public_data),
        evaluator=evaluator_config,
        replicate_ids=[0, 1, 2, 3],
        replicate_seeds=[11, 22, 33, 44],
        budget_per_run=24,
    )
    canary_config = SimpleNamespace(
        experiment_alpha=0.05,
        min_effect_size=0.0,
        max_single_task_regression=0.25,
        max_normalized_regression=0.05,
        min_valid=1,
        score_scale_floor=1.0,
    )
    runtime = _build_canary_panel(
        SimpleNamespace(
            rsi=SimpleNamespace(
                canary_panel=[panel_task_config],
                canary_panel_epoch=0,
                benchmark_family_manifest_path=str(benchmark_path),
                canary=canary_config,
            )
        ),
        task_metric_type=TaskMetric,
        add_metric=add_task_metric,
        artifact_root=tmp_path / "artifacts",
    )

    definition = runtime.panel.tasks[0]
    assert definition.sample_ids == tuple(item.sample_id for item in chosen_records)
    assert definition.public_input_sha256 == tuple(
        item.public_input_sha256 for item in chosen_records
    )
    assert definition.sample_content_sha256 == tuple(
        item.sample_content_sha256 for item in chosen_records
    )


def test_outer_timeout_kills_nested_reference_candidate(tmp_path: Path, monkeypatch):
    import aide.rsi.trusted_evaluator as trusted_evaluator_module

    evaluator, _, config = _make_evaluator(tmp_path, monkeypatch)
    dataset = Path(config.dataset_dir)
    dataset.chmod(0o755)
    labels = dataset / "labels.csv"
    labels.chmod(0o644)
    labels.write_text("id,label\na,1\n")
    features = dataset / "features.csv"
    features.write_text("id,x\na,1\n")
    features.chmod(0o444)
    labels.chmod(0o444)
    dataset.chmod(0o555)
    split = Path(config.split_manifest)
    split.write_text('{"evaluation_sample_ids":["a"]}\n')
    config_path = Path(config.config_path)
    config_path.write_text(
        json.dumps(
            {
                "labels_file": "labels.csv",
                "public_files": ["features.csv"],
                "scoring": {"id_column": "id", "label_column": "label"},
            }
        )
        + "\n"
    )
    config.entrypoint = REFERENCE_EVALUATOR_ENTRYPOINT
    config.dataset_sha256 = tree_sha256(dataset)
    config.split_sha256 = file_sha256(split)
    config.config_sha256 = file_sha256(config_path)
    config.timeout_s = 3
    evaluator = TrustedEvaluator(
        config,
        task_description={"Task goal": "timeout nested candidate"},
        artifact_root=Path(config.dataset_dir).parent / "artifacts",
    )
    candidate_sha256 = store_candidate(
        "import time\ntime.sleep(3600)\n", evaluator.artifact_root
    )
    captured_groups: list[int] = []
    original_kill = trusted_evaluator_module._kill_process_group

    def capture_then_kill(process, *, additional_process_groups_path=None):
        if additional_process_groups_path is not None:
            try:
                groups = json.loads(additional_process_groups_path.read_text())
            except FileNotFoundError:
                groups = []
            captured_groups.extend(groups)
        return original_kill(
            process,
            additional_process_groups_path=additional_process_groups_path,
        )

    monkeypatch.setattr(
        trusted_evaluator_module, "_kill_process_group", capture_then_kill
    )
    try:
        with pytest.raises(TrustedEvaluatorError, match="timeout"):
            evaluator.evaluate(candidate_sha256)
    except TrustedEvaluatorError as exc:
        if "candidate sandbox" in str(exc) or "strict" in str(exc):
            pytest.skip(f"strict nested candidate sandbox unavailable: {exc}")
        raise

    assert captured_groups, "reference adapter never registered its candidate group"
    for process_group in captured_groups:
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            try:
                os.killpg(process_group, 0)
            except ProcessLookupError:
                break
            # A terminated orphan may briefly remain as a zombie until reaped.
            result = subprocess.run(
                ["ps", "-o", "stat=", "-p", str(process_group)],
                check=False,
                capture_output=True,
                text=True,
            )
            if result.returncode != 0 or result.stdout.strip().startswith("Z"):
                break
            time.sleep(0.05)
        else:
            pytest.fail(
                f"nested candidate process group {process_group} survived timeout"
            )


def test_canonical_evaluation_sample_ids_detect_semantic_overlap(tmp_path: Path):
    compact = tmp_path / "compact.json"
    formatted = tmp_path / "formatted.json"
    compact.write_text('{"evaluation_sample_ids":["a","b"]}')
    formatted.write_text('{\n  "evaluation_sample_ids": ["b", "a"]\n}')
    left = canonical_evaluation_sample_ids(compact)
    right = canonical_evaluation_sample_ids(formatted)
    assert left == right == ("a", "b")
    assert evaluation_sample_overlap(left, right) == ("a", "b")


def test_memory_floor_is_megabytes_not_bytes(tmp_path: Path, monkeypatch):
    _, _, config = _make_evaluator(tmp_path, monkeypatch)
    config.max_memory_mb = 1
    with pytest.raises(TrustedEvaluatorError, match="max_memory_mb"):
        TrustedEvaluator(
            config,
            task_description={"Task goal": "test"},
            artifact_root=tmp_path / "artifacts",
        )


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


def test_candidate_snapshot_cannot_be_changed_and_artifact_is_preserved(
    tmp_path: Path, monkeypatch
):
    evaluator, candidate_sha256, _ = _make_evaluator(
        tmp_path, monkeypatch, tamper_candidate=True
    )

    with pytest.raises(
        TrustedEvaluatorError, match="pinned evaluator returned nonzero"
    ):
        evaluator.evaluate(candidate_sha256)

    assert (
        evaluator.artifact_root
        / "sha256"
        / candidate_sha256[:2]
        / f"{candidate_sha256}.py"
    ).read_text() == "print('candidate')\n"


def test_evaluator_cannot_read_unmounted_host_files(tmp_path: Path, monkeypatch):
    secret = tmp_path.parent / "host-only-secret.txt"
    secret.write_text("host secret sentinel")
    evaluator, candidate_sha256, _ = _make_evaluator(
        tmp_path, monkeypatch, probe_outside_path=secret
    )

    result = evaluator.evaluate(candidate_sha256)

    assert result.score == pytest.approx(0.875)


def test_evaluator_cannot_connect_to_host_loopback(tmp_path: Path, monkeypatch):
    import socket

    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    evaluator, candidate_sha256, _ = _make_evaluator(
        tmp_path, monkeypatch, probe_network_port=listener.getsockname()[1]
    )

    try:
        result = evaluator.evaluate(candidate_sha256)
    finally:
        listener.close()

    assert result.score == pytest.approx(0.875)


def test_bubblewrap_invocation_uses_private_namespaces_and_read_only_inputs(
    tmp_path: Path, monkeypatch
):
    evaluator, candidate_sha256, _ = _make_evaluator(tmp_path, monkeypatch)
    evaluator.sandbox_backend = "bubblewrap"
    monkeypatch.setattr(
        "aide.rsi.trusted_evaluator.shutil.which", lambda name: "/usr/bin/bwrap"
    )
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    candidate = tmp_path / "candidate.py"
    candidate.write_text("print('candidate')\n")

    command, environment, child_request = evaluator._evaluator_process(
        temp_dir=scratch,
        candidate_path=candidate,
        request={"candidate_sha256": candidate_sha256},
    )

    assert command[0] == "/usr/bin/bwrap"
    assert "--unshare-all" in command
    assert "--new-session" in command
    assert "--ro-bind" in command
    assert "--bind" in command
    assert "--clearenv" in command
    assert environment["PATH"] == evaluator.evaluator_path
    assert child_request["dataset_dir"] == "/hidden-data"
    assert child_request["output_dir"] == "/scratch/predictions"


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


def test_canary_evaluator_requires_an_independent_data_split():
    metric = SimpleNamespace(name="accuracy", maximize=True)
    search = SimpleNamespace(
        dataset_sha256="a" * 64,
        split_sha256="b" * 64,
        metric_id="accuracy",
        metric_maximize=True,
    )
    canary = SimpleNamespace(
        dataset_sha256="a" * 64,
        split_sha256="b" * 64,
        metric_id="accuracy",
        metric_maximize=True,
    )

    with pytest.raises(ValueError, match="different pinned dataset or split"):
        _validate_trusted_evaluator_roles(search, canary, metric)

    canary.split_sha256 = "c" * 64
    _validate_trusted_evaluator_roles(search, canary, metric)


def test_reference_sample_content_detects_duplicate_rows_with_different_ids(
    tmp_path: Path,
):
    (tmp_path / "features.csv").write_text("id,x\na,1\nb,1\n")
    (tmp_path / "labels.csv").write_text("id,label\na,positive\nb,positive\n")
    config = {
        "labels_file": "labels.csv",
        "public_files": ["features.csv"],
        "scoring": {"id_column": "id", "label_column": "label"},
    }
    first = sample_content_sha256(tmp_path, config, ("a",))
    second = sample_content_sha256(tmp_path, config, ("b",))
    assert first == second
    metric = SimpleNamespace(name="accuracy", maximize=True)
    search = SimpleNamespace(
        dataset_sha256="a" * 64,
        split_sha256="b" * 64,
        metric_id="accuracy",
        metric_maximize=True,
        evaluation_sample_content_sha256=first,
        evaluation_sample_public_input_sha256=sample_identity_sha256(
            tmp_path, config, ("a",)
        )[0],
    )
    canary = SimpleNamespace(
        dataset_sha256="c" * 64,
        split_sha256="d" * 64,
        metric_id="accuracy",
        metric_maximize=True,
        evaluation_sample_content_sha256=second,
        evaluation_sample_public_input_sha256=sample_identity_sha256(
            tmp_path, config, ("b",)
        )[0],
    )
    with pytest.raises(ValueError, match="duplicate candidate-visible input"):
        _validate_trusted_evaluator_roles(search, canary, metric)


def test_reference_public_identity_ignores_file_order_and_label_changes(tmp_path: Path):
    (tmp_path / "f1.csv").write_text("id,x\na,1\nb,1\n")
    (tmp_path / "f2.csv").write_text("id,x\na,2\nb,2\n")
    (tmp_path / "labels.csv").write_text("id,label\na,yes\nb,no\n")
    config = {
        "labels_file": "labels.csv",
        "public_files": ["f1.csv", "f2.csv"],
        "scoring": {"id_column": "id", "label_column": "label"},
    }
    first_public, first_full = sample_identity_sha256(tmp_path, config, ("a",))
    reordered_public, reordered_full = sample_identity_sha256(
        tmp_path, {**config, "public_files": ["f2.csv", "f1.csv"]}, ("a",)
    )
    assert first_public == reordered_public
    assert first_full == reordered_full

    (tmp_path / "labels.csv").write_text("id,label\na,changed\nb,no\n")
    changed_public, changed_full = sample_identity_sha256(tmp_path, config, ("a",))
    assert changed_public == first_public
    assert changed_full != first_full
    metric = SimpleNamespace(name="accuracy", maximize=True)
    search = SimpleNamespace(
        dataset_sha256="a" * 64,
        split_sha256="b" * 64,
        metric_id="accuracy",
        metric_maximize=True,
        task_sha256="task",
        evaluation_sample_public_input_sha256=first_public,
        evaluation_sample_content_sha256=first_full,
    )
    canary = SimpleNamespace(
        dataset_sha256="c" * 64,
        split_sha256="d" * 64,
        metric_id="accuracy",
        metric_maximize=True,
        task_sha256="task",
        evaluation_sample_public_input_sha256=changed_public,
        evaluation_sample_content_sha256=changed_full,
    )
    with pytest.raises(ValueError, match="candidate-visible"):
        _validate_trusted_evaluator_roles(search, canary, metric)


def test_reference_identity_preserves_file_names_when_columns_collide(tmp_path: Path):
    (tmp_path / "f1.csv").write_text("id,x\na,1\n")
    (tmp_path / "f2.csv").write_text("id,x\na,2\n")
    (tmp_path / "labels.csv").write_text("id,label\na,yes\n")
    config = {
        "labels_file": "labels.csv",
        "public_files": ["f1.csv", "f2.csv"],
        "scoring": {"id_column": "id", "label_column": "label"},
    }
    public_both, _ = sample_identity_sha256(tmp_path, config, ("a",))
    public_first, _ = sample_identity_sha256(
        tmp_path, {**config, "public_files": ["f1.csv"]}, ("a",)
    )
    assert public_both != public_first


def test_reference_identity_rejects_duplicate_candidate_visible_rows(tmp_path: Path):
    (tmp_path / "features.csv").write_text("id,x\na,1\nb,1\n")
    (tmp_path / "labels.csv").write_text("id,label\na,yes\nb,no\n")
    config = {
        "labels_file": "labels.csv",
        "public_files": ["features.csv"],
        "scoring": {"id_column": "id", "label_column": "label"},
    }
    with pytest.raises(ReferenceEvaluatorError, match="duplicate candidate-visible"):
        sample_identity_sha256(tmp_path, config, ("a", "b"))


def test_reference_identity_canonicalizes_csv_numeric_and_whitespace_values(
    tmp_path: Path,
):
    (tmp_path / "features.csv").write_text("id,x\na, 1.000 \n")
    (tmp_path / "labels.csv").write_text("id,label\na, yes \n")
    config = {
        "labels_file": "labels.csv",
        "public_files": ["features.csv"],
        "scoring": {"id_column": "id", "label_column": "label"},
    }
    first_public, first_full = sample_identity_sha256(tmp_path, config, ("a",))
    (tmp_path / "features.csv").write_text("id,x\na,1e0\n")
    (tmp_path / "labels.csv").write_text("id,label\na,yes\n")
    second_public, second_full = sample_identity_sha256(tmp_path, config, ("a",))
    assert first_public == second_public
    assert first_full == second_full


def test_reference_identity_rejects_duplicate_csv_columns(tmp_path: Path):
    (tmp_path / "features.csv").write_text("id,x,x\na,1,2\n")
    (tmp_path / "labels.csv").write_text("id,label\na,yes\n")
    config = {
        "labels_file": "labels.csv",
        "public_files": ["features.csv"],
        "scoring": {"id_column": "id", "label_column": "label"},
    }
    with pytest.raises(ReferenceEvaluatorError, match="duplicate columns"):
        sample_identity_sha256(tmp_path, config, ("a",))


def test_canary_evaluator_must_use_the_same_metric():
    metric = SimpleNamespace(name="accuracy", maximize=True)
    canary = SimpleNamespace(
        dataset_sha256="a" * 64,
        split_sha256="c" * 64,
        metric_id="loss",
        metric_maximize=False,
    )

    with pytest.raises(ValueError, match="canary evaluator metric"):
        _validate_trusted_evaluator_roles(
            SimpleNamespace(
                dataset_sha256="b" * 64,
                split_sha256="d" * 64,
                metric_id="accuracy",
                metric_maximize=True,
            ),
            canary,
            metric,
        )

    with pytest.raises(ValueError, match="requires the trusted search evaluator"):
        _validate_trusted_evaluator_roles(None, canary, metric)


def test_prior_run_evaluator_identities_migrate_by_role():
    assert _stored_evaluator_identity({"trusted_evaluator_identity": "search"}) == {
        "search": "search",
        "canary": None,
    }
    assert _stored_evaluator_identity({"trusted_evaluator_identity": None}) == {
        "search": None,
        "canary": None,
    }
    assert _stored_evaluator_identity({}) is None


def test_evaluator_identity_binds_task_description_and_pinned_inputs(
    tmp_path: Path, monkeypatch
):
    evaluator, _, _ = _make_evaluator(tmp_path, monkeypatch)
    assert evaluator.task_sha256 == _stable_digest({"Task goal": "test"})
    assert evaluator.identity == _stable_digest(evaluator._identity_fields())


def test_evaluator_authority_identity_is_stable_across_split_rotation(
    tmp_path: Path, monkeypatch
):
    evaluator, _, config = _make_evaluator(tmp_path, monkeypatch)
    next_split = tmp_path / "split-next.json"
    next_split.write_text('{"partition":"qualification-v2"}\n')
    config.split_manifest = str(next_split)
    config.split_sha256 = file_sha256(next_split)
    rotated = TrustedEvaluator(
        config,
        task_description={"Task goal": "test"},
        artifact_root=evaluator.artifact_root,
    )
    assert rotated.identity != evaluator.identity
    assert rotated.authority_identity == evaluator.authority_identity


@pytest.mark.parametrize(
    ("resource", "delta"),
    (("max_output_mb", 1), ("max_processes", 1), ("max_open_files", 16)),
)
def test_evaluator_identity_binds_resource_limits(
    tmp_path: Path, monkeypatch, resource, delta
):
    evaluator, _, config = _make_evaluator(tmp_path, monkeypatch)
    defaults = {"max_processes": 64, "max_open_files": 64}
    setattr(
        config, resource, getattr(config, resource, defaults.get(resource, 0)) + delta
    )
    changed = TrustedEvaluator(
        config,
        task_description={"Task goal": "test"},
        artifact_root=evaluator.artifact_root,
    )
    assert changed.identity != evaluator.identity


def test_requested_process_limit_is_capped_to_host_hard_limit(monkeypatch):
    import aide.rsi.trusted_evaluator as trusted_evaluator_module

    monkeypatch.setattr(
        trusted_evaluator_module.resource,
        "getrlimit",
        lambda _resource_id: (64, 128),
    )
    assert _effective_resource_limit("RLIMIT_NPROC", 2048) == 128
