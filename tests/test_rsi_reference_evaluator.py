import json
from pathlib import Path

import pytest

from aide.rsi import reference_evaluator as reference
from aide.rsi.sandbox import SandboxUnavailable


def test_reference_candidate_gets_only_public_files_and_predictions_are_exact(
    tmp_path: Path, monkeypatch
):
    dataset = tmp_path / "dataset"
    dataset.mkdir()
    (dataset / "features.csv").write_text("id,x\na,1\nb,2\n")
    (dataset / "labels.csv").write_text("id,label\na,1\nb,0\n")
    (tmp_path / "candidate.py").write_text("print('candidate')\n")
    seen = {}

    def fake_run_candidate(script, workspace, config, **kwargs):
        seen["source"] = Path(script).read_text()
        input_root = Path(workspace) / "input"
        seen["files"] = sorted(path.name for path in input_root.iterdir())
        return b'{"id":"a","prediction":1}\n{"id":"b","prediction":0}\n'

    monkeypatch.setattr(reference, "_run_candidate_seatbelt", fake_run_candidate)
    request = {
        "dataset_dir": str(dataset),
        "candidate_path": str(tmp_path / "candidate.py"),
        "max_processes": 2048,
        "max_open_files": 256,
    }
    config = {
        "labels_file": "labels.csv",
        "public_files": ["features.csv"],
    }
    result = reference._run_candidate(request, config, ("a", "b"))
    assert seen["files"] == ["features.csv"]
    assert "candidate" in seen["source"]
    assert json.loads(result.decode().splitlines()[0]) == {"id": "a", "prediction": 1}


def test_reference_evaluator_uses_separate_fixed_metric_scorer(
    tmp_path: Path, monkeypatch
):
    dataset = tmp_path / "dataset"
    dataset.mkdir()
    (dataset / "labels.csv").write_text("id,label\na,1\nb,0\n")
    split = tmp_path / "split.json"
    split.write_text('{"evaluation_sample_ids":["a","b"]}')
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps(
            {
                "labels_file": "labels.csv",
                "scoring": {"id_column": "id", "label_column": "label"},
            }
        )
    )
    output = tmp_path / "output"
    output.mkdir()
    request_path = tmp_path / "request.json"
    response_path = tmp_path / "response.json"
    identities = {
        "candidate_sha256": "c" * 64,
        "task_sha256": "t" * 64,
        "evaluator_sha256": "e" * 64,
        "evaluator_config_sha256": "f" * 64,
        "dataset_sha256": "d" * 64,
        "split_sha256": "s" * 64,
        "environment_sha256": "n" * 64,
        "metric_id": "accuracy",
        "metric_maximize": True,
        "max_processes": 2048,
        "max_open_files": 256,
    }
    request_path.write_text(
        json.dumps(
            {
                **identities,
                "evaluator_config_path": str(config_path),
                "dataset_dir": str(dataset),
                "split_manifest_path": str(split),
                "output_dir": str(output),
            }
        )
    )
    monkeypatch.setattr(
        reference,
        "_run_candidate",
        lambda request, config, samples: (
            b'{"id":"b","prediction":0}\n{"id":"a","prediction":1}\n'
        ),
    )

    reference._evaluate(request_path, response_path)
    response = json.loads(response_path.read_text())
    assert response["score"] == 1.0
    assert response["metric_id"] == "accuracy"
    assert len(response["predictions_sha256"]) == 64


def test_reference_candidate_cannot_read_labels_or_open_network(tmp_path: Path):
    dataset = tmp_path / "hidden"
    dataset.mkdir()
    (dataset / "features.csv").write_text("id,x\nsample-1,1\n")
    labels = dataset / "labels.csv"
    labels.write_text("id,label\nsample-1,private-sentinel\n")
    candidate_path = tmp_path / "candidate.py"
    candidate_path.write_text(
        "import json, socket\n"
        "try:\n"
        f"    exposed = 'private-sentinel' in open({str(labels)!r}).read()\n"
        "except Exception:\n"
        "    exposed = False\n"
        "try:\n"
        "    socket.create_connection(('127.0.0.1', 9), timeout=0.2)\n"
        "    network = True\n"
        "except Exception:\n"
        "    network = False\n"
        "print(json.dumps({'id':'sample-1','prediction':"
        "{'labels_exposed':exposed,'network_available':network}}))\n"
    )
    try:
        prediction_bytes = reference._run_candidate(
            {
                "dataset_dir": str(dataset),
                "candidate_path": str(candidate_path),
                "max_processes": 2048,
                "max_open_files": 256,
            },
            {"labels_file": "labels.csv", "public_files": ["features.csv"]},
            ("sample-1",),
        )
    except SandboxUnavailable as exc:
        pytest.skip(f"strict candidate sandbox is unavailable: {exc}")
    prediction = json.loads(prediction_bytes.decode())
    assert prediction["prediction"] == {
        "labels_exposed": False,
        "network_available": False,
    }
