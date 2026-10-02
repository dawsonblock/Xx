"""Reference split-process evaluator for tabular prediction candidates.

Candidates receive only files listed as public inputs and emit one JSON object
per line to stdout: {"id": "sample-id", "prediction": value}. Labels are
loaded only by the separate scorer process, which never receives candidate code.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unicodedata
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

from aide.rsi.sandbox import SandboxUnavailable

IDENTITY_KEYS = (
    "candidate_sha256",
    "task_sha256",
    "evaluator_sha256",
    "evaluator_config_sha256",
    "dataset_sha256",
    "split_sha256",
    "environment_sha256",
    "metric_id",
    "metric_maximize",
)


class ReferenceEvaluatorError(RuntimeError):
    """The reference evaluator could not produce a valid prediction record."""


_CANDIDATE_SEATBELT_PROFILE = """(version 1)
(deny default)
(allow process-exec)
(allow file-read-metadata (subpath "/"))
(allow file-read-data
    (literal "/")
    (subpath (param "PY_PREFIX"))
    (subpath (param "PY_BASE"))
    (subpath "/usr/bin")
    (subpath "/bin")
    (subpath "/usr/lib")
    (subpath "/System/Library")
    (subpath "/usr/share/zoneinfo")
    (subpath "/opt/homebrew/opt")
    (subpath "/opt/homebrew/Cellar")
    (subpath "/usr/local/opt")
    (subpath "/usr/local/Cellar")
    (subpath (param "WORK"))
    (subpath (param "INPUT")))
(allow sysctl-read)
"""


def _canonical_id(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ReferenceEvaluatorError("sample IDs must be nonempty strings")
    return unicodedata.normalize("NFC", value.strip())


def _canonical_cell(value: Any) -> str:
    if not isinstance(value, str):
        raise ReferenceEvaluatorError("CSV cells must be present strings")
    normalized = unicodedata.normalize("NFC", value.strip())
    try:
        number = Decimal(normalized)
    except InvalidOperation:
        return "text:" + normalized
    if number.is_finite():
        number = number.normalize()
        return "number:" + (format(number, "f") if number else "0")
    return "text:" + normalized


def _sample_ids(split_path: Path) -> tuple[str, ...]:
    try:
        raw = json.loads(split_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReferenceEvaluatorError("split manifest is invalid JSON") from exc
    values = raw.get("evaluation_sample_ids") if isinstance(raw, dict) else None
    if not isinstance(values, list) or not values:
        raise ReferenceEvaluatorError("split manifest requires evaluation_sample_ids")
    result = tuple(sorted(_canonical_id(value) for value in values))
    if len(result) != len(set(result)):
        raise ReferenceEvaluatorError("split manifest contains duplicate sample IDs")
    return result


def sample_identity_sha256(
    dataset_root: Path, config: dict[str, Any], sample_ids: tuple[str, ...]
) -> tuple[frozenset[str], frozenset[str]]:
    """Return public-input and full-record hashes, independent of IDs and list order."""
    scoring = config.get("scoring", {})
    if not isinstance(scoring, dict):
        raise ReferenceEvaluatorError("scoring must be an object")
    id_column = unicodedata.normalize("NFC", scoring.get("id_column", "id"))
    label_column = unicodedata.normalize("NFC", scoring.get("label_column", "label"))
    labels_relative = _safe_relative(config.get("labels_file"), field="labels_file")
    labels_path = (dataset_root / labels_relative).resolve(strict=True)
    if not labels_path.is_file() or not labels_path.is_relative_to(dataset_root):
        raise ReferenceEvaluatorError("labels_file must be a dataset file")
    try:
        with labels_path.open("r", newline="", encoding="utf-8") as stream:
            reader = csv.DictReader(stream)
            headers = reader.fieldnames or []
            normalized_headers = [
                unicodedata.normalize("NFC", name) for name in headers
            ]
            if (
                not headers
                or len(set(normalized_headers)) != len(normalized_headers)
                or id_column not in normalized_headers
                or label_column not in normalized_headers
            ):
                raise ReferenceEvaluatorError("trusted label file has invalid columns")
            id_header = headers[normalized_headers.index(id_column)]
            label_header = headers[normalized_headers.index(label_column)]
            label_rows = list(reader)
        label_by_id: dict[str, str] = {}
        for row in label_rows:
            if None in row or any(value is None for value in row.values()):
                raise ReferenceEvaluatorError("trusted label file has malformed rows")
            sample_id = _canonical_id(row[id_header])
            if sample_id in label_by_id:
                raise ReferenceEvaluatorError(
                    "trusted label file contains duplicate IDs"
                )
            label_by_id[sample_id] = _canonical_cell(row[label_header])
        feature_rows: dict[str, dict[str, dict[str, str]]] = {}
        public_files = config.get("public_files")
        if not isinstance(public_files, list) or not public_files:
            raise ReferenceEvaluatorError(
                "public_files must list at least one feature file"
            )
        seen_paths: set[str] = set()
        for value in public_files:
            relative = _safe_relative(value, field="public_files entry")
            canonical_path = unicodedata.normalize("NFC", relative.as_posix())
            if canonical_path in seen_paths:
                raise ReferenceEvaluatorError("public_files contains duplicate paths")
            seen_paths.add(canonical_path)
            feature_path = (dataset_root / relative).resolve(strict=True)
            if not feature_path.is_file() or not feature_path.is_relative_to(
                dataset_root
            ):
                raise ReferenceEvaluatorError(
                    "public feature path is outside the dataset"
                )
            if feature_path == labels_path:
                raise ReferenceEvaluatorError(
                    "labels_file cannot be a public candidate input"
                )
            seen_in_file: set[str] = set()
            with feature_path.open("r", newline="", encoding="utf-8") as stream:
                reader = csv.DictReader(stream)
                if not reader.fieldnames:
                    raise ReferenceEvaluatorError("public feature file has no header")
                normalized_headers = [
                    unicodedata.normalize("NFC", name) if name is not None else ""
                    for name in reader.fieldnames
                ]
                if (
                    any(not name for name in normalized_headers)
                    or len(set(normalized_headers)) != len(normalized_headers)
                    or id_column not in normalized_headers
                ):
                    raise ReferenceEvaluatorError(
                        "public feature file has invalid or duplicate columns"
                    )
                id_header = reader.fieldnames[normalized_headers.index(id_column)]
                for row in reader:
                    if None in row or any(value is None for value in row.values()):
                        raise ReferenceEvaluatorError(
                            "public feature file has malformed rows"
                        )
                    sample_id = _canonical_id(row[id_header])
                    if sample_id in seen_in_file:
                        raise ReferenceEvaluatorError(
                            "public feature file contains duplicate IDs"
                        )
                    seen_in_file.add(sample_id)
                    feature_rows.setdefault(sample_id, {})[canonical_path] = {
                        unicodedata.normalize("NFC", key): _canonical_cell(value)
                        for key, value in row.items()
                        if key != id_header
                    }
    except (OSError, UnicodeDecodeError, csv.Error, KeyError) as exc:
        raise ReferenceEvaluatorError(
            "sample content could not be canonicalized"
        ) from exc
    if not set(sample_ids) <= set(label_by_id) or not set(sample_ids) <= set(
        feature_rows
    ):
        raise ReferenceEvaluatorError("sample content is missing pinned IDs")
    public_hashes: set[str] = set()
    full_hashes: set[str] = set()
    for sample_id in sample_ids:
        public_payload = {
            "files": {
                filename: {
                    column: feature_rows[sample_id][filename][column]
                    for column in sorted(feature_rows[sample_id][filename])
                }
                for filename in sorted(feature_rows[sample_id])
            }
        }
        canonical_public = json.dumps(
            public_payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        public_digest = hashlib.sha256(canonical_public.encode("utf-8")).hexdigest()
        public_hashes.add(public_digest)
        canonical_full = json.dumps(
            {
                "public_input_sha256": public_digest,
                "label": label_by_id[sample_id],
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        full_hashes.add(hashlib.sha256(canonical_full.encode("utf-8")).hexdigest())
    if len(public_hashes) != len(sample_ids):
        raise ReferenceEvaluatorError(
            "evaluation shard contains duplicate candidate-visible rows"
        )
    return frozenset(public_hashes), frozenset(full_hashes)


def sample_content_sha256(
    dataset_root: Path, config: dict[str, Any], sample_ids: tuple[str, ...]
) -> frozenset[str]:
    """Compatibility helper returning full feature-and-label identities."""
    return sample_identity_sha256(dataset_root, config, sample_ids)[1]


def _safe_relative(value: Any, *, field: str) -> Path:
    if not isinstance(value, str) or not value:
        raise ReferenceEvaluatorError(f"{field} must be a relative path")
    path = Path(value)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise ReferenceEvaluatorError(f"{field} must stay inside the dataset")
    return path


def _read_predictions(
    data: bytes, expected_ids: tuple[str, ...]
) -> list[dict[str, Any]]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ReferenceEvaluatorError("candidate predictions are not UTF-8") from exc
    predictions: list[dict[str, Any]] = []
    seen: set[str] = set()
    for line_number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ReferenceEvaluatorError(
                f"candidate prediction line {line_number} is invalid JSON"
            ) from exc
        if not isinstance(row, dict) or set(row) != {"id", "prediction"}:
            raise ReferenceEvaluatorError(
                "each prediction must contain exactly id and prediction"
            )
        sample_id = _canonical_id(row["id"])
        if sample_id in seen:
            raise ReferenceEvaluatorError(f"duplicate prediction for {sample_id}")
        seen.add(sample_id)
        predictions.append({"id": sample_id, "prediction": row["prediction"]})
    if seen != set(expected_ids):
        raise ReferenceEvaluatorError(
            "prediction sample IDs do not match the pinned split"
        )
    return predictions


def _load_scorer_rows(request: dict[str, Any]) -> tuple[list[Any], list[Any]]:
    sample_ids = tuple(request["evaluation_sample_ids"])
    label_file = Path(request["labels_path"])
    config = request["scoring"]
    id_column = config.get("id_column", "id")
    label_column = config.get("label_column", "label")
    try:
        with label_file.open("r", newline="", encoding="utf-8") as stream:
            rows = list(csv.DictReader(stream))
    except (OSError, UnicodeDecodeError, csv.Error) as exc:
        raise ReferenceEvaluatorError("trusted labels could not be read") from exc
    by_id: dict[str, dict[str, str]] = {}
    for row in rows:
        sample_id = _canonical_id(row.get(id_column))
        if sample_id in by_id:
            raise ReferenceEvaluatorError("trusted label file contains duplicate IDs")
        by_id[sample_id] = row
    if set(by_id) != set(sample_ids):
        raise ReferenceEvaluatorError("trusted label IDs do not match the pinned split")
    predictions_path = Path(request["predictions_path"])
    predictions = {
        row["id"]: row["prediction"]
        for row in _read_predictions(predictions_path.read_bytes(), sample_ids)
    }
    labels = [by_id[sample_id][label_column] for sample_id in sample_ids]
    predicted = [predictions[sample_id] for sample_id in sample_ids]
    return labels, predicted


def _score(metric_id: str, labels: list[Any], predictions: list[Any]) -> float:
    if not labels or len(labels) != len(predictions):
        raise ReferenceEvaluatorError("label and prediction counts differ")
    if metric_id == "accuracy":
        return sum(str(a) == str(b) for a, b in zip(labels, predictions)) / len(labels)
    try:
        actual = [float(value) for value in labels]
        predicted = [float(value) for value in predictions]
    except (TypeError, ValueError) as exc:
        raise ReferenceEvaluatorError(
            "regression metric requires numeric values"
        ) from exc
    if not all(math.isfinite(value) for value in actual + predicted):
        raise ReferenceEvaluatorError("metric inputs must be finite")
    squared = [(a - p) ** 2 for a, p in zip(actual, predicted)]
    absolute = [abs(a - p) for a, p in zip(actual, predicted)]
    if metric_id == "mean_squared_error":
        return sum(squared) / len(squared)
    if metric_id == "root_mean_squared_error":
        return math.sqrt(sum(squared) / len(squared))
    if metric_id == "mean_absolute_error":
        return sum(absolute) / len(absolute)
    if metric_id == "r2":
        mean = sum(actual) / len(actual)
        total = sum((value - mean) ** 2 for value in actual)
        return (
            1.0
            if total == 0 and sum(squared) == 0
            else (0.0 if total == 0 else 1.0 - sum(squared) / total)
        )
    raise ReferenceEvaluatorError(f"unsupported fixed metric: {metric_id}")


def _score_child(score_request_path: Path) -> None:
    request = json.loads(score_request_path.read_text(encoding="utf-8"))
    labels, predictions = _load_scorer_rows(request)
    score = _score(request["metric_id"], labels, predictions)
    if not math.isfinite(score):
        raise ReferenceEvaluatorError("trusted scorer produced a non-finite score")
    Path(request["score_path"]).write_text(
        json.dumps({"score": score}, sort_keys=True) + "\n", encoding="utf-8"
    )


def _run_candidate(
    request: dict[str, Any], config: dict[str, Any], samples: tuple[str, ...]
) -> bytes:
    dataset_root = Path(request["dataset_dir"]).resolve(strict=True)
    labels_relative = _safe_relative(config.get("labels_file"), field="labels_file")
    labels_path = (dataset_root / labels_relative).resolve(strict=True)
    if not labels_path.is_file() or not labels_path.is_relative_to(dataset_root):
        raise ReferenceEvaluatorError("labels_file must be a dataset file")
    public_files = config.get("public_files")
    if not isinstance(public_files, list) or not public_files:
        raise ReferenceEvaluatorError(
            "public_files must list at least one feature file"
        )
    scratch_root = (
        Path(request.get("output_dir", request["candidate_path"])).resolve().parent
    )
    with tempfile.TemporaryDirectory(
        prefix="aide-reference-candidate-", dir=scratch_root
    ) as temp:
        workspace = Path(temp)
        input_root = workspace / "input"
        input_root.mkdir()
        for value in public_files:
            relative = _safe_relative(value, field="public_files entry")
            source = (dataset_root / relative).resolve(strict=True)
            if not source.is_file() or not source.is_relative_to(dataset_root):
                raise ReferenceEvaluatorError(
                    "public feature path is outside the dataset"
                )
            if source == labels_path:
                raise ReferenceEvaluatorError(
                    "labels_file cannot be a public candidate input"
                )
            target = input_root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
            target.chmod(0o444)
        input_root.chmod(0o555)
        sandbox_config = config.get("candidate_sandbox", {})
        if not isinstance(sandbox_config, dict):
            raise ReferenceEvaluatorError("candidate_sandbox must be an object")
        candidate_source = Path(request["candidate_path"]).read_text(encoding="utf-8")
        script = workspace / "candidate.py"
        script.write_text(candidate_source, encoding="utf-8")
        script.chmod(0o444)
        stdout = _run_candidate_seatbelt(
            script,
            workspace,
            sandbox_config,
            max_processes=int(request["max_processes"]),
            max_open_files=int(request["max_open_files"]),
            child_process_groups_path=(
                Path(request["candidate_process_groups_path"])
                if request.get("candidate_process_groups_path")
                else None
            ),
        )
        predictions = _read_predictions(stdout, samples)
        return b"".join(
            (json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n").encode()
            for row in predictions
        )


def _run_candidate_seatbelt(
    script: Path,
    workspace: Path,
    config: dict[str, Any],
    *,
    max_processes: int,
    max_open_files: int,
    child_process_groups_path: Path | None = None,
) -> bytes:
    timeout = int(config.get("timeout_s", 300))
    memory_mb = int(config.get("memory_mb", 1024))
    output_mb = int(config.get("max_output_mb", 64))
    tmpfs_mb = int(config.get("tmpfs_mb", 16))
    if not 1 <= timeout <= 86400 or not 128 <= memory_mb <= 65536:
        raise ReferenceEvaluatorError("candidate resource limits are invalid")
    if not 1 <= output_mb <= 4096 or not 1 <= tmpfs_mb <= 1024:
        raise ReferenceEvaluatorError("candidate output limits are invalid")
    if sys.platform == "darwin":
        sandbox_exec = shutil.which("sandbox-exec")
        if sandbox_exec is None:
            raise SandboxUnavailable("macOS Seatbelt is unavailable")
        prefix = [sandbox_exec]
        for name, value in (
            ("PY_PREFIX", str(Path(sys.prefix).resolve())),
            ("PY_BASE", str(Path(sys.base_prefix).resolve())),
            ("WORK", workspace.resolve()),
            ("INPUT", (workspace / "input").resolve()),
        ):
            prefix.extend(("-D", f"{name}={value}"))
        prefix.extend(("-p", _CANDIDATE_SEATBELT_PROFILE))
        command = [*prefix, sys.executable, "-I", "-B", str(script)]
    elif sys.platform.startswith("linux"):
        bwrap = shutil.which("bwrap")
        if bwrap is None:
            raise SandboxUnavailable("Linux Bubblewrap is unavailable")
        command = [
            bwrap,
            "--die-with-parent",
            "--new-session",
            "--unshare-all",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--size",
            str(tmpfs_mb * 1024**2),
            "--tmpfs",
            "/tmp",
        ]
        bound: set[str] = set()
        for root in ("/usr", "/bin", "/lib", "/lib64", "/etc"):
            if Path(root).exists():
                command.extend(("--ro-bind", root, root))
                bound.add(str(Path(root).resolve()))
        for root in {Path(sys.prefix).resolve(), Path(sys.base_prefix).resolve()}:
            if root.exists() and not any(
                str(root) == item or str(root).startswith(item + os.sep)
                for item in bound
            ):
                command.extend(("--ro-bind", str(root), str(root)))
                bound.add(str(root))
        command.extend(
            (
                "--ro-bind",
                str(workspace),
                "/work",
                "--chdir",
                "/work",
                "--clearenv",
                "--setenv",
                "HOME",
                "/tmp",
                "--setenv",
                "TMPDIR",
                "/tmp",
                "--setenv",
                "PATH",
                "/usr/bin:/bin",
                sys.executable,
                "-I",
                "-B",
                "/work/candidate.py",
            )
        )
    else:
        raise SandboxUnavailable("no supported strict candidate sandbox is available")
    environment = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(workspace),
        "TMPDIR": str(workspace),
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    with tempfile.TemporaryFile() as output:
        try:
            process = subprocess.Popen(
                command,
                cwd=workspace,
                env=environment,
                stdin=None,
                stdout=output,
                stderr=None,
                close_fds=True,
                start_new_session=True,
            )
        except OSError as exc:
            raise SandboxUnavailable("candidate Seatbelt launch failed") from exc
        if child_process_groups_path is not None:
            child_process_groups_path.parent.mkdir(parents=True, exist_ok=True)
            staged = child_process_groups_path.with_suffix(".tmp")
            staged.write_text(json.dumps([process.pid]) + "\n", encoding="utf-8")
            os.replace(staged, child_process_groups_path)
        deadline = time.monotonic() + timeout
        max_output = output_mb * 1024**2
        memory_limit = memory_mb * 1024**2
        missing_memory_samples = 0
        while process.poll() is None:
            if os.fstat(output.fileno()).st_size > max_output:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
                raise ReferenceEvaluatorError("candidate exceeded output limit")
            if time.monotonic() >= deadline:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
                raise ReferenceEvaluatorError("candidate exceeded timeout")
            if sys.platform == "darwin":
                from aide.rsi.sandbox import SecureInterpreter

                resident = SecureInterpreter._macos_resident_bytes(process.pid)
                if resident is None:
                    missing_memory_samples += 1
                else:
                    missing_memory_samples = 0
                if missing_memory_samples >= 3 or (
                    resident is not None and resident > memory_limit
                ):
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
                    raise ReferenceEvaluatorError(
                        "candidate memory limit could not be enforced"
                    )
            time.sleep(0.02)
        if process.returncode != 0:
            raise ReferenceEvaluatorError("candidate sandbox failed")
        output.seek(0)
        return output.read(max_output + 1)


def _evaluate(request_path: Path, response_path: Path) -> None:
    request = json.loads(request_path.read_text(encoding="utf-8"))
    config_path = Path(request["evaluator_config_path"])
    config = json.loads(config_path.read_text(encoding="utf-8"))
    samples = _sample_ids(Path(request["split_manifest_path"]))
    scoring = config.get("scoring", {})
    if not isinstance(scoring, dict):
        raise ReferenceEvaluatorError("scoring must be an object")
    scorer_timeout = int(scoring.get("timeout_s", 30))
    if not 1 <= scorer_timeout <= 3600:
        raise ReferenceEvaluatorError("scoring timeout_s must be in [1, 3600]")
    metric_id = request["metric_id"]
    maximize = metric_id == "accuracy" or metric_id == "r2"
    if (
        metric_id
        not in {
            "accuracy",
            "mean_squared_error",
            "root_mean_squared_error",
            "mean_absolute_error",
            "r2",
        }
        or maximize is not request["metric_maximize"]
    ):
        raise ReferenceEvaluatorError("metric is outside the fixed scorer registry")
    prediction_bytes = _run_candidate(request, config, samples)
    output_dir = Path(request["output_dir"])
    output_dir.mkdir(parents=True, exist_ok=True)
    predictions_path = output_dir / "predictions.jsonl"
    predictions_path.write_bytes(prediction_bytes)

    with tempfile.TemporaryDirectory(prefix="aide-reference-score-") as temp:
        score_path = Path(temp) / "score.json"
        score_request_path = Path(temp) / "score-request.json"
        score_request_path.write_text(
            json.dumps(
                {
                    "labels_path": str(
                        Path(request["dataset_dir"]) / config["labels_file"]
                    ),
                    "predictions_path": str(predictions_path),
                    "evaluation_sample_ids": list(samples),
                    "scoring": scoring,
                    "metric_id": metric_id,
                    "score_path": str(score_path),
                },
                sort_keys=True,
            )
        )
        package_root = Path(__file__).resolve().parents[2]
        command = [
            sys.executable,
            "-I",
            "-c",
            (
                "import runpy,sys; sys.path.insert(0,sys.argv.pop(1)); "
                "sys.argv=['aide.rsi.reference_evaluator',*sys.argv[1:]]; "
                "runpy.run_module('aide.rsi.reference_evaluator',run_name='__main__')"
            ),
            str(package_root),
            "--score-request",
            str(score_request_path),
        ]
        timeout = scorer_timeout
        completed = subprocess.run(
            command,
            cwd=temp,
            env={"PATH": "/usr/bin:/bin", "PYTHONNOUSERSITE": "1"},
            stdin=None,
            stdout=None,
            stderr=None,
            close_fds=True,
            timeout=timeout,
            check=False,
        )
        if completed.returncode != 0 or not score_path.is_file():
            raise ReferenceEvaluatorError("trusted scorer failed")
        score = json.loads(score_path.read_text(encoding="utf-8"))["score"]

    response = {key: request[key] for key in IDENTITY_KEYS}
    response.update(
        schema_version=1,
        score=float(score),
        predictions_sha256=hashlib.sha256(prediction_bytes).hexdigest(),
    )
    response_path.write_text(json.dumps(response, sort_keys=True) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--request")
    parser.add_argument("--response")
    parser.add_argument("--score-request")
    args = parser.parse_args()
    if args.score_request:
        _score_child(Path(args.score_request))
    elif args.request and args.response:
        _evaluate(Path(args.request), Path(args.response))
    else:
        parser.error("provide --request and --response, or --score-request")


if __name__ == "__main__":
    main()
