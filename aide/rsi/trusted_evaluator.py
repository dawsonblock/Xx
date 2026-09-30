"""Pinned, host-owned task evaluator protocol for live RSI outcomes.

The evaluator bundle is operator supplied and must run the candidate against its
own fixed data/split contract. It never receives the host attestation key. The
host validates all pinned identities and signs the finite result after return.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import math
import os
import signal
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .artifacts import load_candidate
from .evidence import attest_evaluation


class TrustedEvaluatorError(RuntimeError):
    """A pinned evaluator could not produce a valid trusted record."""


def _unique_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def file_sha256(path: str | Path) -> str:
    path = Path(path)
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def tree_sha256(path: str | Path) -> str:
    """Hash a directory deterministically and refuse symlinks/special files."""
    path = Path(path)
    if not path.is_dir() or path.is_symlink():
        raise TrustedEvaluatorError(f"expected a real directory: {path}")
    digest = hashlib.sha256()
    for item in sorted(
        path.rglob("*"), key=lambda entry: entry.relative_to(path).as_posix()
    ):
        relative = item.relative_to(path).as_posix().encode("utf-8")
        if item.is_symlink():
            raise TrustedEvaluatorError(
                f"symlink in pinned directory: {relative.decode()}"
            )
        if item.is_dir():
            digest.update(b"D\0" + relative + b"\0")
        elif item.is_file():
            digest.update(b"F\0" + relative + b"\0")
            digest.update(item.stat().st_size.to_bytes(8, "big"))
            digest.update(bytes.fromhex(file_sha256(item)))
        else:
            raise TrustedEvaluatorError(
                f"unsupported file in pinned directory: {relative.decode()}"
            )
    return digest.hexdigest()


def _require_read_only_tree(path: Path) -> None:
    for item in [path, *path.rglob("*")]:
        if item.is_symlink() or stat.S_IMODE(item.stat().st_mode) & 0o222:
            raise TrustedEvaluatorError(
                "trusted evaluator dataset must be a read-only tree"
            )


def _stable_digest(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _required_path(config: Any, name: str, *, directory: bool = False) -> Path:
    value = getattr(config, name, None)
    if not isinstance(value, (str, Path)) or not str(value).strip():
        raise TrustedEvaluatorError(f"trusted evaluator requires {name}")
    path = Path(value).expanduser().resolve(strict=True)
    if directory and not path.is_dir():
        raise TrustedEvaluatorError(f"trusted evaluator {name} must be a directory")
    if not directory and not path.is_file():
        raise TrustedEvaluatorError(f"trusted evaluator {name} must be a file")
    return path


@dataclass(frozen=True)
class TrustedEvaluation:
    score: float
    provenance: dict[str, Any]


class TrustedEvaluator:
    """Invoke a content-pinned evaluator bundle and attest its result on-host."""

    def __init__(
        self, config: Any, *, task_description: Any, artifact_root: str | Path
    ):
        self.bundle_dir = _required_path(config, "bundle_dir", directory=True)
        self.bundle_sha256 = str(getattr(config, "bundle_sha256", "") or "").lower()
        self.config_path = _required_path(config, "config_path")
        self.config_sha256 = str(getattr(config, "config_sha256", "") or "").lower()
        self.dataset_dir = _required_path(config, "dataset_dir", directory=True)
        self.dataset_sha256 = str(getattr(config, "dataset_sha256", "") or "").lower()
        self.split_path = _required_path(config, "split_manifest")
        self.split_sha256 = str(getattr(config, "split_sha256", "") or "").lower()
        self.environment_manifest = _required_path(config, "environment_manifest")
        expected_environment_manifest = str(
            getattr(config, "environment_manifest_sha256", "") or ""
        ).lower()
        self.environment_manifest_sha256 = expected_environment_manifest
        self.metric_id = str(getattr(config, "metric_id", "") or "").strip()
        self.metric_maximize = getattr(config, "metric_maximize", None)
        self.timeout_s = float(getattr(config, "timeout_s", 0) or 0)
        self.artifact_root = Path(artifact_root).resolve()
        self.task_sha256 = _stable_digest(task_description)

        entrypoint = str(getattr(config, "entrypoint", "evaluate.py") or "evaluate.py")
        relative_entrypoint = Path(entrypoint)
        if relative_entrypoint.is_absolute() or ".." in relative_entrypoint.parts:
            raise TrustedEvaluatorError(
                "evaluator entrypoint must stay inside its bundle"
            )
        self.entrypoint = (self.bundle_dir / relative_entrypoint).resolve(strict=True)
        if not self.entrypoint.is_file() or not self.entrypoint.is_relative_to(
            self.bundle_dir
        ):
            raise TrustedEvaluatorError("evaluator entrypoint is not a bundle file")
        self.evaluator_sha256 = _stable_digest(
            {
                "bundle_sha256": self.bundle_sha256,
                "entrypoint": relative_entrypoint.as_posix(),
            }
        )

        for name, value in (
            ("bundle_sha256", self.bundle_sha256),
            ("config_sha256", self.config_sha256),
            ("dataset_sha256", self.dataset_sha256),
            ("split_sha256", self.split_sha256),
            ("environment_manifest_sha256", expected_environment_manifest),
        ):
            if len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
                raise TrustedEvaluatorError(f"trusted evaluator requires pinned {name}")
        if not self.metric_id or not isinstance(self.metric_maximize, bool):
            raise TrustedEvaluatorError(
                "trusted evaluator requires a fixed metric and direction"
            )
        if not math.isfinite(self.timeout_s) or not 0 < self.timeout_s <= 86400:
            raise TrustedEvaluatorError(
                "trusted evaluator timeout_s must be in (0, 86400]"
            )
        if (
            not os.environ.get("AIDE_RSI_EVALUATION_HMAC_KEY")
            or len(os.environ["AIDE_RSI_EVALUATION_HMAC_KEY"].encode("utf-8")) < 32
        ):
            raise TrustedEvaluatorError(
                "AIDE_RSI_EVALUATION_HMAC_KEY must contain at least 32 bytes"
            )

        self._verify_inputs(expected_environment_manifest)
        _require_read_only_tree(self.dataset_dir)
        python_path = Path(sys.executable).resolve(strict=True)
        self.environment_sha256 = _stable_digest(
            {
                "manifest_sha256": expected_environment_manifest,
                "python_executable_sha256": file_sha256(python_path),
                "python_version": sys.version,
                "installed_distributions": sorted(
                    (
                        (dist.metadata.get("Name", "").lower(), dist.version)
                        for dist in importlib.metadata.distributions()
                    ),
                    key=lambda item: item[0],
                ),
            }
        )
        self.identity = _stable_digest(self._identity_fields())

    def _verify_inputs(
        self, expected_environment_manifest: str, *, verify_dataset: bool = True
    ) -> None:
        try:
            actuals = {
                "bundle_sha256": tree_sha256(self.bundle_dir),
                "config_sha256": file_sha256(self.config_path),
                "split_sha256": file_sha256(self.split_path),
                "environment_manifest_sha256": file_sha256(self.environment_manifest),
            }
            if verify_dataset:
                actuals["dataset_sha256"] = tree_sha256(self.dataset_dir)
        except OSError as exc:
            raise TrustedEvaluatorError(
                "pinned evaluator inputs could not be read"
            ) from exc
        expected = {
            "bundle_sha256": self.bundle_sha256,
            "config_sha256": self.config_sha256,
            "split_sha256": self.split_sha256,
            "environment_manifest_sha256": expected_environment_manifest,
        }
        if verify_dataset:
            expected["dataset_sha256"] = self.dataset_sha256
        for name, actual in actuals.items():
            if actual != expected[name]:
                raise TrustedEvaluatorError(
                    f"trusted evaluator {name} does not match pin"
                )

    def _identity_fields(self) -> dict[str, Any]:
        return {
            "task_sha256": self.task_sha256,
            "evaluator_sha256": self.evaluator_sha256,
            "evaluator_config_sha256": self.config_sha256,
            "dataset_sha256": self.dataset_sha256,
            "split_sha256": self.split_sha256,
            "environment_sha256": self.environment_sha256,
            "metric_id": self.metric_id,
            "metric_maximize": self.metric_maximize,
        }

    def evaluate(self, candidate_sha256: str) -> TrustedEvaluation:
        # The potentially large hidden dataset is content-hashed at startup.
        # Require it to be operator-mounted read-only, then recheck the smaller
        # evaluator/control inputs for each candidate.
        self._verify_inputs(self.environment_manifest_sha256, verify_dataset=False)
        try:
            candidate_source = load_candidate(candidate_sha256, self.artifact_root)
        except (OSError, ValueError, UnicodeDecodeError) as exc:
            raise TrustedEvaluatorError(
                "candidate artifact is missing or corrupt"
            ) from exc
        if (
            hashlib.sha256(candidate_source.encode("utf-8")).hexdigest()
            != candidate_sha256
        ):
            raise TrustedEvaluatorError("candidate source digest changed")

        with tempfile.TemporaryDirectory(prefix="aide-rsi-eval-") as temp:
            temp_dir = Path(temp)
            request_path = temp_dir / "request.json"
            response_path = temp_dir / "response.json"
            output_dir = temp_dir / "predictions"
            output_dir.mkdir()
            request = {
                "schema_version": 1,
                "candidate_sha256": candidate_sha256,
                "candidate_path": str(
                    self.artifact_root
                    / "sha256"
                    / candidate_sha256[:2]
                    / f"{candidate_sha256}.py"
                ),
                "task_sha256": self.task_sha256,
                "evaluator_sha256": self.evaluator_sha256,
                "evaluator_config_sha256": self.config_sha256,
                "evaluator_config_path": str(self.config_path),
                "dataset_sha256": self.dataset_sha256,
                "dataset_dir": str(self.dataset_dir),
                "split_sha256": self.split_sha256,
                "split_manifest_path": str(self.split_path),
                "environment_sha256": self.environment_sha256,
                "metric_id": self.metric_id,
                "metric_maximize": self.metric_maximize,
                "output_dir": str(output_dir),
            }
            request_path.write_text(json.dumps(request, sort_keys=True) + "\n")
            environment = {
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "HOME": str(temp_dir),
                "TMPDIR": str(temp_dir),
                "PYTHONNOUSERSITE": "1",
            }
            try:
                process = subprocess.Popen(
                    [
                        sys.executable,
                        "-I",
                        "-c",
                        "import runpy,sys; bundle,entry,*args=sys.argv[1:]; "
                        "sys.path.insert(0,bundle); sys.argv=[entry,*args]; "
                        "runpy.run_path(entry,run_name='__main__')",
                        str(self.bundle_dir),
                        str(self.entrypoint),
                        "--request",
                        str(request_path),
                        "--response",
                        str(response_path),
                    ],
                    cwd=temp_dir,
                    env=environment,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    close_fds=True,
                    start_new_session=True,
                )
                try:
                    return_code = process.wait(timeout=self.timeout_s)
                except subprocess.TimeoutExpired as exc:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait()
                    raise TrustedEvaluatorError(
                        "pinned evaluator exceeded its timeout"
                    ) from exc
                if return_code != 0:
                    raise TrustedEvaluatorError("pinned evaluator returned nonzero")
            except OSError as exc:
                raise TrustedEvaluatorError(
                    "pinned evaluator execution failed"
                ) from exc

            if response_path.is_symlink() or not response_path.is_file():
                raise TrustedEvaluatorError(
                    "pinned evaluator did not return a regular response file"
                )
            try:
                if response_path.stat().st_size > 64 * 1024:
                    raise TrustedEvaluatorError(
                        "pinned evaluator response exceeded 64 KiB"
                    )
                result = json.loads(
                    response_path.read_text(encoding="utf-8"),
                    object_pairs_hook=_unique_json_object,
                )
            except (
                OSError,
                UnicodeDecodeError,
                json.JSONDecodeError,
                ValueError,
            ) as exc:
                raise TrustedEvaluatorError(
                    "pinned evaluator returned invalid JSON"
                ) from exc

            required = {
                "schema_version",
                "candidate_sha256",
                "task_sha256",
                "evaluator_sha256",
                "evaluator_config_sha256",
                "dataset_sha256",
                "split_sha256",
                "environment_sha256",
                "metric_id",
                "metric_maximize",
                "score",
                "predictions_sha256",
            }
            if not isinstance(result, dict) or set(result) != required:
                raise TrustedEvaluatorError(
                    "pinned evaluator response has an invalid schema"
                )
            expected = {
                **self._identity_fields(),
                "candidate_sha256": candidate_sha256,
                "schema_version": 1,
            }
            if any(result.get(key) != value for key, value in expected.items()):
                raise TrustedEvaluatorError(
                    "pinned evaluator response identity mismatch"
                )
            raw_score = result["score"]
            if isinstance(raw_score, bool) or not isinstance(raw_score, (int, float)):
                raise TrustedEvaluatorError("pinned evaluator score is not numeric")
            score = float(raw_score)
            if not math.isfinite(score):
                raise TrustedEvaluatorError("pinned evaluator score is not finite")
            predictions_sha256 = result["predictions_sha256"]
            if (
                not isinstance(predictions_sha256, str)
                or len(predictions_sha256) != 64
                or any(c not in "0123456789abcdef" for c in predictions_sha256)
            ):
                raise TrustedEvaluatorError(
                    "pinned evaluator prediction digest is invalid"
                )
            predictions_path = output_dir / "predictions.jsonl"
            if predictions_path.is_symlink() or not predictions_path.is_file():
                raise TrustedEvaluatorError(
                    "pinned evaluator did not write predictions.jsonl"
                )
            if file_sha256(predictions_path) != predictions_sha256:
                raise TrustedEvaluatorError(
                    "pinned evaluator prediction digest does not match output"
                )

            try:
                self._verify_inputs(
                    self.environment_manifest_sha256, verify_dataset=False
                )
            except TrustedEvaluatorError as exc:
                raise TrustedEvaluatorError(
                    "pinned evaluator inputs changed during evaluation"
                ) from exc
            try:
                load_candidate(candidate_sha256, self.artifact_root)
            except (OSError, ValueError, UnicodeDecodeError) as exc:
                raise TrustedEvaluatorError(
                    "candidate artifact changed during trusted evaluation"
                ) from exc

        provenance = {
            **self._identity_fields(),
            "candidate_sha256": candidate_sha256,
            "predictions_sha256": predictions_sha256,
        }
        try:
            attested = attest_evaluation(provenance, score)
        except ValueError as exc:
            raise TrustedEvaluatorError(
                "host evaluation attestation could not be created"
            ) from exc
        return TrustedEvaluation(score=score, provenance=attested)


def create_trusted_evaluator(
    config: Any, *, task_description: Any, artifact_root: str | Path
):
    """Build the evaluator only when explicitly enabled in RSI configuration."""
    if not bool(getattr(config, "enabled", False)):
        return None
    return TrustedEvaluator(
        config, task_description=task_description, artifact_root=artifact_root
    )
