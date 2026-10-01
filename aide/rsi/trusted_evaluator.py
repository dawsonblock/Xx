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
import platform
import resource
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .artifacts import load_candidate, store_evaluation_artifact
from .evidence import attest_evaluation, evaluation_record_bytes

REFERENCE_EVALUATOR_ENTRYPOINT = "__aide_reference__"


class TrustedEvaluatorError(RuntimeError):
    """A pinned evaluator could not produce a valid trusted record."""


def _effective_resource_limit(name: str, requested: int) -> int:
    """Cap requested limits to the host hard limit before passing them to a child."""
    resource_id = getattr(resource, name, None)
    if resource_id is None:
        return requested
    try:
        _, hard_limit = resource.getrlimit(resource_id)
    except (OSError, ValueError):
        return requested
    if hard_limit == resource.RLIM_INFINITY:
        return requested
    return min(requested, int(hard_limit))


def canonical_evaluation_sample_ids(path: str | Path) -> tuple[str, ...] | None:
    """Read normalized sample IDs from a split manifest when supplied."""
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TrustedEvaluatorError("split manifest is not valid JSON") from exc
    values = raw.get("evaluation_sample_ids") if isinstance(raw, dict) else None
    if values is None:
        return None
    if not isinstance(values, list) or not values:
        raise TrustedEvaluatorError("evaluation_sample_ids must be a nonempty list")
    normalized = []
    for value in values:
        if not isinstance(value, str) or not value.strip():
            raise TrustedEvaluatorError(
                "evaluation sample IDs must be nonempty strings"
            )
        normalized.append(unicodedata.normalize("NFC", value.strip()))
    if len(set(normalized)) != len(normalized):
        raise TrustedEvaluatorError(
            "evaluation sample IDs must be unique after normalization"
        )
    return tuple(sorted(normalized))


def evaluation_sample_overlap(
    left: tuple[str, ...] | None, right: tuple[str, ...] | None
) -> tuple[str, ...] | None:
    """Return shared sample IDs, or None when either population is unverified."""
    if left is None or right is None:
        return None
    return tuple(sorted(set(left) & set(right)))


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


def _python_source_tree_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    for item in sorted(path.rglob("*.py")):
        if item.is_symlink():
            raise TrustedEvaluatorError("symlink in first-party evaluator source")
        relative = item.relative_to(path).as_posix().encode("utf-8")
        digest.update(b"F\0" + relative + b"\0")
        digest.update(bytes.fromhex(file_sha256(item)))
    return digest.hexdigest()


def _stage_reference_package(package_root: Path, destination: Path) -> Path:
    source = package_root / "aide"
    if not source.is_dir() or source.is_symlink():
        raise TrustedEvaluatorError("first-party evaluator package is unavailable")
    target = destination / "aide"
    for item in source.rglob("*.py"):
        if item.is_symlink():
            raise TrustedEvaluatorError("symlink in first-party evaluator package")
        relative = item.relative_to(source)
        staged = target / relative
        staged.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(item, staged)
        staged.chmod(0o444)
    for directory in sorted((p for p in target.rglob("*") if p.is_dir()), reverse=True):
        directory.chmod(0o555)
    target.chmod(0o555)
    return target


def _require_read_only_tree(path: Path, *, description: str) -> None:
    for item in [path, *path.rglob("*")]:
        if item.is_symlink() or stat.S_IMODE(item.stat().st_mode) & 0o222:
            raise TrustedEvaluatorError(f"{description} must be a read-only tree")


def _scratch_size(path: Path) -> int:
    """Return regular-file bytes in evaluator scratch space, rejecting links."""
    total = 0
    for item in path.rglob("*"):
        try:
            mode = item.lstat().st_mode
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(mode) or not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
            return 1 << 63
        if stat.S_ISREG(mode):
            total += item.stat().st_size
    return total


def _kill_process_group(
    process: subprocess.Popen,
    *,
    additional_process_groups_path: Path | None = None,
) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except PermissionError:
        # On macOS a Seatbelt-launched evaluator may make its process group
        # unaddressable while the direct child remains signalable.
        try:
            process.send_signal(signal.SIGKILL)
        except ProcessLookupError:
            pass
    process.wait()
    if additional_process_groups_path is not None:
        try:
            process_groups = json.loads(
                additional_process_groups_path.read_text(encoding="utf-8")
            )
        except FileNotFoundError:
            return
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            raise TrustedEvaluatorError("nested process group record is invalid")
        if not isinstance(process_groups, list):
            raise TrustedEvaluatorError("nested process group record is invalid")
        for process_group in process_groups:
            if (
                isinstance(process_group, bool)
                or not isinstance(process_group, int)
                or process_group <= 1
            ):
                raise TrustedEvaluatorError("nested process group record is invalid")
            try:
                os.killpg(process_group, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except PermissionError:
                # A newly sandboxed macOS group can reject group signaling;
                # its session leader PID is the recorded process group ID.
                try:
                    os.kill(process_group, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        additional_process_groups_path.unlink(missing_ok=True)


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


_EVALUATOR_SEATBELT_PROFILE = """(version 1)
(deny default)
(allow process-exec)
(allow process-fork)
(allow file-read-metadata (subpath "/"))
(allow file-read*
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
    (literal "/etc/localtime")
    (literal "/dev/null")
    (literal "/dev/urandom")
    (subpath (param "BUNDLE"))
    (subpath (param "DATASET"))
    (subpath (param "CONFIG"))
    (subpath (param "SPLIT"))
    (subpath (param "CANDIDATE"))
    (subpath (param "SCRATCH")))
(allow file-write* (subpath (param "SCRATCH")))
(allow sysctl-read)
"""


_EVALUATOR_WRAPPER = """import resource, runpy, sys
file_limit, cpu_limit, memory_limit = map(int, sys.argv[1:4])
process_limit, descriptor_limit = map(int, sys.argv[4:6])
resource.setrlimit(resource.RLIMIT_FSIZE, (file_limit, file_limit))
resource.setrlimit(resource.RLIMIT_CPU, (cpu_limit, cpu_limit))
resource.setrlimit(resource.RLIMIT_NPROC, (process_limit, process_limit))
resource.setrlimit(resource.RLIMIT_NOFILE, (descriptor_limit, descriptor_limit))
if sys.platform.startswith("linux"):
    resource.setrlimit(resource.RLIMIT_AS, (memory_limit, memory_limit))
bundle, entry, *args = sys.argv[6:]
sys.path.insert(0, bundle)
sys.argv = [entry, *args]
runpy.run_path(entry, run_name="__main__")
"""


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
        self.evaluation_sample_ids = canonical_evaluation_sample_ids(self.split_path)
        self.environment_manifest = _required_path(config, "environment_manifest")
        expected_environment_manifest = str(
            getattr(config, "environment_manifest_sha256", "") or ""
        ).lower()
        self.environment_manifest_sha256 = expected_environment_manifest
        self.metric_id = str(getattr(config, "metric_id", "") or "").strip()
        self.metric_maximize = getattr(config, "metric_maximize", None)
        self.timeout_s = float(getattr(config, "timeout_s", 0) or 0)
        self.max_output_bytes = int(getattr(config, "max_output_mb", 64) or 0) * 1024**2
        self.max_memory_bytes = (
            int(getattr(config, "max_memory_mb", 4096) or 0) * 1024**2
        )
        self.max_processes = int(getattr(config, "max_processes", 2048) or 0)
        self.max_open_files = int(getattr(config, "max_open_files", 256) or 0)
        self.sandbox_backend = self._resolve_sandbox_backend(
            str(getattr(config, "sandbox_backend", "auto") or "auto").lower()
        )
        self.evaluator_path = f"{Path(sys.executable).parent}:/usr/bin:/bin"
        self.artifact_root = Path(artifact_root).resolve()
        self.task_sha256 = _stable_digest(task_description)

        entrypoint = str(getattr(config, "entrypoint", "evaluate.py") or "evaluate.py")
        self.reference_evaluator = entrypoint == REFERENCE_EVALUATOR_ENTRYPOINT
        self.evaluation_sample_content_sha256: frozenset[str] | None = None
        self.evaluation_sample_public_input_sha256: frozenset[str] | None = None
        if self.reference_evaluator and self.evaluation_sample_ids is not None:
            try:
                from .reference_evaluator import sample_identity_sha256

                pinned_config = json.loads(self.config_path.read_text(encoding="utf-8"))
                (
                    self.evaluation_sample_public_input_sha256,
                    self.evaluation_sample_content_sha256,
                ) = sample_identity_sha256(
                    self.dataset_dir, pinned_config, self.evaluation_sample_ids
                )
            except (
                OSError,
                UnicodeDecodeError,
                json.JSONDecodeError,
                ValueError,
                RuntimeError,
            ) as exc:
                raise TrustedEvaluatorError(
                    "reference evaluator sample content could not be pinned"
                ) from exc
        self.reference_package_root = Path(__file__).resolve().parents[2]
        if self.reference_evaluator:
            self.entrypoint = None
            self.reference_source_sha256 = _python_source_tree_sha256(
                self.reference_package_root / "aide"
            )
            evaluator_identity = {
                "bundle_sha256": self.bundle_sha256,
                "entrypoint": REFERENCE_EVALUATOR_ENTRYPOINT,
                "reference_source_sha256": self.reference_source_sha256,
            }
        else:
            relative_entrypoint = Path(entrypoint)
            if relative_entrypoint.is_absolute() or ".." in relative_entrypoint.parts:
                raise TrustedEvaluatorError(
                    "evaluator entrypoint must stay inside its bundle"
                )
            self.entrypoint = (self.bundle_dir / relative_entrypoint).resolve(
                strict=True
            )
            if not self.entrypoint.is_file() or not self.entrypoint.is_relative_to(
                self.bundle_dir
            ):
                raise TrustedEvaluatorError("evaluator entrypoint is not a bundle file")
            evaluator_identity = {
                "bundle_sha256": self.bundle_sha256,
                "entrypoint": relative_entrypoint.as_posix(),
            }
        self.evaluator_sha256 = _stable_digest(evaluator_identity)

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
        if not 1 <= self.max_output_bytes <= 4096 * 1024**2:
            raise TrustedEvaluatorError(
                "trusted evaluator max_output_mb must be in [1, 4096]"
            )
        if not 128 * 1024**2 <= self.max_memory_bytes <= 65536 * 1024**2:
            raise TrustedEvaluatorError(
                "trusted evaluator max_memory_mb must be in [128, 65536]"
            )
        if not 1 <= self.max_processes <= 65536:
            raise TrustedEvaluatorError("max_processes must be in [1, 65536]")
        if not 16 <= self.max_open_files <= 65536:
            raise TrustedEvaluatorError("max_open_files must be in [16, 65536]")
        # Hosted and managed macOS environments can have lower hard ceilings
        # than the configured maximum. Bind and apply the effective ceiling so
        # the wrapper cannot fail before the evaluator starts.
        self.max_processes = _effective_resource_limit(
            "RLIMIT_NPROC", self.max_processes
        )
        self.max_open_files = _effective_resource_limit(
            "RLIMIT_NOFILE", self.max_open_files
        )
        if (
            not os.environ.get("AIDE_RSI_EVALUATION_HMAC_KEY")
            or len(os.environ["AIDE_RSI_EVALUATION_HMAC_KEY"].encode("utf-8")) < 32
        ):
            raise TrustedEvaluatorError(
                "AIDE_RSI_EVALUATION_HMAC_KEY must contain at least 32 bytes"
            )

        self._verify_inputs(expected_environment_manifest)
        _require_read_only_tree(
            self.dataset_dir, description="trusted evaluator dataset"
        )
        python_path = Path(sys.executable).resolve(strict=True)
        self.environment_sha256 = _stable_digest(
            {
                "manifest_sha256": expected_environment_manifest,
                "python_executable_sha256": file_sha256(python_path),
                "python_version": sys.version,
                "platform": platform.platform(),
                "path": self.evaluator_path,
                "sandbox_backend": self.sandbox_backend,
                "evaluator_path": self.evaluator_path,
                "evaluation_limits": {
                    "timeout_s": self.timeout_s,
                    "max_output_bytes": self.max_output_bytes,
                    "max_memory_bytes": self.max_memory_bytes,
                    "max_processes": self.max_processes,
                    "max_open_files": self.max_open_files,
                },
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
        self.authority_identity = _stable_digest(self._authority_identity_fields())

    @staticmethod
    def _resolve_sandbox_backend(requested: str) -> str:
        if requested == "auto":
            if sys.platform == "darwin" and shutil.which("sandbox-exec"):
                return "seatbelt"
            if sys.platform.startswith("linux") and shutil.which("bwrap"):
                return "bubblewrap"
            raise TrustedEvaluatorError(
                "strict evaluator sandbox unavailable; install macOS sandbox-exec "
                "or Linux bubblewrap"
            )
        if requested == "seatbelt":
            if sys.platform != "darwin" or not shutil.which("sandbox-exec"):
                raise TrustedEvaluatorError(
                    "Seatbelt evaluator backend requires macOS sandbox-exec"
                )
            return requested
        if requested == "bubblewrap":
            if not sys.platform.startswith("linux") or not shutil.which("bwrap"):
                raise TrustedEvaluatorError(
                    "Bubblewrap evaluator backend requires Linux and bwrap"
                )
            return requested
        raise TrustedEvaluatorError(
            "trusted evaluator sandbox_backend must be auto, seatbelt, or bubblewrap"
        )

    def _evaluator_process(
        self,
        *,
        temp_dir: Path,
        candidate_path: Path,
        request: dict[str, Any],
    ) -> tuple[list[str], dict[str, str], dict[str, Any]]:
        """Build a fail-closed Seatbelt or Bubblewrap evaluator invocation."""
        if self.reference_evaluator:
            if (
                _python_source_tree_sha256(self.reference_package_root / "aide")
                != self.reference_source_sha256
            ):
                raise TrustedEvaluatorError(
                    "first-party evaluator source changed after it was pinned"
                )
            evaluator_root = temp_dir / "evaluator"
            evaluator_root.mkdir()
            _stage_reference_package(self.reference_package_root, evaluator_root)
            entrypoint_path = evaluator_root / "aide" / "rsi" / "reference_evaluator.py"
        else:
            evaluator_root = self.bundle_dir
            entrypoint_path = self.entrypoint
        if self.sandbox_backend == "seatbelt":
            request_paths = {
                "candidate_path": str(candidate_path),
                "evaluator_config_path": str(self.config_path),
                "dataset_dir": str(self.dataset_dir),
                "split_manifest_path": str(self.split_path),
                "output_dir": str(temp_dir / "predictions"),
            }
            bundle_path = str(evaluator_root)
            entrypoint = str(entrypoint_path)
            request_path = str(temp_dir / "request.json")
            response_path = str(temp_dir / "response.json")
            scratch_path = str(temp_dir)
            prefix = [shutil.which("sandbox-exec") or "sandbox-exec"]
            for name, value in (
                ("PY_PREFIX", sys.prefix),
                ("PY_BASE", sys.base_prefix),
                ("BUNDLE", evaluator_root),
                ("DATASET", self.dataset_dir),
                ("CONFIG", self.config_path),
                ("SPLIT", self.split_path),
                ("CANDIDATE", candidate_path.resolve()),
                ("SCRATCH", temp_dir.resolve()),
            ):
                prefix.extend(("-D", f"{name}={value}"))
            prefix.extend(("-p", _EVALUATOR_SEATBELT_PROFILE))
            home_path = scratch_path
        else:
            request_paths = {
                "candidate_path": "/candidate.py",
                "evaluator_config_path": "/task-config.json",
                "dataset_dir": "/hidden-data",
                "split_manifest_path": "/split-manifest.json",
                "output_dir": "/scratch/predictions",
            }
            bundle_path = "/evaluator"
            if self.reference_evaluator:
                entrypoint = "/evaluator/aide/rsi/reference_evaluator.py"
            else:
                entrypoint = (
                    Path(bundle_path) / self.entrypoint.relative_to(self.bundle_dir)
                ).as_posix()
            request_path = "/scratch/request.json"
            response_path = "/scratch/response.json"
            scratch_path = "/scratch"
            prefix = [
                shutil.which("bwrap") or "bwrap",
                "--die-with-parent",
                "--new-session",
                "--unshare-all",
                "--proc",
                "/proc",
                "--dev",
                "/dev",
                "--tmpfs",
                "/tmp",
            ]
            bound: set[str] = set()
            for root in ("/usr", "/bin", "/lib", "/lib64", "/etc"):
                if Path(root).exists():
                    prefix.extend(("--ro-bind", root, root))
                    bound.add(str(Path(root).resolve()))
            for runtime_path in {
                Path(sys.prefix).resolve(),
                Path(sys.base_prefix).resolve(),
            }:
                if runtime_path.exists() and not any(
                    str(runtime_path) == root
                    or str(runtime_path).startswith(root + os.sep)
                    for root in bound
                ):
                    prefix.extend(("--ro-bind", str(runtime_path), str(runtime_path)))
                    bound.add(str(runtime_path))
            prefix.extend(
                (
                    "--ro-bind",
                    str(evaluator_root),
                    "/evaluator",
                    "--ro-bind",
                    str(self.dataset_dir),
                    "/hidden-data",
                    "--ro-bind",
                    str(self.config_path),
                    "/task-config.json",
                    "--ro-bind",
                    str(self.split_path),
                    "/split-manifest.json",
                    "--ro-bind",
                    str(candidate_path),
                    "/candidate.py",
                    "--bind",
                    str(temp_dir),
                    "/scratch",
                    "--chdir",
                    "/scratch",
                    "--clearenv",
                    "--setenv",
                    "HOME",
                    "/tmp",
                    "--setenv",
                    "TMPDIR",
                    "/tmp",
                    "--setenv",
                    "PATH",
                    self.evaluator_path,
                )
            )
            home_path = "/tmp"

        child_request = {**request, **request_paths}
        if self.reference_evaluator:
            child_request["candidate_process_groups_path"] = str(
                temp_dir / "candidate_process_groups.json"
            )
            # This content-pinned adapter is the only evaluator allowed to run
            # outside the outer Seatbelt namespace: it must launch a nested
            # candidate sandbox, which macOS forbids from inside Seatbelt.
            command = [
                sys.executable,
                "-I",
                "-B",
                "-c",
                _EVALUATOR_WRAPPER,
                str(self.max_output_bytes),
                str(max(1, math.ceil(self.timeout_s))),
                str(self.max_memory_bytes),
                str(self.max_processes),
                str(self.max_open_files),
                bundle_path,
                entrypoint,
                "--request",
                request_path,
                "--response",
                response_path,
            ]
            return (
                command,
                {
                    "PATH": self.evaluator_path,
                    "HOME": str(temp_dir),
                    "TMPDIR": str(temp_dir),
                    "PYTHONNOUSERSITE": "1",
                    "PYTHONDONTWRITEBYTECODE": "1",
                },
                child_request,
            )
        command = [
            *prefix,
            sys.executable,
            "-I",
            "-B",
            "-c",
            _EVALUATOR_WRAPPER,
            str(self.max_output_bytes),
            str(max(1, math.ceil(self.timeout_s))),
            str(self.max_memory_bytes),
            str(self.max_processes),
            str(self.max_open_files),
            bundle_path,
            entrypoint,
            "--request",
            request_path,
            "--response",
            response_path,
        ]
        environment = {
            "PATH": self.evaluator_path,
            "HOME": home_path,
            "TMPDIR": home_path,
            "PYTHONNOUSERSITE": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        return command, environment, child_request

    def _verify_inputs(
        self, expected_environment_manifest: str, *, verify_dataset: bool = True
    ) -> None:
        _require_read_only_tree(self.bundle_dir, description="trusted evaluator bundle")
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

    def _authority_identity_fields(self) -> dict[str, Any]:
        """Stable evaluator/scoring authority, excluding rotating data shards."""
        return {
            "task_sha256": self.task_sha256,
            "evaluator_sha256": self.evaluator_sha256,
            "evaluator_config_sha256": self.config_sha256,
            "environment_sha256": self.environment_sha256,
            "metric_id": self.metric_id,
            "metric_maximize": self.metric_maximize,
        }

    def evaluate(self, candidate_sha256: str) -> TrustedEvaluation:
        self._verify_inputs(self.environment_manifest_sha256)
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

        with (
            tempfile.TemporaryDirectory(prefix="aide-rsi-eval-") as temp,
            tempfile.TemporaryDirectory(prefix="aide-rsi-candidate-") as source_temp,
        ):
            temp_dir = Path(temp)
            request_path = temp_dir / "request.json"
            response_path = temp_dir / "response.json"
            child_process_groups_path = (
                temp_dir / "candidate_process_groups.json"
                if self.reference_evaluator
                else None
            )
            candidate_path = Path(source_temp) / "candidate.py"
            candidate_bytes = candidate_source.encode("utf-8")
            candidate_path.write_bytes(candidate_bytes)
            candidate_path.chmod(0o444)
            output_dir = temp_dir / "predictions"
            output_dir.mkdir()
            request = {
                "schema_version": 1,
                "candidate_sha256": candidate_sha256,
                "candidate_path": str(candidate_path),
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
                "max_processes": self.max_processes,
                "max_open_files": self.max_open_files,
                "max_memory_bytes": self.max_memory_bytes,
                "output_dir": str(output_dir),
            }
            command, environment, child_request = self._evaluator_process(
                temp_dir=temp_dir,
                candidate_path=candidate_path,
                request=request,
            )
            request_path.write_text(json.dumps(child_request, sort_keys=True) + "\n")
            resident_reader = None
            if self.sandbox_backend == "seatbelt":
                from .sandbox import SecureInterpreter

                resident_reader = SecureInterpreter._macos_resident_bytes
            missing_memory_samples = 0
            try:
                process = subprocess.Popen(
                    command,
                    cwd=(temp_dir if self.sandbox_backend == "seatbelt" else "/"),
                    env=environment,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    close_fds=True,
                    start_new_session=True,
                )
                deadline = time.monotonic() + self.timeout_s
                while process.poll() is None:
                    if _scratch_size(temp_dir) > self.max_output_bytes:
                        _kill_process_group(
                            process,
                            additional_process_groups_path=child_process_groups_path,
                        )
                        raise TrustedEvaluatorError(
                            "pinned evaluator exceeded its scratch output limit"
                        )
                    if resident_reader is not None:
                        resident_bytes = resident_reader(process.pid)
                        if resident_bytes is None:
                            missing_memory_samples += 1
                            if missing_memory_samples >= 3:
                                _kill_process_group(
                                    process,
                                    additional_process_groups_path=child_process_groups_path,
                                )
                                raise TrustedEvaluatorError(
                                    "macOS evaluator memory monitoring failed"
                                )
                        elif resident_bytes > self.max_memory_bytes:
                            _kill_process_group(
                                process,
                                additional_process_groups_path=child_process_groups_path,
                            )
                            raise TrustedEvaluatorError(
                                "pinned evaluator exceeded its memory limit"
                            )
                        else:
                            missing_memory_samples = 0
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        _kill_process_group(
                            process,
                            additional_process_groups_path=child_process_groups_path,
                        )
                        raise TrustedEvaluatorError(
                            "pinned evaluator exceeded its timeout"
                        )
                    try:
                        process.wait(timeout=min(0.05, remaining))
                    except subprocess.TimeoutExpired:
                        continue
                return_code = process.returncode
                # A bundle may exit successfully while a child it created keeps
                # writing into the scratch directory. The evaluator owns one
                # process group, so end that group before validating its outputs.
                _kill_process_group(
                    process,
                    additional_process_groups_path=child_process_groups_path,
                )
                if return_code != 0:
                    if _scratch_size(temp_dir) >= self.max_output_bytes:
                        raise TrustedEvaluatorError(
                            "pinned evaluator exceeded its scratch output limit"
                        )
                    raise TrustedEvaluatorError("pinned evaluator returned nonzero")
            except OSError as exc:
                raise TrustedEvaluatorError(
                    "pinned evaluator execution failed"
                ) from exc

            try:
                candidate_mode = candidate_path.lstat().st_mode
            except OSError as exc:
                raise TrustedEvaluatorError(
                    "candidate snapshot changed during trusted evaluation"
                ) from exc
            if not stat.S_ISREG(candidate_mode):
                raise TrustedEvaluatorError(
                    "candidate snapshot changed during trusted evaluation"
                )
            try:
                candidate_snapshot_digest = file_sha256(candidate_path)
            except OSError as exc:
                raise TrustedEvaluatorError(
                    "candidate snapshot changed during trusted evaluation"
                ) from exc
            if candidate_snapshot_digest != candidate_sha256:
                raise TrustedEvaluatorError(
                    "candidate snapshot changed during trusted evaluation"
                )

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
            predictions_bytes = predictions_path.read_bytes()
            if hashlib.sha256(predictions_bytes).hexdigest() != predictions_sha256:
                raise TrustedEvaluatorError(
                    "pinned evaluator prediction digest does not match output"
                )
            try:
                stored_predictions_sha256 = store_evaluation_artifact(
                    predictions_bytes,
                    self.artifact_root,
                    kind="predictions",
                    suffix=".jsonl",
                )
            except (OSError, ValueError) as exc:
                raise TrustedEvaluatorError(
                    "predictions artifact could not be stored"
                ) from exc
            if stored_predictions_sha256 != predictions_sha256:
                raise TrustedEvaluatorError(
                    "stored prediction artifact digest mismatch"
                )

            try:
                self._verify_inputs(self.environment_manifest_sha256)
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
        record_bytes = evaluation_record_bytes(attested, score)
        try:
            record_digest = store_evaluation_artifact(
                record_bytes,
                self.artifact_root,
                kind="evaluations",
                suffix=".json",
            )
        except (OSError, ValueError) as exc:
            raise TrustedEvaluatorError(
                "evaluation record could not be stored"
            ) from exc
        if attested.get("evaluation_record_sha256") != record_digest:
            raise TrustedEvaluatorError(
                "evaluation record digest changed before storage"
            )
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
