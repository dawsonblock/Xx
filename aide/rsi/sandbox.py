from __future__ import annotations

import ctypes
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path


class SandboxUnavailable(RuntimeError):
    pass


class _MacProcTaskInfo(ctypes.Structure):
    # Matches proc_taskinfo in the macOS SDK's sys/proc_info.h.
    _fields_ = [
        ("virtual_size", ctypes.c_uint64),
        ("resident_size", ctypes.c_uint64),
        ("times", ctypes.c_uint64 * 4),
        ("rest", ctypes.c_int32 * 11),
    ]


@lru_cache(maxsize=1)
def _macos_libproc():
    libproc = ctypes.CDLL("/usr/lib/libproc.dylib")
    libproc.proc_pidinfo.argtypes = [
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_uint64,
        ctypes.c_void_p,
        ctypes.c_int,
    ]
    libproc.proc_pidinfo.restype = ctypes.c_int
    return libproc


# Seatbelt profiles are evaluated by the macOS kernel. Keep path values in
# sandbox-exec parameters rather than interpolating filesystem names into SBPL.
_SEATBELT_PROFILE = """(version 1)
(deny default)
(allow process-exec)
(allow file-read-metadata (subpath "/"))
(allow file-read-data
    (literal "/")
    (subpath (param "PY_PREFIX"))
    (subpath (param "PY_BASE"))
    (subpath (param "BREW_CELLAR"))
    (subpath (param "BREW_OPT"))
    (subpath (param "WORK"))
    (subpath (param "INPUT")))
(allow file-write* (subpath (param "WORK")))
(allow sysctl-read)
"""


@dataclass(frozen=True)
class SandboxLimits:
    """Resource envelope for strict candidate execution."""

    memory_mb: int = 32768
    seatbelt_memory_mb: int = 1024
    cpu_seconds: int = 0
    file_size_mb: int = 2048
    workspace_mb: int = 2048
    max_output_mb: int = 16
    nproc: int = 128
    nofile: int = 256


class SecureInterpreter:
    """Fail-closed candidate executor.

    Strict mode supports three authority boundaries:

    * ``bubblewrap`` on Linux: user/pid/network/mount namespaces with read-only
      runtime/input and a disposable writable workspace.
    * ``container`` on any host with Docker/Podman: no network, read-only rootfs,
      dropped capabilities, no-new-privileges, bounded pids/memory, read-only task
      input, and one disposable writable workspace.
    * ``seatbelt`` on macOS: a deny-by-default local kernel profile, with only
      the Python runtime, task input, and disposable workspace readable.

    ``auto`` prefers bubblewrap on Linux, then an explicitly configured OCI
    image, then Seatbelt on macOS. Seatbelt availability is checked with live
    confinement probes before candidate execution.
    The process backend remains a trusted-code compatibility mode only.
    """

    def __init__(
        self,
        base_workspace: str | Path,
        *,
        timeout: int = 3600,
        mode: str = "strict",
        backend: str = "auto",
        container_runtime: str = "auto",
        container_image: str | None = None,
        agent_file_name: str = "runfile.py",
        format_tb_ipython: bool = False,
        allow_insecure_process: bool = False,
        limits: SandboxLimits | None = None,
    ):
        self.base_workspace = Path(base_workspace).resolve()
        self.timeout = int(timeout) if timeout is not None else 3600
        self.mode = str(mode).lower()
        self.backend_request = str(backend).lower()
        self.container_runtime_request = str(container_runtime).lower()
        self.container_image = str(container_image).strip() if container_image else None
        self.agent_file_name = str(agent_file_name)
        if (
            self.agent_file_name in {"", ".", ".."}
            or Path(self.agent_file_name).name != self.agent_file_name
        ):
            raise ValueError("agent_file_name must be a single file name")
        self.format_tb_ipython = bool(format_tb_ipython)
        self.allow_insecure_process = bool(allow_insecure_process)
        self.limits = limits or SandboxLimits(cpu_seconds=self.timeout)
        self._tmp_root = self.base_workspace / ".rsi_exec"
        self._tmp_root.mkdir(parents=True, exist_ok=True)
        self.backend = self._resolve_backend()
        if self.backend == "seatbelt":
            self._seatbelt_preflight()

    def _resolve_runtime(self) -> str | None:
        if self.container_runtime_request in {"docker", "podman"}:
            return shutil.which(self.container_runtime_request)
        if self.container_runtime_request not in {"auto", ""}:
            raise SandboxUnavailable(
                f"unsupported container runtime: {self.container_runtime_request}"
            )
        return shutil.which("docker") or shutil.which("podman")

    def _resolve_backend(self) -> str:
        if self.mode == "process":
            if not self.allow_insecure_process:
                raise SandboxUnavailable(
                    "process sandbox is not hostile-code containment; explicit opt-in required"
                )
            return "process"
        if self.mode != "strict":
            raise SandboxUnavailable(f"unsupported sandbox mode: {self.mode}")

        requested = self.backend_request
        if requested not in {"auto", "bubblewrap", "container", "seatbelt"}:
            raise SandboxUnavailable(f"unsupported strict sandbox backend: {requested}")

        bwrap_ok = (
            sys.platform.startswith("linux") and shutil.which("bwrap") is not None
        )
        runtime = self._resolve_runtime()
        container_ok = runtime is not None and bool(self.container_image)
        seatbelt_ok = (
            sys.platform == "darwin"
            and shutil.which("sandbox-exec") is not None
            and shutil.which("hdiutil") is not None
        )

        if requested == "bubblewrap":
            if not bwrap_ok:
                raise SandboxUnavailable(
                    "bubblewrap backend requested but Linux `bwrap` is unavailable"
                )
            return "bubblewrap"
        if requested == "container":
            if not container_ok:
                raise SandboxUnavailable(
                    "container backend requires Docker/Podman and rsi.sandbox.container_image"
                )
            return "container"
        if requested == "seatbelt":
            if not seatbelt_ok:
                raise SandboxUnavailable(
                    "Seatbelt backend requires macOS, sandbox-exec, and hdiutil"
                )
            return "seatbelt"
        if bwrap_ok:
            return "bubblewrap"
        if container_ok:
            return "container"
        if seatbelt_ok:
            return "seatbelt"
        raise SandboxUnavailable(
            "no strict sandbox backend is available. Install Linux bubblewrap, or configure "
            "Docker/Podman plus rsi.sandbox.container_image, or use macOS Seatbelt. "
            "Process mode requires explicit trusted-code opt-in."
        )

    def _seatbelt_command(self, work: Path, script: Path) -> list[str]:
        binary = shutil.which("sandbox-exec")
        if sys.platform != "darwin" or binary is None:
            raise SandboxUnavailable("macOS Seatbelt backend became unavailable")
        prefix = Path(sys.prefix).resolve()
        base = Path(sys.base_prefix).resolve()
        # Python installed by pyenv/uv may still load dylibs from Homebrew. Decide
        # from the host's available Homebrew roots, not from where Python itself
        # lives, so Seatbelt can load those linked runtime dependencies.
        brew_root = next(
            (
                root
                for root in (Path("/opt/homebrew"), Path("/usr/local"))
                if (root / "opt").is_dir() or (root / "Cellar").is_dir()
            ),
            None,
        )
        input_dir = self.base_workspace / "input"
        paths = {
            "PY_PREFIX": prefix,
            "PY_BASE": base,
            "BREW_CELLAR": brew_root / "Cellar" if brew_root else base,
            "BREW_OPT": brew_root / "opt" if brew_root else base,
            "WORK": work.resolve(),
            "INPUT": input_dir.resolve() if input_dir.exists() else work.resolve(),
        }
        cmd = [binary, "-p", _SEATBELT_PROFILE]
        for name, path in paths.items():
            cmd += ["-D", f"{name}={path}"]
        return cmd + [sys.executable, str(script)]

    @staticmethod
    def _seatbelt_env(work: Path) -> dict[str, str]:
        return {
            "HOME": str(work),
            "TMPDIR": str(work),
            "PATH": "/usr/bin:/bin",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
        }

    def _seatbelt_preflight(self) -> None:
        if self.limits.workspace_mb < 64:
            raise SandboxUnavailable("macOS workspace limit must be at least 64 MiB")
        if (
            self.limits.memory_mb <= 0
            or self.limits.seatbelt_memory_mb <= 0
            or self._macos_resident_bytes(os.getpid()) is None
        ):
            raise SandboxUnavailable("macOS candidate memory monitoring is unavailable")
        sentinel_fd, sentinel_name = tempfile.mkstemp(
            prefix=".rsi-seatbelt-probe-", dir=self._tmp_root
        )
        sentinel = Path(sentinel_name)
        try:
            with os.fdopen(sentinel_fd, "w") as stream:
                stream.write("private")
            with self._seatbelt_workspace(64) as work:
                probe = work / "probe.py"
                probe.write_text(
                    "import errno, socket, subprocess, sys\n"
                    "from pathlib import Path\n"
                    "work, sentinel = map(Path, sys.argv[1:])\n"
                    "(work / 'writable').write_text('ok')\n"
                    "def denied(action):\n"
                    "    try: action()\n"
                    "    except OSError as exc: return exc.errno in (errno.EPERM, errno.EACCES)\n"
                    "    return False\n"
                    "if not denied(lambda: sentinel.read_bytes()): raise SystemExit('host read allowed')\n"
                    "if not denied(lambda: sentinel.write_text('bad')): raise SystemExit('host write allowed')\n"
                    "if not denied(lambda: socket.create_connection(('127.0.0.1', 1), timeout=1)): raise SystemExit('network allowed')\n"
                    "if not denied(lambda: subprocess.run(['/usr/bin/true'], check=True)): raise SystemExit('spawn allowed')\n"
                    "print('seatbelt-ok')\n"
                )
                result = subprocess.run(
                    self._seatbelt_command(work, probe) + [str(work), str(sentinel)],
                    cwd=work,
                    env=self._seatbelt_env(work),
                    capture_output=True,
                    text=True,
                    timeout=15,
                    check=False,
                )
                if result.returncode != 0 or result.stdout.strip() != "seatbelt-ok":
                    raise SandboxUnavailable(
                        f"macOS Seatbelt confinement check failed (exit {result.returncode}): "
                        f"{result.stderr[-500:]}"
                    )
        except subprocess.TimeoutExpired as exc:
            raise SandboxUnavailable(
                "macOS Seatbelt confinement check timed out"
            ) from exc
        finally:
            sentinel.unlink(missing_ok=True)

    @staticmethod
    def _macos_resident_bytes(pid: int) -> int | None:
        try:
            info = _MacProcTaskInfo()
            size = _macos_libproc().proc_pidinfo(
                pid, 4, 0, ctypes.byref(info), ctypes.sizeof(info)
            )
            return int(info.resident_size) if size == ctypes.sizeof(info) else None
        except (OSError, AttributeError, ValueError, ctypes.ArgumentError):
            return None

    @contextmanager
    def _seatbelt_workspace(self, size_mb: int):
        slot = self._new_workspace()
        work = slot / "workspace"
        work.mkdir()
        image = slot / "workspace.sparseimage"
        mounted = False
        try:
            subprocess.run(
                [
                    "hdiutil",
                    "create",
                    "-size",
                    f"{int(size_mb)}m",
                    "-fs",
                    "HFS+X",
                    "-type",
                    "SPARSE",
                    "-volname",
                    "AIDERSI",
                    "-quiet",
                    str(image),
                ],
                capture_output=True,
                text=True,
                timeout=60,
                check=True,
            )
            subprocess.run(
                [
                    "hdiutil",
                    "attach",
                    "-nobrowse",
                    "-mountpoint",
                    str(work),
                    "-quiet",
                    str(image),
                ],
                capture_output=True,
                text=True,
                timeout=60,
                check=True,
            )
            mounted = os.path.ismount(work)
            if not mounted:
                raise SandboxUnavailable("macOS workspace image did not mount")
            yield work
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            raise SandboxUnavailable(
                "failed to create bounded macOS workspace"
            ) from exc
        finally:
            mounted = mounted or os.path.ismount(work)
            if mounted:
                for _ in range(3):
                    try:
                        subprocess.run(
                            ["hdiutil", "detach", "-quiet", str(work)],
                            capture_output=True,
                            timeout=30,
                            check=True,
                        )
                        break
                    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                        time.sleep(0.2)
                if os.path.ismount(work):
                    raise SandboxUnavailable(
                        f"failed to detach macOS workspace image at {work}"
                    )
            shutil.rmtree(slot)

    def _new_workspace(self) -> Path:
        return Path(tempfile.mkdtemp(prefix="candidate-", dir=self._tmp_root))

    def _limit_preexec(self, *, require_portable_limits: bool = False):
        limits = self.limits
        try:
            import resource
        except ImportError as exc:
            if require_portable_limits:
                raise SandboxUnavailable(
                    "POSIX resource limits are unavailable"
                ) from exc
            return None

        def apply() -> None:
            if limits.memory_mb > 0:
                size = int(limits.memory_mb) * 1024 * 1024
                try:
                    resource.setrlimit(resource.RLIMIT_AS, (size, size))
                except (OSError, ValueError):
                    # Darwin can reject RLIMIT_AS. It is not a reliable physical
                    # memory boundary there; apply the other limits separately.
                    pass
            cpu = int(limits.cpu_seconds or self.timeout)
            if cpu > 0:
                try:
                    resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu + 1))
                except (OSError, ValueError):
                    if require_portable_limits:
                        raise
            if limits.file_size_mb > 0:
                size = int(limits.file_size_mb) * 1024 * 1024
                try:
                    resource.setrlimit(resource.RLIMIT_FSIZE, (size, size))
                except (OSError, ValueError):
                    if require_portable_limits:
                        raise
            if hasattr(resource, "RLIMIT_NPROC") and limits.nproc > 0:
                try:
                    resource.setrlimit(
                        resource.RLIMIT_NPROC, (int(limits.nproc), int(limits.nproc))
                    )
                except (OSError, ValueError):
                    # Seatbelt denies process creation; this is an extra guard.
                    pass
            if limits.nofile > 0:
                try:
                    resource.setrlimit(
                        resource.RLIMIT_NOFILE, (int(limits.nofile), int(limits.nofile))
                    )
                except (OSError, ValueError):
                    if require_portable_limits:
                        raise

        return apply

    @staticmethod
    def _read_capped(path: Path, limit_bytes: int) -> tuple[str, bool]:
        if not path.exists():
            return "", False
        size = path.stat().st_size
        with path.open("rb") as f:
            data = f.read(max(0, limit_bytes))
        text = data.decode(errors="replace")
        truncated = size > limit_bytes
        if truncated:
            text += f"\n...[output truncated: {size - limit_bytes} bytes omitted]...\n"
        return text, truncated

    def _collect_result(
        self,
        proc_returncode: int,
        work: Path,
        elapsed: float,
        backend: str,
        *,
        capture_dir: Path | None = None,
        truncated: tuple[bool, bool] = (False, False),
    ):
        from aide.execution_types import ExecutionResult

        cap = max(1, int(self.limits.max_output_mb)) * 1024 * 1024
        output_dir = capture_dir or work
        stdout, read_trunc_out = self._read_capped(output_dir / "stdout", cap)
        stderr, read_trunc_err = self._read_capped(output_dir / "stderr", cap)
        trunc_out = truncated[0] or read_trunc_out
        trunc_err = truncated[1] or read_trunc_err
        if trunc_out and not read_trunc_out:
            stdout += "\n...[stdout truncated at capture limit]...\n"
        if trunc_err and not read_trunc_err:
            stderr += "\n...[stderr truncated at capture limit]...\n"
        output = [x for x in (stdout, stderr) if x]
        exc = None if proc_returncode == 0 else "RuntimeError"
        output.append(f"Execution time: {elapsed:.3f} seconds ({backend} sandbox).")
        meta = {
            "returncode": proc_returncode,
            "stdout_truncated": trunc_out,
            "stderr_truncated": trunc_err,
            "sandbox_backend": backend,
        }
        return ExecutionResult(
            output, elapsed, exc, meta if exc or trunc_out or trunc_err else None, []
        )

    def _run_subprocess(
        self,
        cmd: list[str],
        work: Path,
        *,
        backend: str,
        env: dict[str, str] | None = None,
        preexec_fn=None,
        cwd: Path | None = None,
        memory_limit_bytes: int | None = None,
    ):
        # Keep host-owned capture files outside the candidate's writable mount.
        # Otherwise candidate code can replace a capture path with a symlink and
        # make the host-side result reader disclose a file the sandbox denied.
        capture_dir = Path(tempfile.mkdtemp(prefix="rsi-capture-", dir=work.parent))
        stdout_path = capture_dir / "stdout"
        stderr_path = capture_dir / "stderr"
        cap = max(1, int(self.limits.max_output_mb)) * 1024 * 1024
        start = time.monotonic()
        truncated = [False, False]
        errors: list[BaseException] = []

        try:
            return self._run_subprocess_with_capture(
                cmd,
                work,
                backend=backend,
                env=env,
                preexec_fn=preexec_fn,
                cwd=cwd,
                memory_limit_bytes=memory_limit_bytes,
                capture_dir=capture_dir,
                stdout_path=stdout_path,
                stderr_path=stderr_path,
                cap=cap,
                start=start,
                truncated=truncated,
                errors=errors,
            )
        finally:
            shutil.rmtree(capture_dir, ignore_errors=True)

    def _run_subprocess_with_capture(
        self,
        cmd: list[str],
        work: Path,
        *,
        backend: str,
        env: dict[str, str] | None,
        preexec_fn,
        cwd: Path | None,
        memory_limit_bytes: int | None,
        capture_dir: Path,
        stdout_path: Path,
        stderr_path: Path,
        cap: int,
        start: float,
        truncated: list[bool],
        errors: list[BaseException],
    ):
        from aide.execution_types import ExecutionResult

        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            preexec_fn=preexec_fn,  # noqa: PLW1509 - needed to enforce child rlimits
            env=env,
            cwd=cwd,
        )
        assert proc.stdout is not None and proc.stderr is not None

        def drain(pipe, path: Path, index: int) -> None:
            written = 0
            try:
                with path.open("wb") as output, pipe:
                    while chunk := pipe.read(65536):
                        remaining = max(0, cap - written)
                        if remaining:
                            output.write(chunk[:remaining])
                            written += min(len(chunk), remaining)
                        if len(chunk) > remaining:
                            truncated[index] = True
            except OSError as exc:
                errors.append(exc)

        readers = [
            threading.Thread(target=drain, args=(proc.stdout, stdout_path, 0)),
            threading.Thread(target=drain, args=(proc.stderr, stderr_path, 1)),
        ]
        for reader in readers:
            reader.start()
        timed_out = False
        memory_exceeded = 0
        monitor_failed = False
        try:
            if memory_limit_bytes is None:
                try:
                    proc.wait(timeout=self.timeout)
                except subprocess.TimeoutExpired:
                    timed_out = True
            else:
                deadline = start + self.timeout
                missing_samples = 0
                while proc.poll() is None:
                    resident = self._macos_resident_bytes(proc.pid)
                    if resident is None:
                        try:
                            proc.wait(timeout=0.05)
                            break
                        except subprocess.TimeoutExpired:
                            missing_samples += 1
                            if missing_samples >= 3:
                                monitor_failed = True
                                break
                            continue
                    missing_samples = 0
                    if resident > memory_limit_bytes:
                        memory_exceeded = resident
                        break
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        timed_out = True
                        break
                    try:
                        proc.wait(timeout=min(remaining, 0.05))
                    except subprocess.TimeoutExpired:
                        pass
            if timed_out or memory_exceeded or monitor_failed:
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
                proc.wait()
        except BaseException:
            if proc.poll() is None:
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
                proc.wait()
            raise
        finally:
            for reader in readers:
                reader.join()
        if errors:
            raise RuntimeError("failed to capture sandbox output") from errors[0]
        if monitor_failed:
            raise SandboxUnavailable("macOS candidate memory monitoring failed")
        if memory_exceeded:
            stdout, _ = self._read_capped(stdout_path, cap)
            stderr, _ = self._read_capped(stderr_path, cap)
            output = [x for x in (stdout, stderr) if x]
            output.append(
                f"MemoryLimitExceeded: resident memory exceeded {memory_limit_bytes} bytes"
            )
            return ExecutionResult(
                output,
                time.monotonic() - start,
                "MemoryLimitExceeded",
                {
                    "sandbox_backend": backend,
                    "resident_bytes": memory_exceeded,
                    "memory_limit_bytes": memory_limit_bytes,
                    "stdout_truncated": truncated[0],
                    "stderr_truncated": truncated[1],
                },
                [],
            )
        if timed_out:
            stdout, _ = self._read_capped(stdout_path, cap)
            stderr, _ = self._read_capped(stderr_path, cap)
            output = [x for x in (stdout, stderr) if x]
            output.append(
                f"TimeoutError: Execution exceeded the time limit of {self.timeout} seconds"
            )
            return ExecutionResult(
                output,
                time.monotonic() - start,
                "TimeoutError",
                {
                    "sandbox_backend": backend,
                    "stdout_truncated": truncated[0],
                    "stderr_truncated": truncated[1],
                },
                [],
            )
        return self._collect_result(
            proc.returncode,
            work,
            time.monotonic() - start,
            backend,
            capture_dir=capture_dir,
            truncated=(truncated[0], truncated[1]),
        )

    def _bubblewrap_run(self, code: str):
        work = self._new_workspace()
        try:
            (work / self.agent_file_name).write_text(code)
            (work / "input").mkdir(exist_ok=True)
            cmd = [
                shutil.which("bwrap") or "bwrap",
                "--die-with-parent",
                "--new-session",
                "--unshare-all",
                "--proc",
                "/proc",
                "--dev",
                "/dev",
                "--size",
                str(min(128, max(16, int(self.limits.workspace_mb))) * 1024 * 1024),
                "--tmpfs",
                "/tmp",
            ]
            if self.limits.workspace_mb > 0:
                cmd += [
                    "--size",
                    str(int(self.limits.workspace_mb) * 1024 * 1024),
                ]
            cmd += ["--tmpfs", "/workspace"]
            bound: set[str] = set()
            for root in ("/usr", "/bin", "/lib", "/lib64", "/etc", "/opt", "/sys"):
                if Path(root).exists():
                    cmd += ["--ro-bind", root, root]
                    bound.add(str(Path(root).resolve()))
            for prefix in {Path(sys.prefix).resolve(), Path(sys.base_prefix).resolve()}:
                if prefix.exists() and not any(
                    str(prefix).startswith(x + os.sep) or str(prefix) == x
                    for x in bound
                ):
                    cmd += ["--ro-bind", str(prefix), str(prefix)]
            cmd += [
                "--ro-bind",
                str(work / self.agent_file_name),
                "/candidate.py",
            ]
            input_dir = self.base_workspace / "input"
            if input_dir.exists():
                cmd += ["--ro-bind", str(input_dir), "/workspace/input"]
            cmd += [
                "--chdir",
                "/workspace",
                "--clearenv",
                "--setenv",
                "HOME",
                "/workspace",
                "--setenv",
                "TMPDIR",
                "/tmp",
                "--setenv",
                "PATH",
                os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
                sys.executable,
                "/candidate.py",
            ]
            return self._run_subprocess(
                cmd,
                work,
                backend="bubblewrap",
                env={"PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin")},
                preexec_fn=self._limit_preexec(),
            )
        finally:
            shutil.rmtree(work, ignore_errors=True)

    def _container_command(
        self, work: Path, *, cidfile: Path | None = None
    ) -> list[str]:
        runtime = self._resolve_runtime()
        if runtime is None or not self.container_image:
            raise SandboxUnavailable("container sandbox backend became unavailable")
        cmd = [
            runtime,
            "run",
            "--rm",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            str(max(1, int(self.limits.nproc))),
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=128m",
            "--tmpfs",
            f"/workspace:rw,noexec,nosuid,size={max(1, int(self.limits.workspace_mb))}m",
            "--mount",
            f"type=bind,src={work},dst=/candidate_src,ro",
            "--workdir",
            "/workspace",
            "--env",
            "HOME=/workspace",
            "--env",
            "TMPDIR=/tmp",
        ]
        if cidfile is not None:
            cmd[2:2] = ["--cidfile", str(cidfile)]
        if self.limits.memory_mb > 0:
            cmd += ["--memory", f"{int(self.limits.memory_mb)}m"]
        if self.limits.nofile > 0:
            cmd += [
                "--ulimit",
                f"nofile={int(self.limits.nofile)}:{int(self.limits.nofile)}",
            ]
        if self.limits.nproc > 0:
            cmd += [
                "--ulimit",
                f"nproc={int(self.limits.nproc)}:{int(self.limits.nproc)}",
            ]
        if self.limits.file_size_mb > 0:
            size = int(self.limits.file_size_mb) * 1024 * 1024
            cmd += ["--ulimit", f"fsize={size}:{size}"]
        input_dir = self.base_workspace / "input"
        if input_dir.exists():
            cmd += ["--mount", f"type=bind,src={input_dir},dst=/workspace/input,ro"]
        # Do not inherit host environment or credentials. The candidate image must
        # contain its runtime dependencies; only HOME/TMPDIR are passed above.
        cmd += [
            "--entrypoint",
            "python",
            self.container_image,
            f"/candidate_src/{self.agent_file_name}",
        ]
        return cmd

    def _container_run(self, code: str):
        work = self._new_workspace()
        cidfile = self._tmp_root / f"container-{uuid.uuid4().hex}.cid"
        try:
            (work / self.agent_file_name).write_text(code)
            cmd = self._container_command(work, cidfile=cidfile)
            try:
                return self._run_subprocess(
                    cmd,
                    work,
                    backend="container",
                    env={"PATH": os.environ.get("PATH", "")},
                )
            finally:
                runtime = self._resolve_runtime()
                try:
                    container_id = cidfile.read_text().strip()
                except OSError:
                    container_id = ""
                if runtime and container_id:
                    # --rm normally removes the container. These idempotent calls
                    # also reap it if the CLI was killed while the daemon kept it.
                    for action in ("kill", "rm"):
                        args = [runtime, action]
                        if action == "rm":
                            args.append("-f")
                        args.append(container_id)
                        try:
                            subprocess.run(
                                args,
                                stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL,
                                timeout=10,
                                check=False,
                                env={"PATH": os.environ.get("PATH", "")},
                            )
                        except (OSError, subprocess.SubprocessError):
                            pass
                cidfile.unlink(missing_ok=True)
        finally:
            shutil.rmtree(work, ignore_errors=True)

    def _seatbelt_run(self, code: str):
        with self._seatbelt_workspace(self.limits.workspace_mb) as work:
            script = work / self.agent_file_name
            script.write_text(code)
            input_dir = self.base_workspace / "input"
            if input_dir.exists():
                os.symlink(input_dir, work / "input", target_is_directory=True)
            try:
                return self._run_subprocess(
                    self._seatbelt_command(work, script),
                    work,
                    backend="seatbelt",
                    env=self._seatbelt_env(work),
                    preexec_fn=self._limit_preexec(require_portable_limits=True),
                    cwd=work,
                    memory_limit_bytes=(
                        min(self.limits.memory_mb, self.limits.seatbelt_memory_mb)
                        * 1024
                        * 1024
                    ),
                )
            except subprocess.SubprocessError as exc:
                raise SandboxUnavailable(
                    "failed to enforce macOS candidate resource limits"
                ) from exc

    def _process_run(self, code: str):
        from aide.interpreter import Interpreter

        work = self._new_workspace()
        try:
            input_dir = self.base_workspace / "input"
            if input_dir.exists():
                os.symlink(input_dir, work / "input", target_is_directory=True)
            interp = Interpreter(
                work,
                timeout=self.timeout,
                format_tb_ipython=self.format_tb_ipython,
                agent_file_name=self.agent_file_name,
                sanitize_env=True,
            )
            try:
                return interp.run(code, True)
            finally:
                interp.cleanup_session()
        finally:
            shutil.rmtree(work, ignore_errors=True)

    def run(self, code: str, reset_session: bool = True):
        if self.backend == "bubblewrap":
            return self._bubblewrap_run(code)
        if self.backend == "container":
            return self._container_run(code)
        if self.backend == "seatbelt":
            return self._seatbelt_run(code)
        return self._process_run(code)

    def cleanup_session(self) -> None:
        return None
