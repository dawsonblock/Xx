import shutil
import sys
from pathlib import Path

import pytest

from aide.rsi.sandbox import SandboxLimits, SandboxUnavailable, SecureInterpreter


def test_candidate_script_name_cannot_escape_workspace(tmp_path: Path):
    with pytest.raises(ValueError, match="single file name"):
        SecureInterpreter(
            tmp_path,
            mode="process",
            allow_insecure_process=True,
            agent_file_name="../outside.py",
        )


@pytest.mark.skipif(
    sys.platform != "darwin" or shutil.which("sandbox-exec") is None,
    reason="macOS Seatbelt is unavailable",
)
def test_seatbelt_blocks_host_access_and_runs_python_locally(tmp_path: Path):
    secret = tmp_path / "secret"
    secret.write_text("HOST_SECRET")
    input_dir = tmp_path / "input"
    input_dir.mkdir()
    (input_dir / "datum").write_text("task data")
    sandbox = SecureInterpreter(tmp_path, mode="strict", backend="seatbelt")
    assert (
        SecureInterpreter(tmp_path, mode="strict", backend="auto").backend == "seatbelt"
    )
    result = sandbox.run(
        "from pathlib import Path\n"
        "import os, socket, subprocess\n"
        "print('input=' + Path('input/datum').read_text())\n"
        f"secret = Path({str(secret)!r})\n"
        f"input_file = Path({str(input_dir / 'datum')!r})\n"
        "for name, action in (\n"
        "    ('host_read', lambda: secret.read_text()),\n"
        "    ('symlink_read', lambda: (Path('leak').symlink_to(secret), Path('leak').read_text())),\n"
        "    ('host_write', lambda: secret.write_text('changed')),\n"
        "    ('input_write', lambda: input_file.write_text('changed')),\n"
        "    ('network', lambda: socket.create_connection(('127.0.0.1', 1), timeout=1)),\n"
        "    ('fork', lambda: subprocess.run(['/usr/bin/true'], check=True)),\n"
        "    ('posix_spawn', lambda: os.posix_spawn('/usr/bin/true', ['/usr/bin/true'], {})),\n"
        "):\n"
        "    try: action(); print(name + '=ALLOWED')\n"
        "    except OSError: print(name + '=DENIED')\n"
    )
    output = "".join(result.term_out)
    assert result.exc_type is None
    assert "input=task data" in output
    for name in (
        "host_read",
        "symlink_read",
        "host_write",
        "input_write",
        "network",
        "fork",
        "posix_spawn",
    ):
        assert f"{name}=DENIED" in output
    assert secret.read_text() == "HOST_SECRET"
    assert (input_dir / "datum").read_text() == "task data"


@pytest.mark.skipif(
    sys.platform != "darwin" or shutil.which("sandbox-exec") is None,
    reason="macOS Seatbelt is unavailable",
)
def test_seatbelt_refuses_a_profile_that_allows_host_access(
    tmp_path: Path, monkeypatch
):
    from aide.rsi import sandbox as module

    monkeypatch.setattr(module, "_SEATBELT_PROFILE", "(version 1)(allow default)")
    with pytest.raises(SandboxUnavailable, match="confinement check failed"):
        SecureInterpreter(tmp_path, mode="strict", backend="seatbelt")


@pytest.mark.skipif(
    sys.platform != "darwin" or shutil.which("sandbox-exec") is None,
    reason="macOS Seatbelt is unavailable",
)
def test_seatbelt_enforces_supported_resource_limits(tmp_path: Path):
    sandbox = SecureInterpreter(
        tmp_path,
        mode="strict",
        backend="seatbelt",
        limits=SandboxLimits(memory_mb=512, cpu_seconds=10, file_size_mb=1, nofile=64),
    )
    result = sandbox.run(
        "import resource\n"
        "print('cpu', resource.getrlimit(resource.RLIMIT_CPU))\n"
        "print('file', resource.getrlimit(resource.RLIMIT_FSIZE))\n"
        "print('nofile', resource.getrlimit(resource.RLIMIT_NOFILE))\n"
    )
    output = "".join(result.term_out)
    assert result.exc_type is None
    assert "cpu (10, 11)" in output
    assert "file (1048576, 1048576)" in output
    assert "nofile (64, 64)" in output


@pytest.mark.skipif(
    sys.platform != "darwin" or shutil.which("sandbox-exec") is None,
    reason="macOS Seatbelt is unavailable",
)
def test_seatbelt_refuses_unenforceable_resource_limits(tmp_path: Path):
    sandbox = SecureInterpreter(
        tmp_path,
        mode="strict",
        backend="seatbelt",
        limits=SandboxLimits(nofile=2**64),
    )
    with pytest.raises(SandboxUnavailable, match="resource limits"):
        sandbox.run("print('must not execute')")


@pytest.mark.skipif(
    sys.platform != "darwin" or shutil.which("sandbox-exec") is None,
    reason="macOS Seatbelt is unavailable",
)
def test_seatbelt_timeout_stops_candidate_and_cleans_workspace(tmp_path: Path):
    sandbox = SecureInterpreter(
        tmp_path,
        mode="strict",
        backend="seatbelt",
        timeout=1,
        limits=SandboxLimits(cpu_seconds=5),
    )
    result = sandbox.run("import time\nprint('started', flush=True)\ntime.sleep(5)")
    assert result.exc_type == "TimeoutError"
    assert "started" in "".join(result.term_out)
    assert list((tmp_path / ".rsi_exec").iterdir()) == []
