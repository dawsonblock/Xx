"""Hostile programs executed through the production Bubblewrap backend."""

from __future__ import annotations

import json
import os
import shutil
import sys

import pytest

from aide.rsi.sandbox import SandboxLimits, SecureInterpreter

pytestmark = pytest.mark.skipif(
    not sys.platform.startswith("linux") or shutil.which("bwrap") is None,
    reason="requires Linux with Bubblewrap",
)


def _output(result) -> str:
    return "\n".join(str(part) for part in result.term_out)


def test_host_paths_secrets_sockets_and_network_are_inaccessible(tmp_path, monkeypatch):
    host = tmp_path / "host"
    host.mkdir()
    secret = host / "promotion-key"
    secret.write_text("promotion-secret-sentinel")
    outside = host / "write-target"
    workspace = tmp_path / "candidate"
    workspace.mkdir()
    input_dir = workspace / "input"
    input_dir.mkdir()
    (input_dir / "escape-link").symlink_to(secret)
    monkeypatch.setenv("AIDE_RSI_PROMOTION_SECRET_TEST", "environment-secret-sentinel")
    fd = os.open(secret, os.O_RDONLY)
    os.set_inheritable(fd, True)
    try:
        interpreter = SecureInterpreter(
            workspace,
            timeout=5,
            mode="strict",
            backend="bubblewrap",
            limits=SandboxLimits(
                memory_mb=128, cpu_seconds=3, file_size_mb=2, nproc=16
            ),
        )
        assert interpreter.backend == "bubblewrap"
        program = f"""
import json, os, socket
def readable(path):
    try:
        return open(path, 'rb').read()
    except OSError:
        return b''
def writable(path):
    try:
        open(path, 'w').write('attacker')
        return True
    except OSError:
        return False
try:
    socket.create_connection(('127.0.0.1', 9), timeout=0.2)
    network = True
except OSError:
    network = False
try:
    os.read({fd}, 100)
    inherited_fd = True
except OSError:
    inherited_fd = False
print(json.dumps({{
  'host_secret': bool(readable({str(secret)!r})),
  'symlink_secret': bool(readable('/workspace/input/escape-link')),
  'proc_secret': b'environment-secret-sentinel' in readable('/proc/1/environ'),
  'env_secret': os.environ.get('AIDE_RSI_PROMOTION_SECRET_TEST'),
  'docker_socket': os.path.exists('/var/run/docker.sock'),
  'network': network,
  'inherited_fd': inherited_fd,
  'host_write': writable({str(outside)!r}),
  'tmp_escape': b'promotion-secret-sentinel' in readable('/tmp/..' + {str(secret)!r}),
}}))
"""
        result = interpreter.run(program)
        output = _output(result)
        observation = next(
            json.loads(line) for line in output.splitlines() if line.startswith("{")
        )
        assert observation == {
            "host_secret": False,
            "symlink_secret": False,
            "proc_secret": False,
            "env_secret": None,
            "docker_socket": False,
            "network": False,
            "inherited_fd": False,
            "host_write": False,
            "tmp_escape": False,
        }
        assert secret.read_text() == "promotion-secret-sentinel"
        assert not outside.exists()
    finally:
        os.close(fd)


def test_bubblewrap_resource_limits_terminate_hostile_program(tmp_path):
    interpreter = SecureInterpreter(
        tmp_path / "candidate",
        timeout=2,
        mode="strict",
        backend="bubblewrap",
        limits=SandboxLimits(memory_mb=64, cpu_seconds=1, file_size_mb=1, nproc=8),
    )
    result = interpreter.run("while True: pass\n")
    assert result.exc_type is not None
    assert result.exec_time <= 5
