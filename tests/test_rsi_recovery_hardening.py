import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from aide.rsi.runner import _publish_best_from_worlds
from aide.rsi.sandbox import SandboxLimits, SecureInterpreter
from aide.rsi.types import ROOT_ID, ReplayNode, ReplayWorld
from aide.utils import atomic


def test_interrupted_journal_replacement_preserves_last_good_copy(tmp_path: Path, monkeypatch):
    journal = tmp_path / "journal.json"
    journal.write_text('{"nodes":[{"id":"previous"}]}')

    def interrupted_replace(source, destination):
        assert Path(source).read_bytes() == b'{"nodes":[{"id":"next"}]}'
        raise OSError("simulated interruption before commit")

    monkeypatch.setattr(atomic.os, "replace", interrupted_replace)
    with pytest.raises(OSError, match="simulated interruption"):
        atomic.replace_bytes(journal, b'{"nodes":[{"id":"next"}]}')
    assert json.loads(journal.read_text())["nodes"][0]["id"] == "previous"
    assert list(tmp_path.glob("journal.json.*.tmp")) == []


def test_committed_world_republishes_best_solution_after_interruption(tmp_path: Path):
    round_log = tmp_path / "round-000"
    round_log.mkdir()
    (round_log / "journal.json").write_text(json.dumps({"nodes": [{"id": "best", "code": "print(42)\n"}]}))
    world = ReplayWorld(
        world_id="run:round:0",
        nodes={"best": ReplayNode("best", ROOT_ID, 0, 1, "best", 42.0, True, False)},
        maximize=True,
        metadata={"round": 0, "policy_digest": "policy-1"},
    )

    # Simulate a crash after WORLD_COMMITTED but before publication.
    score, manifest = _publish_best_from_worlds([world], tmp_path)
    assert score == 42.0
    assert manifest["world_id"] == world.world_id
    assert (tmp_path / "best_solution.py").read_text() == "print(42)\n"

    # A crash between the code and manifest writes is repaired on restart too.
    (tmp_path / "best_solution.py").write_text("stale")
    (tmp_path / "best_solution.manifest.json").write_text("truncated")
    _publish_best_from_worlds([world], tmp_path)
    assert (tmp_path / "best_solution.py").read_text() == "print(42)\n"
    assert json.loads((tmp_path / "best_solution.manifest.json").read_text()) == manifest


def test_sandbox_caps_output_while_subprocess_is_running(tmp_path: Path, monkeypatch):
    class ExecutionResult:
        def __init__(self, term_out, exec_time, exc_type, exc_info, exc_stack):
            self.term_out = term_out
            self.exec_time = exec_time
            self.exc_type = exc_type
            self.exc_info = exc_info
            self.exc_stack = exc_stack

    monkeypatch.setitem(sys.modules, "aide.interpreter", SimpleNamespace(ExecutionResult=ExecutionResult))
    sandbox = SecureInterpreter(tmp_path, mode="process", allow_insecure_process=True,
                                limits=SandboxLimits(max_output_mb=1))
    work = sandbox._new_workspace()
    result = sandbox._run_subprocess(
        [sys.executable, "-c", "import sys; sys.stdout.write('a' * 1500000); sys.stderr.write('b' * 1500000)"],
        work, backend="test",
    )
    assert (work / ".stdout").stat().st_size == 1024 * 1024
    assert (work / ".stderr").stat().st_size == 1024 * 1024
    assert result.exc_info["stdout_truncated"] is True
    assert result.exc_info["stderr_truncated"] is True
    assert "truncated" in "".join(result.term_out)


def test_sandbox_timeout_still_returns_bounded_result(tmp_path: Path, monkeypatch):
    class ExecutionResult:
        def __init__(self, term_out, exec_time, exc_type, exc_info, exc_stack):
            self.term_out = term_out
            self.exc_type = exc_type
            self.exc_info = exc_info

    monkeypatch.setitem(sys.modules, "aide.interpreter", SimpleNamespace(ExecutionResult=ExecutionResult))
    sandbox = SecureInterpreter(tmp_path, mode="process", allow_insecure_process=True,
                                timeout=1, limits=SandboxLimits(max_output_mb=1))
    result = sandbox._run_subprocess(
        [sys.executable, "-c", "import time; print('started', flush=True); time.sleep(5)"],
        sandbox._new_workspace(), backend="test",
    )
    assert result.exc_type == "TimeoutError"
    assert "started" in "".join(result.term_out)
