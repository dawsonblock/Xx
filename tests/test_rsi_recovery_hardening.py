import json
import sys
from pathlib import Path
import pytest

from aide.rsi.artifacts import candidate_digest, store_candidate
from aide.rsi.evidence import evaluation_result_digest
from aide.rsi.runner import (
    _policy_digest,
    _publish_best_from_worlds,
    _recover_canary_transaction,
)
from aide.rsi.sandbox import SandboxLimits, SecureInterpreter
from aide.rsi.state import RSIStateStore
from aide.rsi.types import ROOT_ID, PolicyGenome, ReplayNode, ReplayWorld
from aide.utils import atomic


def trusted_provenance(candidate_hash: str, score: float) -> dict:
    provenance = {
        "candidate_sha256": candidate_hash,
        "evaluation_authority": "trusted_external",
        "evaluator_sha256": "b" * 64,
        "dataset_sha256": "c" * 64,
        "split_sha256": "d" * 64,
        "metric_maximize": True,
    }
    provenance["result_sha256"] = evaluation_result_digest(provenance, score)
    return provenance


def test_interrupted_journal_replacement_preserves_last_good_copy(
    tmp_path: Path, monkeypatch
):
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
    code = "print(42)\n"
    digest = store_candidate(code, tmp_path / "rsi" / "artifacts")
    (round_log / "journal.json").write_text(
        json.dumps({"nodes": [{"id": "best", "code": "tampered"}]})
    )
    world = ReplayWorld(
        world_id="run:round:0",
        nodes={
            "best": ReplayNode(
                "best",
                ROOT_ID,
                0,
                1,
                "best",
                42.0,
                True,
                False,
                provenance={
                    **trusted_provenance(digest, 42.0),
                },
            )
        },
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
    assert (
        json.loads((tmp_path / "best_solution.manifest.json").read_text()) == manifest
    )
    assert manifest["candidate_sha256"] == candidate_digest(code)


def test_publication_rejects_tampered_content_addressed_candidate(tmp_path: Path):
    digest = store_candidate("print(1)\n", tmp_path / "rsi" / "artifacts")
    artifact = tmp_path / "rsi" / "artifacts" / "sha256" / digest[:2] / f"{digest}.py"
    artifact.write_text("print(2)\n")
    world = ReplayWorld(
        "tampered",
        {
            "n": ReplayNode(
                "n",
                ROOT_ID,
                0,
                1,
                "n",
                1.0,
                True,
                False,
                provenance={
                    **trusted_provenance(digest, 1.0),
                },
            )
        },
        metadata={"round": 0},
    )
    with pytest.raises(ValueError, match="digest mismatch"):
        _publish_best_from_worlds([world], tmp_path)


def test_untrusted_feedback_metric_cannot_authorize_publication(tmp_path: Path):
    digest = store_candidate("print(1)\n", tmp_path / "rsi" / "artifacts")
    world = ReplayWorld(
        "advisory",
        {
            "n": ReplayNode(
                "n",
                ROOT_ID,
                0,
                1,
                "n",
                1.0,
                True,
                False,
                provenance={
                    "candidate_sha256": digest,
                    "evaluation_authority": "feedback_model_interpreted_candidate_output",
                },
            )
        },
        metadata={"round": 0},
    )
    assert _publish_best_from_worlds([world], tmp_path) == (None, {})
    assert not (tmp_path / "best_solution.py").exists()


def test_canary_decision_recovers_after_pending_policy_removal(tmp_path: Path):
    rsi_dir = tmp_path / "rsi"
    canary_root = tmp_path / "round-002" / "canary"
    canary_root.mkdir(parents=True)
    incumbent = PolicyGenome(beta=0.2)
    challenger = PolicyGenome(beta=0.8)
    incumbent.save(rsi_dir / "incumbent_policy.json")
    challenger.save(rsi_dir / "pending_policy.json")
    transaction = {
        "incumbent": incumbent.to_dict(),
        "challenger": challenger.to_dict(),
        "incumbent_digest": _policy_digest(incumbent),
        "candidate_digest": _policy_digest(challenger),
    }
    (canary_root / "transaction.json").write_text(json.dumps(transaction))
    decision = {
        "passed": True,
        "incumbent_digest": _policy_digest(incumbent),
        "candidate_digest": _policy_digest(challenger),
    }
    (canary_root / "decision.json").write_text(json.dumps(decision))
    (rsi_dir / "pending_policy.json").unlink()
    state_store = RSIStateStore(rsi_dir / "state.json")
    state_store.write(
        phase="CANARY_RUNNING",
        current_round=2,
        next_round=2,
        incumbent_digest=_policy_digest(incumbent),
        pending_digest=_policy_digest(challenger),
    )

    recovered = _recover_canary_transaction(
        state=state_store.load(), state_store=state_store, rsi_dir=rsi_dir
    )
    assert recovered["phase"] == "IDLE"
    assert recovered["incumbent_digest"] == _policy_digest(challenger)
    assert (
        PolicyGenome.load(rsi_dir / "incumbent_policy.json").to_dict()
        == challenger.to_dict()
    )
    assert not (rsi_dir / "pending_policy.json").exists()


def test_canary_recovery_removes_pending_file_after_state_commit(tmp_path: Path):
    rsi_dir = tmp_path / "rsi"
    canary_root = tmp_path / "round-001" / "canary"
    canary_root.mkdir(parents=True)
    incumbent = PolicyGenome(beta=0.2)
    challenger = PolicyGenome(beta=0.8)
    transaction = {
        "incumbent": incumbent.to_dict(),
        "challenger": challenger.to_dict(),
        "incumbent_digest": _policy_digest(incumbent),
        "candidate_digest": _policy_digest(challenger),
    }
    decision = {
        "passed": True,
        "incumbent_digest": _policy_digest(incumbent),
        "candidate_digest": _policy_digest(challenger),
    }
    (canary_root / "transaction.json").write_text(json.dumps(transaction))
    (canary_root / "decision.json").write_text(json.dumps(decision))
    challenger.save(rsi_dir / "incumbent_policy.json")
    challenger.save(rsi_dir / "pending_policy.json")
    state_store = RSIStateStore(rsi_dir / "state.json")
    state_store.write(
        phase="IDLE",
        current_round=1,
        next_round=1,
        incumbent_digest=_policy_digest(challenger),
        pending_digest=None,
        last_canary=decision,
    )

    _recover_canary_transaction(
        state=state_store.load(), state_store=state_store, rsi_dir=rsi_dir
    )
    assert not (rsi_dir / "pending_policy.json").exists()


def test_sandbox_caps_output_while_subprocess_is_running(tmp_path: Path):
    sandbox = SecureInterpreter(
        tmp_path,
        mode="process",
        allow_insecure_process=True,
        limits=SandboxLimits(max_output_mb=1),
    )
    work = sandbox._new_workspace()
    result = sandbox._run_subprocess(
        [
            sys.executable,
            "-c",
            "import sys; sys.stdout.write('a' * 1500000); sys.stderr.write('b' * 1500000)",
        ],
        work,
        backend="test",
    )
    assert not (work / ".stdout").exists()
    assert not (work / ".stderr").exists()
    assert result.exc_info["stdout_truncated"] is True
    assert result.exc_info["stderr_truncated"] is True
    assert "truncated" in "".join(result.term_out)


def test_sandbox_timeout_still_returns_bounded_result(tmp_path: Path):
    sandbox = SecureInterpreter(
        tmp_path,
        mode="process",
        allow_insecure_process=True,
        timeout=1,
        limits=SandboxLimits(max_output_mb=1),
    )
    result = sandbox._run_subprocess(
        [
            sys.executable,
            "-c",
            "import time; print('started', flush=True); time.sleep(5)",
        ],
        sandbox._new_workspace(),
        backend="test",
    )
    assert result.exc_type == "TimeoutError"
    assert "started" in "".join(result.term_out)


def test_container_timeout_explicitly_kills_and_removes_container(
    tmp_path: Path, monkeypatch
):
    from aide.rsi import sandbox as sandbox_module

    sandbox = SecureInterpreter(
        tmp_path,
        mode="process",
        allow_insecure_process=True,
        container_image="test-image",
        limits=SandboxLimits(workspace_mb=128),
    )
    monkeypatch.setattr(sandbox, "_resolve_runtime", lambda: "/usr/bin/docker")
    cleanup_calls = []

    def fake_run(cmd, **kwargs):
        cleanup_calls.append(cmd)

    def fake_runner(cmd, *args, **kwargs):
        cidfile = Path(cmd[cmd.index("--cidfile") + 1])
        cidfile.write_text("container-id\n")
        raise TimeoutError("simulated lost CLI process")

    monkeypatch.setattr(sandbox_module.subprocess, "run", fake_run)
    monkeypatch.setattr(sandbox, "_run_subprocess", fake_runner)
    with pytest.raises(TimeoutError, match="lost CLI"):
        sandbox._container_run("print('candidate')\n")
    assert cleanup_calls == [
        ["/usr/bin/docker", "kill", "container-id"],
        ["/usr/bin/docker", "rm", "-f", "container-id"],
    ]


def test_bubblewrap_uses_bounded_tmpfs_workspace(tmp_path: Path, monkeypatch):
    from aide.rsi import sandbox as sandbox_module

    monkeypatch.setattr(sandbox_module.sys, "platform", "linux")
    monkeypatch.setattr(
        sandbox_module.shutil,
        "which",
        lambda name: "/usr/bin/bwrap" if name == "bwrap" else None,
    )
    sandbox = SecureInterpreter(
        tmp_path,
        mode="strict",
        backend="bubblewrap",
        limits=SandboxLimits(workspace_mb=64),
    )
    captured = {}

    def fake_runner(cmd, *args, **kwargs):
        captured["cmd"] = cmd
        return None

    monkeypatch.setattr(sandbox, "_run_subprocess", fake_runner)
    sandbox._bubblewrap_run("print('candidate')\n")
    cmd = captured["cmd"]
    workspace_size = cmd.index("--size", cmd.index("/tmp") + 1)
    assert cmd[workspace_size + 1] == str(64 * 1024 * 1024)
    assert cmd[workspace_size + 2 : workspace_size + 4] == [
        "--tmpfs",
        "/workspace",
    ]
    assert "--bind" not in cmd
    assert "/candidate.py" in cmd
