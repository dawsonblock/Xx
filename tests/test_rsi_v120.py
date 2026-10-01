from dataclasses import dataclass
from pathlib import Path

import pytest

from aide.rsi.canary import RealCanaryGate
from aide.rsi.evidence import attest_evaluation
from aide.rsi.evolution import mutate_genome
from aide.rsi.policy import AdaptiveReplayPolicy
from aide.rsi.qualification import QualificationGate
from aide.rsi.sandbox import SandboxLimits, SecureInterpreter
from aide.rsi.split import WorldSplit
from aide.rsi.support import ReplaySupportIndex
from aide.rsi.types import ROOT_ID, Observation, PolicyGenome, ReplayNode, ReplayWorld

_TEST_ATTESTATION_KEY = "test-only-hmac-key-with-at-least-32-bytes"


@pytest.fixture(autouse=True)
def trusted_evaluator_key(monkeypatch):
    monkeypatch.setenv("AIDE_RSI_EVALUATION_HMAC_KEY", _TEST_ATTESTATION_KEY)


def test_policy_dsl_rejects_unknown_operators():
    with pytest.raises(ValueError):
        PolicyGenome(score_rule="arbitrary_python").bounded()
    with pytest.raises(ValueError):
        PolicyGenome(allocation_rule="shell").bounded()
    with pytest.raises(ValueError):
        PolicyGenome(stop_rule="oracle").bounded()


def test_policy_dsl_ucb_changes_refine_score():
    obs = {
        "a": Observation(
            "a", ROOT_ID, 0, 1, "a", 1.0, True, False, "ok", None, None, None, 0.1
        ),
        "a1": Observation(
            "a1", "a", 1, 2, "a", 1.05, True, False, "ok", None, 0.05, None, 0.1
        ),
    }
    linear = AdaptiveReplayPolicy(
        PolicyGenome(score_rule="linear", ucb_weight=4.0, beta=0.8)
    )
    ucb = AdaptiveReplayPolicy(PolicyGenome(score_rule="ucb", ucb_weight=4.0, beta=0.8))
    a = linear._score_refine("a1", obs, True, 0.8, total_probes=20)[0]
    b = ucb._score_refine("a1", obs, True, 0.8, total_probes=20)[0]
    assert b != a


def test_mutation_can_change_typed_structure():
    import random

    base = PolicyGenome()
    seen = set()
    rng = random.Random(7)
    cur = base
    for _ in range(100):
        cur = mutate_genome(cur, rng, scale=0.2)
        seen.add((cur.score_rule, cur.allocation_rule, cur.stop_rule))
    assert any(
        x != (base.score_rule, base.allocation_rule, base.stop_rule) for x in seen
    )


def test_support_index_uses_historical_prefixes():
    world = ReplayWorld(
        "w",
        {
            "a": ReplayNode("a", ROOT_ID, 0, 1, "a", 1.0, True, False),
            "a1": ReplayNode("a1", "a", 1, 2, "a", 1.1, True, False),
        },
    )
    idx = ReplaySupportIndex([world])
    prefix = {
        "x": Observation(
            "x", ROOT_ID, 0, 1, "x", 0.9, True, False, "ok", None, None, None, 0.1
        ),
    }
    assert 0.0 < idx.support_observations(prefix) <= 1.0


@dataclass
class Metric:
    value: float
    is_worst: bool = False
    maximize: bool = True


class Node:
    def __init__(self, score):
        self.metric = Metric(score)
        self.is_buggy = False
        self.rsi_provenance = attest_evaluation(
            {
                "candidate_sha256": "a" * 64,
                "evaluator_sha256": "b" * 64,
                "evaluator_config_sha256": "f" * 64,
                "task_sha256": "9" * 64,
                "dataset_sha256": "c" * 64,
                "split_sha256": "d" * 64,
                "predictions_sha256": "8" * 64,
                "environment_sha256": "7" * 64,
                "metric_id": "test.metric",
                "metric_maximize": True,
            },
            score,
            key=_TEST_ATTESTATION_KEY,
        )


class Journal:
    metric_maximize = True

    def __init__(self, score):
        self.nodes = [Node(score)]


def test_repeated_canary_requires_pass_fraction():
    gate = RealCanaryGate(
        max_normalized_regression=0.05, min_pass_fraction=0.66, min_pairs=3
    )
    pairs = [
        (Journal(1.2), Journal(1.0)),
        (Journal(1.1), Journal(1.0)),
        (Journal(0.94), Journal(1.0)),
    ]
    result = gate.evaluate_series(pairs)
    assert result.passed
    assert result.pass_fraction == pytest.approx(2 / 3)
    assert result.lower_confidence_bound is not None
    assert result.lower_confidence_bound >= -gate.max_normalized_regression
    assert len(result.pairs) == 3


def test_canary_confidence_gate_rejects_too_few_pairs_and_uncertainty():
    pairs = [(Journal(1.1), Journal(1.0)) for _ in range(3)]
    insufficient = RealCanaryGate().evaluate_series(pairs)
    assert not insufficient.passed
    assert insufficient.lower_confidence_bound is None
    assert "too few paired" in insufficient.reason

    noisy_pairs = [
        (Journal(1.4), Journal(1.0)),
        (Journal(1.3), Journal(1.0)),
        (Journal(0.8), Journal(1.0)),
        (Journal(1.2), Journal(1.0)),
        (Journal(0.9), Journal(1.0)),
    ]
    uncertain = RealCanaryGate().evaluate_series(noisy_pairs)
    assert not uncertain.passed
    assert uncertain.lower_confidence_bound < -0.05


class FakeEvaluator:
    def pareto_fitness(self, policy, worlds, beta_grid):
        # Candidate with higher exploit_weight wins on +1 worlds and loses badly
        # on -1 worlds, letting the aggregate gate hide a single-world regression
        # unless the worst-world check is active.
        return sum(
            policy.genome.exploit_weight * w.metadata.get("sign", 1.0) for w in worlds
        )


def test_qualification_blocks_worst_world_regression():
    good = ReplayWorld(
        "good",
        {"g": ReplayNode("g", ROOT_ID, 0, 1, "g", 1.0, True, False)},
        metadata={"sign": 1.0},
    )
    bad = ReplayWorld(
        "bad",
        {"b": ReplayNode("b", ROOT_ID, 0, 1, "b", 1.0, True, False)},
        metadata={"sign": -1.0},
    )
    split = WorldSplit([good], [good], [good, bad])
    gate = QualificationGate(
        FakeEvaluator(),
        max_qualification_regression=999.0,
        max_single_world_regression=0.2,
        min_qualification_worlds=2,
    )
    incumbent = PolicyGenome(exploit_weight=1.0)
    candidate = PolicyGenome(exploit_weight=2.0)
    rec = gate.compare(candidate, incumbent, split)
    assert not rec.promoted
    assert rec.worst_qualification_delta < -0.2


def test_container_backend_command_is_networkless_and_readonly(
    tmp_path: Path, monkeypatch
):
    from aide.rsi import sandbox as sb

    def fake_which(name):
        if name == "docker":
            return "/usr/bin/docker"
        return None

    monkeypatch.setattr(sb.shutil, "which", fake_which)
    interp = SecureInterpreter(
        tmp_path,
        mode="strict",
        backend="container",
        container_runtime="docker",
        container_image="aideml-rsi-sandbox:1.2.0",
        limits=SandboxLimits(memory_mb=512, nproc=16, nofile=64, workspace_mb=128),
    )
    work = tmp_path / "candidate"
    work.mkdir()
    cmd = interp._container_command(work)
    joined = " ".join(cmd)
    assert "--network none" in joined
    assert "--read-only" in joined
    assert "--cap-drop ALL" in joined
    assert "no-new-privileges" in joined
    assert "aideml-rsi-sandbox:1.2.0" in joined
    assert "/workspace:rw,noexec,nosuid,size=128m" in joined


def test_v11_policy_json_loads_with_safe_structural_defaults():
    old = {
        "beta": 0.4,
        "exploit_weight": 1.5,
        "trend_weight": 0.8,
        "stagnation_patience": 4,
    }
    g = PolicyGenome.from_dict(old)
    assert g.score_rule == "linear"
    assert g.allocation_rule == "portfolio"
    assert g.stop_rule == "threshold"
    assert g.beta == pytest.approx(0.4)


def test_strict_auto_uses_container_when_bwrap_missing(tmp_path: Path, monkeypatch):
    from aide.rsi import sandbox as sb

    def fake_which(name):
        if name == "docker":
            return "/usr/bin/docker"
        return None

    monkeypatch.setattr(sb.shutil, "which", fake_which)
    interp = SecureInterpreter(
        tmp_path,
        mode="strict",
        backend="auto",
        container_runtime="auto",
        container_image="aideml-rsi-sandbox:1.2.0",
    )
    assert interp.backend == "container"
