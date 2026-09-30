from __future__ import annotations

from dataclasses import dataclass

from aide.rsi.jev import JevAdvisor
from aide.rsi.live import LiveExplorationController
from aide.rsi.policy import AdaptiveReplayPolicy
from aide.rsi.replay import ReplaySimulator
from aide.rsi.types import PolicyGenome, ReplayNode, ReplayWorld, ROOT_ID


class FakeResponse:
    def __init__(self, body, status_code=200, text=""):
        self._body = body
        self.status_code = status_code
        self.text = text

    def json(self):
        return self._body


def _choice_body(qid: str, choice: str, probs: dict[str, float], confidence: float):
    return {
        "model": "local-jev-fabric",
        "answers": {
            qid: {
                "type": "choice",
                "choice": choice,
                "probabilities": probs,
                "confidence": confidence,
            }
        },
        "fabric": {
            "request_id": "req-1",
            "evidence_sha256": "abc123",
            "decisions": {qid: {"backend": "anyjev"}},
        },
    }


def test_jev_high_confidence_failure_can_mark_repairable():
    criteria = JevAdvisor.FAILURE_CRITERIA
    probs = {k: 0.01 for k in criteria}
    probs["repairable_implementation"] = 0.96
    # normalize exactly
    leftover = (1.0 - probs["repairable_implementation"]) / (len(criteria) - 1)
    probs = {k: (0.96 if k == "repairable_implementation" else leftover) for k in criteria}

    def post(*args, **kwargs):
        return FakeResponse(_choice_body("dream.failure_class.v1", "repairable_implementation", probs, 0.96))

    advisor = JevAdvisor(enabled=True, confidence_threshold=0.72, failure_influence=True, post_fn=post)
    repairability, advice = advisor.repairability(fail_class="runtime", error="shape mismatch")
    assert repairability == "repairable"
    assert advice is not None
    assert advice.backend == "anyjev"
    assert advice.authoritative is False


def test_jev_low_confidence_does_not_override_fallback():
    criteria = JevAdvisor.FAILURE_CRITERIA
    probs = {k: 1.0 / len(criteria) for k in criteria}

    def post(*args, **kwargs):
        return FakeResponse(_choice_body("dream.failure_class.v1", "structural_algorithm", probs, 0.40))

    advisor = JevAdvisor(enabled=True, confidence_threshold=0.72, failure_influence=True, post_fn=post)
    repairability, advice = advisor.repairability(fail_class="compile", error="syntax error")
    assert repairability is None
    assert advice is not None
    assert advice.confidence == 0.40


def test_failure_request_excludes_raw_credentials_and_keeps_fixed_signals():
    captured = []
    criteria = JevAdvisor.FAILURE_CRITERIA
    probs = {k: 1.0 / len(criteria) for k in criteria}

    def post(*args, **kwargs):
        captured.append(kwargs["json"])
        return FakeResponse(_choice_body("dream.failure_class.v1", "uncertain", probs, 0.2))

    advisor = JevAdvisor(enabled=True, post_fn=post)
    advisor.classify_failure(
        fail_class="runtime",
        error="shape mismatch; password=hunter2; AWS_SECRET_ACCESS_KEY=abc123",
        analysis="Bearer tokenvalue123456 and database password: another-secret",
    )
    state = captured[0]["state"]
    assert "shape" in state
    for secret in ("hunter2", "abc123", "tokenvalue123456", "another-secret"):
        assert secret not in state


def test_jev_fail_open_preserves_search_when_fabric_is_down():
    def post(*args, **kwargs):
        raise OSError("connection refused")

    advisor = JevAdvisor(enabled=True, fail_open=True, post_fn=post)
    repairability, advice = advisor.repairability(fail_class="compile", error="bad syntax")
    assert repairability is None
    assert advice is not None
    assert advice.error


def test_replay_preserves_recorded_jev_repairability_without_network():
    world = ReplayWorld(
        world_id="w",
        maximize=True,
        nodes={
            "a": ReplayNode(
                id="a",
                parent_id=ROOT_ID,
                step=0,
                depth=1,
                branch_id="a",
                score=None,
                valid=False,
                is_buggy=True,
                fail_class="runtime",
                error="shape mismatch",
                repairability="repairable",
                advisory={"failure_classification": {"confidence": 0.91}},
            )
        },
    )
    sim = ReplaySimulator(world)
    sim.probe_batch(["root:0"])
    obs = next(iter(sim.observed().values()))
    assert obs.repairability == "repairable"
    assert obs.advisory_confidence == 0.91


@dataclass
class FakeMetric:
    value: float
    is_worst: bool = False
    maximize: bool = True


class FakeNode:
    def __init__(self, node_id="n1", *, buggy=False, metric=1.0, parent=None):
        self.id = node_id
        self.parent = parent
        self.children = set()
        if parent is not None:
            parent.children.add(self)
        self.metric = FakeMetric(metric) if metric is not None else None
        self.is_buggy = buggy
        self.analysis = "compile syntax failure" if buggy else "ok"
        self.exc_info = None
        self.exc_type = "SyntaxError" if buggy else None
        self.exec_time = 0.1
        self.step = 0
        self.rsi_jev_advisory = {}

    @property
    def is_leaf(self):
        return not self.children


class FakeJournal:
    def __init__(self, nodes):
        self.nodes = nodes
        self.metric_maximize = True


class ShadowOnlyAdvisor:
    def __init__(self):
        self.rank_calls = 0

    def repairability(self, **kwargs):
        return None, None

    def shadow_rank_actions(self, state, deterministic_batch):
        self.rank_calls += 1
        # Deliberately disagree; controller must ignore this shadow suggestion.
        return None


def test_shadow_action_advisor_cannot_change_live_selected_batch():
    node = FakeNode()
    journal = FakeJournal([node])
    genome = PolicyGenome(beta=0.0, exploration_weight=0.0, underexplored_weight=0.0)

    plain = LiveExplorationController(genome, width_cap=1, depth_cap=4)
    with_shadow_advisor = ShadowOnlyAdvisor()
    shadow = LiveExplorationController(genome, width_cap=1, depth_cap=4, advisor=with_shadow_advisor)

    a = plain.select_parents(journal)
    b = shadow.select_parents(journal)
    assert [getattr(x, "id", None) for x in a] == [getattr(x, "id", None) for x in b]
    assert with_shadow_advisor.rank_calls == 1


def test_policy_uses_recorded_jev_repairability_for_recovery_role():
    obs_world = ReplayWorld(
        world_id="repair",
        maximize=True,
        nodes={
            "a": ReplayNode(
                id="a", parent_id=ROOT_ID, step=0, depth=1, branch_id="a",
                score=None, valid=False, is_buggy=True,
                fail_class="dependency", error="missing module",
                repairability="repairable",
            ),
            "a2": ReplayNode(
                id="a2", parent_id="a", step=1, depth=2, branch_id="a",
                score=1.0, valid=True, is_buggy=False,
            ),
        },
    )
    sim = ReplaySimulator(obs_world)
    sim.probe_batch(["root:0"])
    policy = AdaptiveReplayPolicy(PolicyGenome(recovery_weight=4.0, failure_penalty=4.0, beta=0.5))
    batch = policy.select_batch(sim.snapshot())
    assert batch == ["refine:a"]
