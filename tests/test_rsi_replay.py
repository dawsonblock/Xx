from aide.rsi.evaluator import ReplayEvaluator
from aide.rsi.policy import AdaptiveReplayPolicy
from aide.rsi.replay import ReplayInvariantError, ReplaySimulator
from aide.rsi.types import PolicyGenome, ReplayNode, ReplayWorld, ROOT_ID


def world():
    nodes = {
        "a": ReplayNode("a", ROOT_ID, 0, 1, "a", 1.0, True, False),
        "a1": ReplayNode("a1", "a", 1, 2, "a", 1.2, True, False),
        "b": ReplayNode("b", ROOT_ID, 2, 1, "b", 0.8, True, False),
        "b1": ReplayNode("b1", "b", 3, 2, "b", 1.5, True, False),
    }
    return ReplayWorld("w", nodes, maximize=True, max_parallelism=2, baseline_score=1.0)


def test_prefix_only_hides_outcomes_until_probe():
    sim = ReplaySimulator(world())
    assert sim.observed() == {}
    actions = sim.public_legal_actions()
    assert len(actions) == 2
    assert all("target_id" not in a for a in actions)
    assert all(set(a) == {"action_id", "parent_id", "kind"} for a in actions)


def test_probe_reveals_recorded_outcome_and_never_invents():
    sim = ReplaySimulator(world())
    first = sim.legal_actions()[0]
    obs = sim.probe_batch([first.action_id])[0]
    assert obs.id == "a"
    assert obs.score == 1.0
    assert "a1" not in sim.observed()
    refine = next(a for a in sim.legal_actions() if a.parent_id == "a")
    sim.probe_batch([refine.action_id])
    assert sim.observed()["a1"].score == 1.2


def test_illegal_reveal_fails_closed():
    sim = ReplaySimulator(world())
    try:
        sim.probe_batch(["refine:a:a1"])
    except ReplayInvariantError:
        pass
    else:
        raise AssertionError("illegal replay action should fail")


def test_policy_reaches_high_value_branch_without_full_tree_requirement():
    w = world()
    policy = AdaptiveReplayPolicy(PolicyGenome(beta=0.8, stop_threshold=-1.0))
    result = ReplayEvaluator(work_penalty=0.0, parallel_bonus=0.0).evaluate_world(policy, w)
    assert result.probes > 0
    assert result.best_score is not None
    assert result.attainment >= 0.0
