from aide.rsi.evaluator import ReplayEvaluator
from aide.rsi.evolution import PolicyEvolutionEngine
from aide.rsi.qualification import QualificationGate
from aide.rsi.split import split_worlds
from aide.rsi.types import PolicyGenome, ReplayNode, ReplayWorld, ROOT_ID


def mk_world(i: int):
    nodes = {
        f"a{i}": ReplayNode(f"a{i}", ROOT_ID, 0, 1, f"a{i}", 1.0, True, False),
        f"a{i}x": ReplayNode(f"a{i}x", f"a{i}", 1, 2, f"a{i}", 1.1, True, False),
        f"b{i}": ReplayNode(f"b{i}", ROOT_ID, 2, 1, f"b{i}", 0.7, True, False),
        f"b{i}x": ReplayNode(f"b{i}x", f"b{i}", 3, 2, f"b{i}", 1.6, True, False),
    }
    return ReplayWorld(f"w{i}", nodes, True, 2, 1.0)


def test_split_has_heldout_worlds():
    split = split_worlds([mk_world(i) for i in range(5)])
    assert split.development
    assert split.validation
    assert split.qualification
    all_ids = {w.world_id for w in split.development + split.validation + split.qualification}
    assert len(all_ids) == 5


def test_evolution_keeps_incumbent_in_candidate_set():
    worlds = [mk_world(i) for i in range(5)]
    split = split_worlds(worlds)
    evaluator = ReplayEvaluator()
    incumbent = PolicyGenome()
    engine = PolicyEvolutionEngine(evaluator, population=12, generations=2, elite_count=3, seed=7)
    candidate, history = engine.evolve(incumbent, split.development, split.validation)
    assert history
    inc_val = evaluator.evaluate_pool(__import__('aide.rsi.policy', fromlist=['AdaptiveReplayPolicy']).AdaptiveReplayPolicy(incumbent), split.validation).mean_reward
    cand_val = evaluator.evaluate_pool(__import__('aide.rsi.policy', fromlist=['AdaptiveReplayPolicy']).AdaptiveReplayPolicy(candidate), split.validation).mean_reward
    assert cand_val + 1e-12 >= inc_val


def test_qualification_record_is_explicit():
    split = split_worlds([mk_world(i) for i in range(5)])
    evaluator = ReplayEvaluator()
    gate = QualificationGate(evaluator, min_qualification_worlds=1)
    incumbent = PolicyGenome()
    record = gate.compare(incumbent, incumbent, split)
    assert record.promoted
    assert abs(record.qualification_delta) < 1e-12
