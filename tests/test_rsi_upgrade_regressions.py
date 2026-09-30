from dataclasses import dataclass
from pathlib import Path

import pytest

from aide.rsi.canary import RealCanaryGate
from aide.rsi.live import LiveExplorationController
from aide.rsi.pool import ReplayWorldPool
from aide.rsi.replay import ReplaySimulator
from aide.rsi.split import PersistentSplitManager
from aide.rsi.state import RSIStateStore
from aide.rsi.types import PolicyGenome, ReplayNode, ReplayWorld, ROOT_ID
from aide.rsi.world import world_from_journal_json


@dataclass
class Metric:
    value: float
    is_worst: bool = False
    maximize: bool = True


class Node:
    def __init__(self, nid, score, parent=None, buggy=False, analysis=""):
        self.id = nid
        self.metric = Metric(score) if score is not None else None
        self.parent = parent
        self.children = set()
        if parent is not None:
            parent.children.add(self)
        self.is_buggy = buggy
        self.analysis = analysis
        self.exc_type = None
        self.exec_time = 0.1
        self.step = 0

    @property
    def is_leaf(self):
        return not self.children


class Journal:
    def __init__(self, nodes, maximize=True):
        self.nodes = nodes
        self.metric_maximize = maximize


def mk_world(i: int) -> ReplayWorld:
    return ReplayWorld(
        f"w{i}",
        {f"n{i}": ReplayNode(f"n{i}", ROOT_ID, 0, 1, f"n{i}", float(i), True, False)},
        maximize=True,
        max_parallelism=1,
    )


def test_live_width_cap_never_duplicates_root_action():
    ctl = LiveExplorationController(
        PolicyGenome(beta=1.0, stop_threshold=-2), max_parallelism=4, width_cap=1
    )
    parents = ctl.select_parents(Journal([]))
    assert parents == [None]


def test_live_uses_same_policy_gene_for_trend():
    a = Node("a", 1.0)
    b = Node("b", 1.1, a)
    c = Node("c", 1.3, b)
    for i, n in enumerate([a, b, c]):
        n.step = i
    j = Journal([a, b, c])
    low = LiveExplorationController(
        PolicyGenome(beta=0.0, trend_weight=0.0, stop_threshold=-2), width_cap=1
    )
    high = LiveExplorationController(
        PolicyGenome(beta=0.0, trend_weight=4.0, stop_threshold=-2), width_cap=1
    )
    low_state, _ = low._prefix_state(j)
    high_state, _ = high._prefix_state(j)
    # Exact same AdaptiveReplayPolicy path is used; changing the gene changes the
    # shared scorer rather than a disconnected live-only implementation.
    aid = low_state["legal_actions"][0]["action_id"]
    parent_id = low_state["legal_actions"][0]["parent_id"]
    low_score = low.policy._score_refine(parent_id, low_state["observed"], True, 0.0)[0]
    high_score = high.policy._score_refine(
        parent_id, high_state["observed"], True, 0.0
    )[0]
    assert high_score != low_score
    assert aid in {x["action_id"] for x in high_state["legal_actions"]}


def test_persistent_split_never_reassigns_qualification(tmp_path: Path):
    mgr = PersistentSplitManager(tmp_path / "splits.json")
    first = mgr.split([mk_world(i) for i in range(5)])
    q_ids = {w.world_id for w in first.qualification}
    assert q_ids
    second = mgr.split([mk_world(i) for i in range(10)])
    assert q_ids <= {w.world_id for w in second.qualification}
    assert q_ids.isdisjoint({w.world_id for w in second.development})


def test_pool_is_content_addressed_and_world_id_immutable(tmp_path: Path):
    pool = ReplayWorldPool(tmp_path)
    w1 = mk_world(1)
    path = pool.add(w1)
    assert path.name.startswith(
        __import__("hashlib").sha256(pool._canonical_bytes(w1)).hexdigest()
    )
    w_changed = ReplayWorld(
        "w1", {"x": ReplayNode("x", ROOT_ID, 0, 1, "x", 99.0, True, False)}
    )
    with pytest.raises(ValueError):
        pool.add(w_changed)


def test_legacy_flat_world_requires_sidecar(tmp_path: Path):
    p = tmp_path / "w.world.json"
    mk_world(1).save(p)
    with pytest.raises(ValueError):
        ReplayWorldPool.load_flat_strict(p)


def test_replay_snapshot_does_not_leak_first_hidden_score(tmp_path: Path):
    journal = tmp_path / "journal.json"
    journal.write_text(
        """{"metric_maximize":true,"node2parent":{},"nodes":[{"id":"a","step":0,"metric":{"value":123.456,"is_worst":false,"maximize":true},"is_buggy":false}]}"""
    )
    world = world_from_journal_json(journal)
    sim = ReplaySimulator(world)
    assert sim.snapshot()["baseline_score"] is None
    assert sim.observed() == {}


def test_paired_canary_uses_incumbent_not_history():
    candidate = Journal([Node("c", 1.2)])
    incumbent = Journal([Node("i", 1.0)])
    result = RealCanaryGate(max_normalized_regression=0.05).evaluate_pair(
        candidate, incumbent
    )
    assert result.passed
    assert result.candidate_best == 1.2
    assert result.incumbent_best == 1.0


def test_canary_regression_normalization_does_not_saturate_on_candidate_delta():
    candidate = Journal([Node("c", 0.0)])
    incumbent = Journal([Node("i", 1000.0)])
    result = RealCanaryGate(max_normalized_regression=0.05).evaluate_pair(
        candidate, incumbent
    )
    assert result.normalized_delta == -20.0
    assert not result.passed


def test_canary_near_zero_uses_configured_fixed_scale_floor():
    candidate = Journal([Node("c", -0.1)])
    incumbent = Journal([Node("i", 0.0)])
    result = RealCanaryGate(
        max_normalized_regression=0.05, score_scale_floor=0.5
    ).evaluate_pair(candidate, incumbent)
    assert result.normalized_delta == -0.2
    assert not result.passed


def test_state_store_atomic_round_trip(tmp_path: Path):
    store = RSIStateStore(tmp_path / "state.json")
    store.write(phase="LIVE_RUNNING", current_round=2, attempts=7)
    loaded = store.load()
    assert loaded["phase"] == "LIVE_RUNNING"
    assert loaded["current_round"] == 2
    assert loaded["attempts"] == 7


def test_strict_sandbox_fails_closed_without_backend(tmp_path: Path, monkeypatch):
    from aide.rsi import sandbox as sb

    monkeypatch.setattr(sb.shutil, "which", lambda name: None)
    with pytest.raises(sb.SandboxUnavailable):
        sb.SecureInterpreter(tmp_path, mode="strict")


def test_replay_action_ids_do_not_expose_hidden_target_ids():
    hidden = "secret-child-id"
    w = ReplayWorld(
        "opaque",
        {hidden: ReplayNode(hidden, ROOT_ID, 0, 1, hidden, 1.0, True, False)},
    )
    action = ReplaySimulator(w).public_legal_actions()[0]
    assert hidden not in action["action_id"]
    assert action["action_id"] == "root:0"


def test_replay_rejects_nonroot_sibling_choices_not_available_live():
    nodes = {
        "a": ReplayNode("a", ROOT_ID, 0, 1, "a", 1.0, True, False),
        "a1": ReplayNode("a1", "a", 1, 2, "a", 1.1, True, False),
        "a2": ReplayNode("a2", "a", 2, 2, "a", 1.2, True, False),
    }
    with pytest.raises(ValueError):
        ReplaySimulator(ReplayWorld("ambiguous", nodes))


def test_pool_preserves_insertion_order_past_round_9(tmp_path: Path):
    pool = ReplayWorldPool(tmp_path)
    expected = []
    for i in range(12):
        w = ReplayWorld(
            f"exp:round:{i}",
            {
                f"n{i}": ReplayNode(
                    f"n{i}", ROOT_ID, i, 1, f"n{i}", float(i), True, False
                )
            },
            metadata={"round": i},
        )
        pool.add(w)
        expected.append(w.world_id)
    assert [w.world_id for w in pool.load_all()] == expected
    assert pool.manifest()["order"] == expected


def test_replaynode_provenance_survives_world_round_trip(tmp_path: Path):
    node = ReplayNode(
        "a",
        ROOT_ID,
        0,
        1,
        "a",
        1.0,
        True,
        False,
        provenance={"policy_digest": "deadbeef", "episode_role": "discovery"},
    )
    w = ReplayWorld("prov", {"a": node})
    p = tmp_path / "prov.json"
    w.save(p)
    loaded = ReplayWorld.load(p)
    assert loaded.nodes["a"].provenance["policy_digest"] == "deadbeef"


def test_pool_migrates_v1_flat_worlds_instead_of_ignoring_them(tmp_path: Path):
    import hashlib

    worlds = []
    for i in (2, 10):
        w = ReplayWorld(
            f"legacy:round:{i}",
            {
                f"n{i}": ReplayNode(
                    f"n{i}", ROOT_ID, i, 1, f"n{i}", float(i), True, False
                )
            },
            metadata={"round": i},
        )
        p = tmp_path / f"legacy_{i}.world.json"
        w.save(p)
        p.with_suffix(p.suffix + ".sha256").write_text(
            hashlib.sha256(p.read_bytes()).hexdigest() + "\n"
        )
        worlds.append(w)
    pool = ReplayWorldPool(tmp_path)
    assert [w.world_id for w in pool.load_all()] == [
        "legacy:round:2",
        "legacy:round:10",
    ]


def test_dependency_light_world_ids_are_content_derived(tmp_path: Path):
    a = tmp_path / "a.json"
    b = tmp_path / "b.json"
    a.write_text(
        '{"metric_maximize":true,"node2parent":{},"nodes":[{"id":"a","step":0,"metric":{"value":1.0,"is_worst":false,"maximize":true},"is_buggy":false}]}'
    )
    b.write_text(
        '{"metric_maximize":true,"node2parent":{},"nodes":[{"id":"b","step":0,"metric":{"value":2.0,"is_worst":false,"maximize":true},"is_buggy":false}]}'
    )
    wa = world_from_journal_json(a)
    wb = world_from_journal_json(b)
    assert wa.world_id != wb.world_id
    assert wa.world_id.startswith("journal-") and wb.world_id.startswith("journal-")


def test_live_and_replay_choose_same_semantic_action_from_equivalent_prefix():
    a = Node("a", 1.0)
    b = Node("b", 0.8)
    a.step, b.step = 0, 1
    journal = Journal([a, b])
    genome = PolicyGenome(beta=0.6, stop_threshold=-2)
    live = LiveExplorationController(
        genome, max_parallelism=1, width_cap=3, depth_cap=4
    )
    live_parent = live.select_parents(journal)[0]

    rw = ReplayWorld(
        "parity",
        {
            "a": ReplayNode("a", ROOT_ID, 0, 1, "a", 1.0, True, False),
            "a1": ReplayNode("a1", "a", 3, 2, "a", 1.1, True, False),
            "b": ReplayNode("b", ROOT_ID, 1, 1, "b", 0.8, True, False),
            "b1": ReplayNode("b1", "b", 4, 2, "b", 0.9, True, False),
            "c": ReplayNode("c", ROOT_ID, 2, 1, "c", 0.7, True, False),
        },
        max_parallelism=1,
    )
    sim = ReplaySimulator(rw)
    sim.probe_batch(["root:0"])  # reveal a
    sim.probe_batch(["root:0"])  # reveal b; c remains unopened
    policy = live.policy
    replay_action = policy.select_batch(sim.snapshot())[0]
    replay_parent = next(
        x for x in sim.public_legal_actions() if x["action_id"] == replay_action
    )["parent_id"]
    live_semantic_parent = ROOT_ID if live_parent is None else live_parent.id
    assert replay_parent == live_semantic_parent


def test_default_four_world_bootstrap_has_all_three_split_roles(tmp_path: Path):
    split = PersistentSplitManager(tmp_path / "splits.json").split(
        [mk_world(i) for i in range(4)]
    )
    assert len(split.development) == 2
    assert len(split.validation) == 1
    assert len(split.qualification) == 1
