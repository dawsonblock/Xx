from __future__ import annotations

import hashlib
import math
import random
from dataclasses import replace
from statistics import median
from types import SimpleNamespace

import pytest

from aide.rsi.canary import RealCanaryGate, TaskClusteredCanaryGate
from aide.rsi.evidence import attest_evaluation
from aide.rsi.runner import (
    _panel_sample_identity_records,
    _recover_multitask_canary_transaction,
    _sample_identity_record_sha256,
    _verify_panel_sample_identity_reservation,
)
from aide.rsi.state import RSIStateStore
from aide.rsi.statistics import (
    MULTITASK_MIN_TASKS,
    CanaryPanel,
    CanaryPanelTask,
    StatisticalBudget,
    canary_execution_schedule,
    multitask_protocol_sha256,
    sequential_alpha,
    task_effect_decision,
    task_sign_test,
)

_TEST_KEY = "test-only-multitask-canary-key-32-bytes"


@pytest.fixture(autouse=True)
def evaluation_attestation_key(monkeypatch):
    monkeypatch.setenv("AIDE_RSI_EVALUATION_HMAC_KEY", _TEST_KEY)


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _pair_gate() -> RealCanaryGate:
    return RealCanaryGate(
        artifact_root=None,
        require_artifacts=False,
        min_pairs=1,
        bootstrap_samples=100,
    )


def _panel(
    *,
    epoch: int = 0,
    duplicate_public: bool = False,
    extra_same_family_task: bool = False,
) -> CanaryPanel:
    gate_policy = _pair_gate().task_pair_policy_config()
    protocol_sha256 = multitask_protocol_sha256(
        0.05, 0.0, 0.25, pair_gate_policy=gate_policy
    )
    tasks = []
    for index in range(MULTITASK_MIN_TASKS):
        family = f"family-{index:02d}"
        stratum = f"stratum-{index // 4}"
        public_hash = _sha(
            "public-0" if duplicate_public and index == 1 else f"public-{index}"
        )
        tasks.append(
            CanaryPanelTask(
                task_id=f"task-{index:02d}",
                task_family=family,
                task_stratum=stratum,
                task_sha256=_sha(f"task identity {index}"),
                evaluator_authority_sha256=_sha(f"authority {index}"),
                shard_sha256=_sha(f"shard {index}"),
                dataset_sha256=_sha(f"dataset {index}"),
                split_sha256=_sha(f"split {index}"),
                metric_id="utility",
                metric_maximize=True,
                sample_ids=(f"sample-{index}",),
                public_input_sha256=(public_hash,),
                sample_content_sha256=(_sha(f"full sample {index}"),),
                replicate_ids=(0, 1, 2, 3),
                replicate_seeds=(
                    101 + index * 1000,
                    202 + index * 1000,
                    303 + index * 1000,
                    404 + index * 1000,
                ),
                budget_per_run=24,
                public_data_sha256=_sha(f"public data directory {index}"),
            )
        )
    if extra_same_family_task:
        tasks.append(
            replace(
                tasks[0],
                task_id="task-extra-in-family-00",
                task_sha256=_sha("task identity extra in family 00"),
                sample_ids=("sample-extra",),
                public_input_sha256=(_sha("public-extra"),),
                sample_content_sha256=(_sha("full-extra"),),
                public_data_sha256=_sha("public-extra-data"),
            )
        )
    return CanaryPanel(epoch=epoch, tasks=tuple(tasks), protocol_sha256=protocol_sha256)


def test_legacy_series_settings_do_not_change_multitask_protocol_identity():
    defaults = _pair_gate()
    legacy_changed = RealCanaryGate(
        min_pass_fraction=0.95,
        min_pairs=17,
        confidence_level=0.99,
        bootstrap_samples=1000,
        max_single_pair_regression=0.5,
    )
    assert defaults.policy_config() != legacy_changed.policy_config()
    assert (
        defaults.task_pair_policy_config() == legacy_changed.task_pair_policy_config()
    )
    assert multitask_protocol_sha256(
        pair_gate_policy=defaults.task_pair_policy_config()
    ) == multitask_protocol_sha256(
        pair_gate_policy=legacy_changed.task_pair_policy_config()
    )

    changed_authoritative = RealCanaryGate(max_normalized_regression=0.1)
    assert defaults.task_pair_policy_config() != (
        changed_authoritative.task_pair_policy_config()
    )
    assert multitask_protocol_sha256(
        pair_gate_policy=defaults.task_pair_policy_config()
    ) != multitask_protocol_sha256(
        pair_gate_policy=changed_authoritative.task_pair_policy_config()
    )


def _journal(score: float, role: str, task_index: int, replicate: int):
    provenance = attest_evaluation(
        {
            "candidate_sha256": _sha(f"candidate-{role}-{task_index}-{replicate}"),
            "evaluator_sha256": _sha("evaluator"),
            "evaluator_config_sha256": _sha("evaluator config"),
            "task_sha256": _sha(f"evaluation-task-{task_index}"),
            "dataset_sha256": _sha(f"evaluation-data-{task_index}"),
            "split_sha256": _sha(f"evaluation-split-{task_index}"),
            "predictions_sha256": _sha(f"predictions-{role}-{task_index}-{replicate}"),
            "environment_sha256": _sha("environment"),
            "metric_id": "utility",
            "metric_maximize": True,
        },
        score,
        key=_TEST_KEY,
    )
    node = SimpleNamespace(
        metric=SimpleNamespace(value=score, is_worst=False),
        score=score,
        is_buggy=False,
        rsi_provenance=provenance,
    )
    return SimpleNamespace(metric_maximize=True, nodes=[node])


def _gate(panel: CanaryPanel, *, attempt: int = 1) -> TaskClusteredCanaryGate:
    pair_gates = {task_id: _pair_gate() for task_id in panel.task_ids}
    return TaskClusteredCanaryGate(
        panel=panel,
        pair_gates=pair_gates,
        promotion_attempt_index=attempt,
        family_alpha=0.05,
        allocated_alpha=sequential_alpha(0.05, attempt),
        min_effect_size=0.0,
        max_task_regression=0.25,
    )


def _schedule_order_by_ordinal(panel: CanaryPanel):
    return {
        (entry["task_id"], entry["replicate_ordinal"]): tuple(entry["order"])
        for entry in canary_execution_schedule(panel)
    }


def test_even_replicate_ids_cannot_force_challenger_first():
    panel = _panel()
    even_ids = tuple(replace(task, replicate_ids=(0, 2, 4, 6)) for task in panel.tasks)
    schedule = canary_execution_schedule(
        CanaryPanel(panel.epoch, even_ids, panel.protocol_sha256)
    )
    first_sides = [entry["order"][0] for entry in schedule]

    assert "incumbent" in first_sides
    assert first_sides.count("challenger") == first_sides.count("incumbent")


def test_odd_replicate_ids_cannot_force_challenger_first():
    panel = _panel()
    odd_ids = tuple(replace(task, replicate_ids=(1, 3, 5, 7)) for task in panel.tasks)
    schedule = canary_execution_schedule(
        CanaryPanel(panel.epoch, odd_ids, panel.protocol_sha256)
    )
    first_sides = [entry["order"][0] for entry in schedule]

    assert "incumbent" in first_sides
    assert first_sides.count("challenger") == first_sides.count("incumbent")


def test_sparse_replicate_ids_do_not_affect_order():
    panel = _panel()
    sparse_ids = tuple(
        replace(task, replicate_ids=(100, 1000, 10000, 100000)) for task in panel.tasks
    )
    sparse_panel = CanaryPanel(panel.epoch, sparse_ids, panel.protocol_sha256)

    assert _schedule_order_by_ordinal(sparse_panel) == _schedule_order_by_ordinal(panel)


def test_reordered_input_panel_has_identical_canonical_schedule():
    panel = _panel()
    reordered = CanaryPanel(
        panel.epoch, tuple(reversed(panel.tasks)), panel.protocol_sha256
    )

    assert reordered.panel_sha256 == panel.panel_sha256
    assert canary_execution_schedule(reordered) == canary_execution_schedule(panel)


def test_schedule_global_balance():
    first_sides = [entry["order"][0] for entry in canary_execution_schedule(_panel())]

    assert abs(first_sides.count("challenger") - first_sides.count("incumbent")) <= 1


def test_schedule_per_task_balance():
    grouped: dict[str, list[str]] = {}
    for entry in canary_execution_schedule(_panel()):
        grouped.setdefault(entry["task_id"], []).append(entry["order"][0])

    assert all(
        orders.count("challenger") == orders.count("incumbent")
        for orders in grouped.values()
    )


def test_schedule_per_family_balance():
    grouped: dict[str, list[str]] = {}
    for entry in canary_execution_schedule(_panel(extra_same_family_task=True)):
        grouped.setdefault(entry["task_family"], []).append(entry["order"][0])

    assert all(
        orders.count("challenger") == orders.count("incumbent")
        for orders in grouped.values()
    )


def test_replicate_id_parity_fuzz_does_not_change_canonical_order():
    rng = random.Random(74192026)
    panel = _panel()
    reference = _schedule_order_by_ordinal(panel)
    for _ in range(2000):
        tasks = []
        for task in panel.tasks:
            base = rng.randrange(0, 10**12)
            parity = rng.randrange(2)
            ids = tuple(base + parity + 2 * ordinal for ordinal in range(4))
            tasks.append(replace(task, replicate_ids=ids))
        fuzzed = CanaryPanel(panel.epoch, tuple(tasks), panel.protocol_sha256)
        assert _schedule_order_by_ordinal(fuzzed) == reference


def test_replicates_reduce_to_one_effect_per_task():
    panel = _panel()
    gate = _gate(panel)
    pairs = {}
    for task_index, task_id in enumerate(panel.task_ids):
        pairs[task_id] = [
            (
                _journal(1.1, "challenger", task_index, replicate),
                _journal(1.0, "incumbent", task_index, replicate),
            )
            for replicate in range(4)
        ]

    result = gate.evaluate_panel(pairs)

    assert result.total_tasks == MULTITASK_MIN_TASKS
    assert all(effect.runs == 4 for effect in result.task_effects)
    assert result.positive_tasks == MULTITASK_MIN_TASKS
    assert result.positive_families == MULTITASK_MIN_TASKS
    assert result.critical_positive_families == 32
    assert result.p_value == pytest.approx(2**-MULTITASK_MIN_TASKS)
    assert result.passed
    decoded = CanaryPanel.from_dict(panel.to_dict())
    assert decoded.panel_sha256 == panel.panel_sha256
    assert decoded.tasks[0].seed_for(1) == 202
    assert decoded.tasks[0].sample_identity_records() == [
        {
            "sample_id": panel.tasks[0].sample_ids[0],
            "public_input_sha256": panel.tasks[0].public_input_sha256[0],
            "sample_content_sha256": panel.tasks[0].sample_content_sha256[0],
        }
    ]


def test_panel_deserialization_rejects_detached_sample_identity_records():
    panel = _panel()
    payload = panel.to_dict()
    payload["tasks"][0]["sample_identity_records"][0]["public_input_sha256"] = _sha(
        "detached public input"
    )
    with pytest.raises(ValueError, match="identity records do not match"):
        CanaryPanel.from_dict(payload)


def test_signed_transaction_sample_rows_match_panel_and_durable_reservation():
    panel = _panel()
    rows = _panel_sample_identity_records(panel)
    state = {
        "consumed_canary_sample_identity_sha256": sorted(
            _sample_identity_record_sha256(row) for row in rows
        )
    }
    _verify_panel_sample_identity_reservation(rows, panel, state)

    swapped = [dict(row) for row in rows]
    swapped[0]["public_input_sha256"] = _sha("remapped input")
    with pytest.raises(ValueError, match="do not match its panel"):
        _verify_panel_sample_identity_reservation(swapped, panel, state)

    with pytest.raises(ValueError, match="not durably reserved"):
        _verify_panel_sample_identity_reservation(rows, panel, {})


def test_many_replicates_from_one_winning_task_cannot_grant_promotion():
    panel = _panel()
    gate = _gate(panel)
    pairs = {}
    for task_index, task_id in enumerate(panel.task_ids):
        candidate_score = 1.2 if task_index == 0 else 0.9
        pairs[task_id] = [
            (
                _journal(candidate_score, "challenger", task_index, replicate),
                _journal(1.0, "incumbent", task_index, replicate),
            )
            for replicate in range(4)
        ]

    result = gate.evaluate_panel(pairs)

    assert result.total_tasks == MULTITASK_MIN_TASKS
    assert result.positive_tasks == 1
    assert result.p_value > 0.5
    assert not result.passed


def test_correlated_tasks_in_one_family_count_as_one_inference_unit():
    panel = _panel(extra_same_family_task=True)
    gate = _gate(panel)
    pairs = {}
    for task_index, task_id in enumerate(panel.task_ids):
        score = 0.9 if task_id == "task-extra-in-family-00" else 1.1
        pairs[task_id] = [
            (
                _journal(score, "challenger", task_index, replicate),
                _journal(1.0, "incumbent", task_index, replicate),
            )
            for replicate in range(4)
        ]

    result = gate.evaluate_panel(pairs)

    assert result.total_tasks == MULTITASK_MIN_TASKS + 1
    assert result.positive_tasks == MULTITASK_MIN_TASKS
    assert result.total_families == MULTITASK_MIN_TASKS
    assert result.positive_families == MULTITASK_MIN_TASKS - 1
    assert result.critical_positive_families == 32


def test_panel_rejects_small_unbalanced_or_overlapping_task_sets():
    panel = _panel()
    with pytest.raises(ValueError, match="at least 40"):
        CanaryPanel(0, panel.tasks[:1], panel.protocol_sha256)
    unbalanced = tuple(
        replace(
            task,
            task_stratum=(
                "stratum-a"
                if index < 11
                else "stratum-b" if index < 15 else "stratum-c"
            ),
        )
        for index, task in enumerate(panel.tasks)
    )
    with pytest.raises(ValueError, match="stratum"):
        CanaryPanel(0, unbalanced, panel.protocol_sha256)
    sparse_strata = tuple(
        replace(task, task_stratum=f"single-family-stratum-{index}")
        for index, task in enumerate(panel.tasks)
    )
    with pytest.raises(ValueError, match="independent families"):
        CanaryPanel(0, sparse_strata, panel.protocol_sha256)
    with pytest.raises(ValueError, match="duplicate candidate-visible"):
        _panel(duplicate_public=True)
    shared_seed_schedule = list(panel.tasks)
    shared_seed_schedule[1] = replace(
        shared_seed_schedule[1],
        replicate_seeds=shared_seed_schedule[0].replicate_seeds,
    )
    with pytest.raises(ValueError, match="replicate seeds"):
        CanaryPanel(0, tuple(shared_seed_schedule), panel.protocol_sha256)


def test_v6_rejects_each_panel_minimum_and_reused_sample_id():
    panel = _panel()
    tasks = list(panel.tasks)
    tasks[1] = replace(tasks[1], task_family=tasks[0].task_family)
    with pytest.raises(ValueError, match="40 independent"):
        CanaryPanel(0, tuple(tasks), panel.protocol_sha256)

    one_stratum = tuple(replace(task, task_stratum="only") for task in panel.tasks)
    with pytest.raises(ValueError, match="3 task strata"):
        CanaryPanel(0, one_stratum, panel.protocol_sha256)

    sparse_stratum = tuple(
        replace(task, task_stratum="a" if index < 20 else "b" if index < 39 else "c")
        for index, task in enumerate(panel.tasks)
    )
    with pytest.raises(ValueError, match="3 independent families"):
        CanaryPanel(0, sparse_stratum, panel.protocol_sha256)

    with pytest.raises(ValueError, match="exactly 4 paired runs"):
        replace(
            panel.tasks[0], replicate_ids=(0, 1, 2), replicate_seeds=(101, 202, 303)
        )

    duplicate_id = list(panel.tasks)
    duplicate_id[1] = replace(duplicate_id[1], sample_ids=duplicate_id[0].sample_ids)
    with pytest.raises(ValueError, match="reuse sample IDs"):
        CanaryPanel(0, tuple(duplicate_id), panel.protocol_sha256)


def test_v6_attempt_501_has_no_alpha_allocation():
    with pytest.raises(ValueError):
        sequential_alpha(0.05, 501)


def test_benchmark_taxonomy_change_invalidates_panel_digest():
    panel = _panel()
    first = CanaryPanel(panel.epoch, panel.tasks, panel.protocol_sha256, "a" * 64)
    second = CanaryPanel(panel.epoch, panel.tasks, panel.protocol_sha256, "b" * 64)
    assert first.panel_sha256 != second.panel_sha256


def test_practical_effect_is_precommitted_and_recorded_in_decision():
    panel = _panel()
    policy = _pair_gate().task_pair_policy_config()
    changed_protocol = multitask_protocol_sha256(
        0.05, 0.01, 0.25, pair_gate_policy=policy
    )
    assert changed_protocol != panel.protocol_sha256
    pair_gates = {task_id: _pair_gate() for task_id in panel.task_ids}
    with pytest.raises(ValueError, match="protocol does not match"):
        TaskClusteredCanaryGate(
            panel=panel,
            pair_gates=pair_gates,
            promotion_attempt_index=1,
            family_alpha=0.05,
            allocated_alpha=sequential_alpha(0.05, 1),
            min_effect_size=0.01,
            max_task_regression=0.25,
        )
    changed_panel = CanaryPanel(panel.epoch, panel.tasks, changed_protocol)
    gate = TaskClusteredCanaryGate(
        panel=changed_panel,
        pair_gates=pair_gates,
        promotion_attempt_index=1,
        family_alpha=0.05,
        allocated_alpha=sequential_alpha(0.05, 1),
        min_effect_size=0.01,
        max_task_regression=0.25,
    )
    result = gate.evaluate_panel({})
    assert result.to_dict()["minimum_practical_effect"] == 0.01


def test_panel_digest_binds_each_sample_id_to_its_content_hashes():
    panel = _panel()
    original = panel.tasks[0]
    swapped = replace(
        original,
        sample_ids=("sample-a", "sample-b"),
        public_input_sha256=(_sha("public-a"), _sha("public-b")),
        sample_content_sha256=(_sha("full-a"), _sha("full-b")),
    )
    paired_permutation = replace(
        swapped,
        sample_ids=("sample-b", "sample-a"),
        public_input_sha256=(_sha("public-b"), _sha("public-a")),
        sample_content_sha256=(_sha("full-b"), _sha("full-a")),
    )
    remapped_content = replace(
        swapped,
        public_input_sha256=(_sha("public-b"), _sha("public-a")),
    )
    paired_panel = CanaryPanel(
        panel.epoch,
        (paired_permutation, *panel.tasks[1:]),
        panel.protocol_sha256,
    )
    baseline_panel = CanaryPanel(
        panel.epoch,
        (swapped, *panel.tasks[1:]),
        panel.protocol_sha256,
    )
    remapped_panel = CanaryPanel(
        panel.epoch,
        (remapped_content, *panel.tasks[1:]),
        panel.protocol_sha256,
    )

    assert paired_panel.panel_sha256 == baseline_panel.panel_sha256
    assert remapped_panel.panel_sha256 != baseline_panel.panel_sha256


def test_task_sign_test_uses_task_effects_and_treats_ties_as_nonwins():
    wins, tasks, p_value = task_sign_test(
        [0.1, 0.2, 0.0, -0.1], minimum_practical_effect=0.0
    )
    assert (wins, tasks) == (2, 4)
    assert p_value == pytest.approx(11 / 16)


def test_task_clustered_gate_rejects_missing_runs_and_wrong_alpha():
    panel = _panel()
    pair_gates = {task_id: _pair_gate() for task_id in panel.task_ids}
    with pytest.raises(ValueError, match="allocated alpha"):
        TaskClusteredCanaryGate(
            panel=panel,
            pair_gates=pair_gates,
            promotion_attempt_index=1,
            family_alpha=0.05,
            allocated_alpha=0.05,
            min_effect_size=0.0,
            max_task_regression=0.25,
        )
    gate = _gate(panel)
    pairs = {
        task_id: [
            (
                _journal(1.1, "challenger", index, replicate),
                _journal(1.0, "incumbent", index, replicate),
            )
            for replicate in range(2 if index == 0 else 4)
        ]
        for index, task_id in enumerate(panel.task_ids)
    }
    result = gate.evaluate_panel(pairs)
    assert not result.passed
    assert "all trusted paired runs" in result.reason


def test_family_clustered_effects_do_not_inflate_promotion_error():
    """Task and seed correlation stays inside one independent family sign."""
    alpha = sequential_alpha(0.05, 1)
    family_count = 20
    tasks_per_family = 2
    runs_per_task = 5
    task_sd = 0.03
    run_sd = 0.02
    for family_correlation in (0.0, 0.25, 0.5, 0.75, 0.95):
        rng = random.Random(20261001 + int(family_correlation * 100))
        false_promotions = 0
        trials = 2500
        for _ in range(trials):
            family_effects = []
            for _family in range(family_count):
                shared_family_effect = rng.gauss(
                    0.0, task_sd * math.sqrt(family_correlation)
                )
                task_effects = []
                for _task in range(tasks_per_family):
                    task_effect = shared_family_effect + rng.gauss(
                        0.0, task_sd * math.sqrt(1.0 - family_correlation)
                    )
                    shared_seed_noise = rng.gauss(0.0, run_sd * math.sqrt(0.75))
                    runs = [
                        task_effect
                        + shared_seed_noise
                        + rng.gauss(0.0, run_sd * math.sqrt(0.25))
                        for _ in range(runs_per_task)
                    ]
                    task_effects.append(float(median(runs)))
                family_effects.append(float(median(task_effects)))
            decision = task_effect_decision(
                family_effects,
                allocated_alpha=alpha,
                minimum_practical_effect=0.0,
                maximum_task_regression=0.25,
            )
            false_promotions += int(decision["passed"])
        rate = false_promotions / trials
        # Dependence is fully contained inside each independently sampled
        # family cluster before its single sign enters the exact test.
        assert rate < alpha + 0.015, (
            family_correlation,
            rate,
            false_promotions,
        )


def test_exact_sign_cutoff_tracks_allocated_alpha():
    panel = _panel()
    result = _gate(panel).evaluate_panel(
        {
            task_id: [
                (
                    _journal(1.1, "challenger", index, replicate),
                    _journal(1.0, "incumbent", index, replicate),
                )
                for replicate in range(4)
            ]
            for index, task_id in enumerate(panel.task_ids)
        }
    )
    assert result.critical_positive_families == 32
    assert result.total_families == 40

    late_gate = TaskClusteredCanaryGate(
        panel=panel,
        pair_gates={task_id: _pair_gate() for task_id in panel.task_ids},
        promotion_attempt_index=300,
        family_alpha=0.05,
        allocated_alpha=sequential_alpha(0.05, 300),
        min_effect_size=0.0,
        max_task_regression=0.25,
    )
    late_result = late_gate.evaluate_panel(
        {
            task_id: [
                (
                    _journal(1.1, "challenger", index, replicate),
                    _journal(1.0, "incumbent", index, replicate),
                )
                for replicate in range(4)
            ]
            for index, task_id in enumerate(panel.task_ids)
        }
    )
    assert late_result.critical_positive_families == 32
    assert late_result.passed


def test_interrupted_multitask_panel_is_burned_and_alpha_is_not_refunded(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("AIDE_RSI_EVALUATION_HMAC_KEY", _TEST_KEY)
    panel = _panel()
    gate = _gate(panel)
    rsi_dir = tmp_path / "run" / "rsi"
    store = RSIStateStore(rsi_dir / "state.json", require_attestation=True)
    initial = StatisticalBudget.initial(0.05)
    store.write(
        phase="IDLE",
        current_round=0,
        next_round=0,
        canary_attempt_count=0,
        canary_experiment_alpha=0.05,
        statistical_protocol_sha256=panel.protocol_sha256,
        statistical_budget=initial.to_dict(),
        consumed_canary_panel_sha256=[],
        consumed_canary_task_sha256=[],
    )
    reservation = initial.reserve(
        panel_sha256=panel.panel_sha256,
        protocol_sha256=panel.protocol_sha256,
    )
    task_hashes = sorted(task.task_sha256 for task in panel.tasks)
    store.write(
        phase="CANARY_RUNNING",
        current_round=0,
        next_round=0,
        pending_digest=_sha("pending-policy"),
        active_canary_panel_sha256=panel.panel_sha256,
        canary_attempt_count=1,
        statistical_budget=reservation.to_dict(),
        consumed_canary_panel_sha256=[panel.panel_sha256],
        consumed_canary_task_sha256=task_hashes,
    )
    canary_root = tmp_path / "run" / "round-000" / "canary"
    canary_root.mkdir(parents=True)
    (canary_root / "transaction.json").write_text('{"partial":true}')

    recovered = _recover_multitask_canary_transaction(
        state=store.load(),
        state_store=store,
        rsi_dir=rsi_dir,
        canary_gate=gate,
    )

    assert recovered["phase"] == "IDLE"
    assert recovered["pending_digest"] is None
    assert recovered["last_canary"]["status"] == "aborted"
    assert recovered["statistical_budget"]["attempt_index"] == 1
    assert recovered["statistical_budget"]["remaining_alpha"] == pytest.approx(
        0.05 - 0.05 / 500
    )
    assert panel.panel_sha256 in recovered["consumed_canary_panel_sha256"]
    assert set(task_hashes) <= set(recovered["consumed_canary_task_sha256"])
