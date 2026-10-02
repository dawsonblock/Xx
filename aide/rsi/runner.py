from __future__ import annotations

import copy
import hashlib
import json
import math
import os
import random
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .artifacts import load_candidate, store_candidate
from .canary import RealCanaryGate, TaskClusteredCanaryGate
from .evaluator import ReplayEvaluator
from .evidence import (
    has_trusted_evaluation,
    has_trusted_world_evidence,
    has_valid_canary_attestation,
    has_valid_canary_transaction,
    sign_canary_decision,
    sign_canary_transaction,
)
from .evolution import PolicyEvolutionEngine
from .jev import JevAdvisor
from .live import LiveExplorationController
from .memory import summarize_worlds
from .metrics import live_cycle_summary
from .policy import AdaptiveReplayPolicy
from .pool import ReplayWorldPool
from .qualification import QualificationGate
from .sandbox import SandboxLimits, SecureInterpreter
from .split import PersistentSplitManager
from .state import RSIStateStore, rsi_writer_lock
from .statistics import (
    CanaryPanel,
    CanaryPanelTask,
    StatisticalBudget,
    canary_execution_schedule,
    multitask_protocol_sha256,
    sequential_alpha,
    statistical_epoch_sha256,
)
from .support import ReplaySupportIndex
from .types import PolicyGenome
from .world import world_from_journal


def _stable_digest(value: Any) -> str:
    try:
        payload = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    except TypeError:
        payload = repr(value)
    return hashlib.sha256(payload.encode()).hexdigest()


def _policy_digest(genome: PolicyGenome | None) -> str | None:
    if genome is None:
        return None
    payload = json.dumps(genome.to_dict(), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()


@dataclass(frozen=True)
class _CanaryPanelTaskRuntime:
    task_id: str
    task_family: str
    task_description: str
    task_metric: Any
    evaluator: Any
    public_data_dir: Path
    definition: CanaryPanelTask


@dataclass(frozen=True)
class _CanaryPanelRuntime:
    panel: CanaryPanel
    tasks: tuple[_CanaryPanelTaskRuntime, ...]

    @property
    def identity(self) -> str:
        return self.panel.panel_sha256

    @property
    def authority_identity(self) -> str:
        authorities = []
        for task in self.tasks:
            evaluator = task.evaluator
            authorities.append(
                {
                    "evaluator_sha256": evaluator.evaluator_sha256,
                    "environment_sha256": evaluator.environment_sha256,
                    "sandbox_backend": evaluator.sandbox_backend,
                    "timeout_s": evaluator.timeout_s,
                    "max_output_bytes": evaluator.max_output_bytes,
                    "max_memory_bytes": evaluator.max_memory_bytes,
                    "max_processes": evaluator.max_processes,
                    "max_open_files": evaluator.max_open_files,
                }
            )
        if any(authority != authorities[0] for authority in authorities[1:]):
            raise ValueError(
                "all canary panel tasks must use one stable evaluator execution authority"
            )
        return _stable_digest(
            {
                "domain": "aide-rsi-multitask-evaluator-authority/v1",
                **authorities[0],
            }
        )

    @property
    def evaluation_sample_ids(self) -> frozenset[str]:
        return frozenset(
            f"{task.definition.task_sha256}:{sample_id}"
            for task in self.tasks
            for sample_id in task.evaluator.evaluation_sample_ids
        )

    @property
    def evaluation_sample_content_sha256(self) -> frozenset[str]:
        return frozenset(
            digest
            for task in self.tasks
            for digest in task.evaluator.evaluation_sample_content_sha256 or ()
        )

    @property
    def evaluation_sample_public_input_sha256(self) -> frozenset[str]:
        return frozenset(
            digest
            for task in self.tasks
            for digest in task.evaluator.evaluation_sample_public_input_sha256 or ()
        )


def _task_path_component(task_id: str) -> str:
    return hashlib.sha256(task_id.encode("utf-8")).hexdigest()[:16]


def _panel_seed_schedule_sha256(panel: CanaryPanel) -> str:
    return _stable_digest(
        {
            task.task_id: [
                [replicate, task.seed_for(replicate)]
                for replicate in task.replicate_ids
            ]
            for task in sorted(panel.tasks, key=lambda item: item.task_id)
        }
    )


def _panel_execution_schedule(panel: CanaryPanel) -> list[dict[str, Any]]:
    task_by_id = {task.task_id: task for task in panel.tasks}
    return [
        {
            **scheduled,
            "shard_sha256": task_by_id[scheduled["task_id"]].shard_sha256,
            "budget_per_run": task_by_id[scheduled["task_id"]].budget_per_run,
        }
        for scheduled in canary_execution_schedule(panel)
    ]


def _panel_execution_schedule_sha256(panel: CanaryPanel) -> str:
    return _stable_digest(
        {
            "panel_sha256": panel.panel_sha256,
            "protocol_sha256": panel.protocol_sha256,
            "runs": _panel_execution_schedule(panel),
        }
    )


def _panel_sample_identity_records(panel: CanaryPanel) -> list[dict[str, str]]:
    """Flatten the panel's canonical row identities without losing ownership."""
    return [
        {
            "task_id": task.task_id,
            "task_sha256": task.task_sha256,
            **sample_identity,
        }
        for task in sorted(panel.tasks, key=lambda item: item.task_id)
        for sample_identity in task.sample_identity_records()
    ]


def _sample_identity_record_sha256(record: dict[str, str]) -> str:
    return _stable_digest(
        {
            "domain": "aide-rsi-canary-sample-identity-reservation/v1",
            "record": record,
        }
    )


def _verify_panel_sample_identity_reservation(
    recorded: Any, panel: CanaryPanel, durable_state: dict[str, Any]
) -> None:
    """Verify transaction rows and their authenticated durable reservation."""
    expected = _panel_sample_identity_records(panel)
    if recorded != expected:
        raise ValueError(
            "multi-task transaction sample identity records do not match its panel"
        )
    record_digests = [_sample_identity_record_sha256(record) for record in expected]
    if not set(record_digests) <= set(
        durable_state.get("consumed_canary_sample_identity_sha256", [])
    ):
        raise ValueError("canary sample identity records were not durably reserved")


def _task_pair_gate_template(
    cfg, *, artifact_root: Path, expected_identity: dict[str, Any] | None = None
) -> RealCanaryGate:
    return RealCanaryGate(
        max_normalized_regression=cfg.rsi.canary.max_normalized_regression,
        min_valid=cfg.rsi.canary.min_valid,
        score_scale_floor=cfg.rsi.canary.score_scale_floor,
        artifact_root=artifact_root,
        require_artifacts=True,
        expected_evaluation_identity=expected_identity,
    )


def _build_canary_panel(cfg, *, task_metric_type, add_metric, artifact_root):
    """Resolve and pin the operator-supplied multi-task canary panel."""
    from .trusted_evaluator import create_trusted_evaluator, tree_sha256

    task_configs = list(getattr(cfg.rsi, "canary_panel", []) or [])
    if not task_configs:
        return None
    epoch = getattr(cfg.rsi, "canary_panel_epoch", 0)
    if isinstance(epoch, bool) or not isinstance(epoch, int) or epoch < 0:
        raise ValueError("rsi.canary_panel_epoch must be a nonnegative integer")
    family_alpha = float(cfg.rsi.canary.experiment_alpha)
    min_effect = float(cfg.rsi.canary.min_effect_size)
    max_task_regression = float(cfg.rsi.canary.max_single_task_regression)
    pair_gate_policy = _task_pair_gate_template(
        cfg, artifact_root=Path(artifact_root)
    ).task_pair_policy_config()
    protocol_sha = multitask_protocol_sha256(
        family_alpha,
        min_effect,
        max_task_regression,
        pair_gate_policy=pair_gate_policy,
    )
    runtimes = []
    definitions = []
    for item in task_configs:
        task_id = str(getattr(item, "task_id", "") or "").strip()
        task_family = str(getattr(item, "task_family", "") or "").strip()
        task_stratum = str(getattr(item, "task_stratum", "") or "").strip()
        description_value = getattr(item, "task_description_file", None)
        public_dir_value = getattr(item, "public_data_dir", None)
        expected_public_digest = str(getattr(item, "public_data_sha256", "") or "")
        evaluator_config = getattr(item, "evaluator", None)
        if (
            not task_id
            or not task_family
            or not task_stratum
            or not description_value
            or not public_dir_value
        ):
            raise ValueError(
                "each canary panel task requires task_id, independent task_family, task_stratum, task_description_file, and public_data_dir"
            )
        description_path = Path(description_value).expanduser()
        if description_path.is_symlink():
            raise ValueError("canary task description must be a regular file")
        description_path = description_path.resolve(strict=True)
        if not description_path.is_file():
            raise ValueError("canary task description must be a regular file")
        task_description = description_path.read_text(encoding="utf-8")
        if not task_description.strip():
            raise ValueError("canary task description cannot be empty")
        public_data_dir = Path(public_dir_value).expanduser()
        if public_data_dir.is_symlink():
            raise ValueError("canary public data root must not be a symlink")
        public_data_dir = public_data_dir.resolve(strict=True)
        actual_public_digest = tree_sha256(public_data_dir)
        if actual_public_digest != expected_public_digest:
            raise ValueError(
                f"canary task {task_id} public data does not match its SHA-256 pin"
            )
        metric_id = str(getattr(evaluator_config, "metric_id", "") or "").strip()
        metric_maximize = getattr(evaluator_config, "metric_maximize", None)
        if not metric_id or not isinstance(metric_maximize, bool):
            raise ValueError(
                f"canary task {task_id} evaluator requires a fixed metric and direction"
            )
        metric = task_metric_type(name=metric_id, maximize=metric_maximize)
        pinned_description = add_metric(task_description, metric)
        evaluator = create_trusted_evaluator(
            evaluator_config,
            task_description=pinned_description,
            artifact_root=artifact_root,
        )
        if evaluator is None:
            raise ValueError(f"canary panel task {task_id} evaluator is disabled")
        if evaluator.evaluation_sample_ids is None:
            raise ValueError(
                f"canary panel task {task_id} requires canonical evaluation_sample_ids"
            )
        if (
            evaluator.evaluation_sample_content_sha256 is None
            or evaluator.evaluation_sample_public_input_sha256 is None
            or evaluator.evaluation_sample_identities is None
        ):
            raise ValueError(
                f"canary panel task {task_id} requires the first-party evaluator's canonical sample identities"
            )
        replicate_ids = tuple(item.replicate_ids)
        replicate_seeds = tuple(item.replicate_seeds)
        # The task identity follows the canonical task description, not its
        # operator-assigned label, so renaming a task cannot create another
        # independent promotion unit.
        task_identity = evaluator.task_sha256
        sample_identities = tuple(
            sorted(
                evaluator.evaluation_sample_identities,
                key=lambda identity: identity.sample_id,
            )
        )
        if tuple(identity.sample_id for identity in sample_identities) != tuple(
            evaluator.evaluation_sample_ids
        ):
            raise ValueError(
                f"canary panel task {task_id} sample identities do not match its pinned split"
            )
        definition = CanaryPanelTask(
            task_id=task_id,
            task_family=task_family,
            task_stratum=task_stratum,
            task_sha256=task_identity,
            evaluator_authority_sha256=evaluator.authority_identity,
            shard_sha256=evaluator.identity,
            dataset_sha256=evaluator.dataset_sha256,
            split_sha256=evaluator.split_sha256,
            metric_id=evaluator.metric_id,
            metric_maximize=evaluator.metric_maximize,
            sample_ids=tuple(identity.sample_id for identity in sample_identities),
            public_input_sha256=tuple(
                identity.public_input_sha256 for identity in sample_identities
            ),
            sample_content_sha256=tuple(
                identity.sample_content_sha256 for identity in sample_identities
            ),
            replicate_ids=replicate_ids,
            replicate_seeds=replicate_seeds,
            budget_per_run=item.budget_per_run,
            public_data_sha256=actual_public_digest,
        )
        definitions.append(definition)
        runtimes.append(
            _CanaryPanelTaskRuntime(
                task_id,
                task_family,
                pinned_description,
                metric,
                evaluator,
                public_data_dir,
                definition,
            )
        )
    panel = CanaryPanel(
        epoch=epoch,
        tasks=tuple(definitions),
        protocol_sha256=protocol_sha,
    )
    return _CanaryPanelRuntime(
        panel,
        tuple(sorted(runtimes, key=lambda item: item.task_id)),
    )


def _validate_search_panel_roles(search, panel_runtime) -> None:
    if search is None:
        raise ValueError("multi-task promotion requires a trusted search evaluator")
    search_ids = set(search.evaluation_sample_ids or ())
    search_public = set(search.evaluation_sample_public_input_sha256 or ())
    search_content = set(search.evaluation_sample_content_sha256 or ())
    for task in panel_runtime.tasks:
        evaluator = task.evaluator
        if task.definition.task_sha256 == search.task_sha256:
            raise ValueError(
                "canary panel includes the search task as a promotion unit"
            )
        if evaluator.metric_id != task.definition.metric_id or (
            evaluator.metric_maximize is not task.definition.metric_maximize
        ):
            raise ValueError("canary panel metric identity changed during construction")
        if search_ids.intersection(evaluator.evaluation_sample_ids or ()):
            raise ValueError("canary panel overlaps search evaluation sample IDs")
        if search_public.intersection(
            evaluator.evaluation_sample_public_input_sha256 or ()
        ):
            raise ValueError("canary panel duplicates search candidate-visible inputs")
        if search_content.intersection(
            evaluator.evaluation_sample_content_sha256 or ()
        ):
            raise ValueError("canary panel duplicates search sample content")


def _used_canary_retirements(
    base_log: Path, durable_state: dict[str, Any] | None = None
) -> tuple[set[str], set[str], set[str]]:
    """Recover IDs, full records, and candidate-visible identities."""
    sample_ids = (durable_state or {}).get("consumed_canary_sample_ids", [])
    if not isinstance(sample_ids, list) or any(
        not isinstance(sample_id, str) or not sample_id for sample_id in sample_ids
    ):
        raise ValueError("durable canary retirement set is invalid")
    used: set[str] = set(sample_ids)
    content_hashes = (durable_state or {}).get(
        "consumed_canary_sample_content_sha256", []
    )
    if not isinstance(content_hashes, list) or any(
        not isinstance(value, str)
        or len(value) != 64
        or any(char not in "0123456789abcdef" for char in value)
        for value in content_hashes
    ):
        raise ValueError("durable canary content retirement set is invalid")
    used_content: set[str] = set(content_hashes)
    public_hashes = (durable_state or {}).get("consumed_canary_public_input_sha256", [])
    if not isinstance(public_hashes, list) or any(
        not isinstance(value, str)
        or len(value) != 64
        or any(char not in "0123456789abcdef" for char in value)
        for value in public_hashes
    ):
        raise ValueError("durable canary public-input retirement set is invalid")
    used_public: set[str] = set(public_hashes)
    for path in base_log.glob("round-*/canary/transaction.json"):
        if path.is_symlink() or not path.is_file():
            raise ValueError("canary transaction must be a regular file")
        try:
            transaction = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError("canary reservation ledger is corrupt") from exc
        if not isinstance(transaction, dict) or not has_valid_canary_transaction(
            transaction
        ):
            raise ValueError("canary reservation ledger has no valid host signature")
        sample_ids = transaction.get("evaluation_sample_ids")
        if not isinstance(sample_ids, list) or any(
            not isinstance(sample_id, str) or not sample_id for sample_id in sample_ids
        ):
            raise ValueError("canary reservation ledger has invalid sample IDs")
        used.update(sample_ids)
        transaction_content = transaction.get("evaluation_sample_content_sha256", [])
        if not isinstance(transaction_content, list) or any(
            not isinstance(value, str)
            or len(value) != 64
            or any(char not in "0123456789abcdef" for char in value)
            for value in transaction_content
        ):
            raise ValueError("canary reservation ledger has invalid content hashes")
        used_content.update(transaction_content)
        transaction_public = transaction.get(
            "evaluation_sample_public_input_sha256", []
        )
        if not isinstance(transaction_public, list) or any(
            not isinstance(value, str)
            or len(value) != 64
            or any(char not in "0123456789abcdef" for char in value)
            for value in transaction_public
        ):
            raise ValueError(
                "canary reservation ledger has invalid public-input hashes"
            )
        used_public.update(transaction_public)
    return used, used_content, used_public


def _used_canary_sample_ids(
    base_log: Path, durable_state: dict[str, Any] | None = None
) -> set[str]:
    """Compatibility helper returning consumed sample IDs."""
    return _used_canary_retirements(base_log, durable_state)[0]


def _canary_shard_overlaps_retired(
    sample_ids: set[str] | tuple[str, ...],
    content_hashes: set[str] | frozenset[str] | None,
    used_ids: set[str],
    used_content_hashes: set[str],
    public_input_hashes: set[str] | frozenset[str] | None = None,
    used_public_input_hashes: set[str] | None = None,
) -> bool:
    return bool(
        set(sample_ids) & used_ids
        or (set(content_hashes or ()) & used_content_hashes)
        or (set(public_input_hashes or ()) & set(used_public_input_hashes or ()))
    )


def _validate_canary_shard_rotation(
    *,
    state: dict[str, Any],
    canary_evaluator,
    shard_identity: str | None,
    shard_epoch: int,
    base_log: Path,
) -> None:
    """Validate one explicit, monotonic rotation to a fresh canary shard."""
    stored_identity = state.get("canary_shard_identity")
    stored_epoch = state.get("canary_shard_epoch")
    if isinstance(stored_epoch, bool) or not isinstance(stored_epoch, int):
        raise TypeError("durable canary shard epoch must be an integer")
    if stored_identity == shard_identity:
        if shard_epoch != stored_epoch:
            raise ValueError("canary shard_epoch changed without rotating the shard")
        return
    stored_authorities = _stored_evaluator_identity(state)
    if not isinstance(stored_authorities, dict) or stored_authorities.get(
        "canary"
    ) != getattr(canary_evaluator, "authority_identity", None):
        raise ValueError("canary evaluator authority changed during shard rotation")
    if state.get("phase") == "CANARY_RUNNING":
        raise ValueError(
            "cannot rotate canary shards while a canary transaction is active"
        )
    if shard_identity is None or canary_evaluator is None:
        raise ValueError("canary shard rotation requires an enabled canary evaluator")
    if shard_epoch != stored_epoch + 1:
        raise ValueError("a fresh canary shard requires shard_epoch to increase by one")
    retired_ids, retired_full, retired_public = _used_canary_retirements(
        base_log, state
    )
    if _canary_shard_overlaps_retired(
        canary_evaluator.evaluation_sample_ids or (),
        canary_evaluator.evaluation_sample_content_sha256,
        retired_ids,
        retired_full,
        canary_evaluator.evaluation_sample_public_input_sha256,
        retired_public,
    ):
        raise ValueError("new canary shard reuses retired evaluation samples")
    if isinstance(canary_evaluator, _CanaryPanelRuntime):
        retired_tasks = set(state.get("consumed_canary_task_sha256", []))
        new_tasks = {task.task_sha256 for task in canary_evaluator.panel.tasks}
        if retired_tasks.intersection(new_tasks):
            raise ValueError("new canary panel reuses a previously tested task")


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n")
    tmp.replace(path)


def _atomic_write_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def _publish_best_from_worlds(
    worlds, base_log: Path
) -> tuple[float | None, dict[str, Any]]:
    """Rebuild the published solution from committed worlds after any interrupted run."""
    best = None
    for world in worlds:
        for node in world.nodes.values():
            if not node.valid or node.score is None or not math.isfinite(node.score):
                continue
            if not node.provenance.get("candidate_sha256"):
                # Legacy worlds lack source-to-score binding and cannot publish
                # an artifact as if its source had been verified.
                continue
            if not has_trusted_evaluation(
                node,
                maximize=world.maximize,
                artifact_root=base_log / "rsi" / "artifacts",
                require_artifacts=True,
            ):
                # Candidate output interpreted by a feedback model is useful for
                # exploration, but cannot authorize a published best artifact.
                continue
            if best is None or (
                node.score > best[1].score
                if world.maximize
                else node.score < best[1].score
            ):
                best = (world, node)
    if best is None:
        return None, {}

    world, node = best
    round_no = int(world.metadata["round"])
    candidate_sha256 = str(node.provenance["candidate_sha256"])
    code = load_candidate(candidate_sha256, base_log / "rsi" / "artifacts")
    meta = {
        "round": round_no,
        "node_id": node.id,
        "score": node.score,
        "policy_digest": world.metadata.get("policy_digest"),
        "world_id": world.world_id,
        "candidate_sha256": candidate_sha256,
    }
    # Either file can be interrupted independently. The next startup rebuilds
    # both from the committed pool, including after a completed run.
    _atomic_write_text(base_log / "best_solution.py", code)
    _write_json(base_log / "best_solution.manifest.json", meta)
    return node.score, meta


def _recover_canary_transaction(
    *,
    state: dict[str, Any],
    state_store: RSIStateStore,
    rsi_dir: Path,
    canary_gate: RealCanaryGate,
) -> dict[str, Any]:
    """Recompute and authenticate a canary before completing interrupted promotion."""
    phase = state.get("phase")
    if phase not in {"CANARY_RUNNING", "IDLE"}:
        return state
    round_no = int(state.get("current_round", state.get("next_round", 0)))
    canary_root = rsi_dir.parent / f"round-{round_no:03d}" / "canary"
    transaction_path = canary_root / "transaction.json"
    decision_path = canary_root / "decision.json"
    if not (transaction_path.exists() and decision_path.exists()):
        if phase == "CANARY_RUNNING":
            return _abort_canary_recovery(
                state=state,
                state_store=state_store,
                rsi_dir=rsi_dir,
                round_no=round_no,
                reason="incomplete_canary_burned_shard",
                transaction_present=transaction_path.is_file(),
                decision_present=decision_path.is_file(),
            )
        return state
    if transaction_path.is_symlink() or decision_path.is_symlink():
        raise ValueError("canary recovery evidence must be regular files")
    transaction = json.loads(transaction_path.read_text())
    decision = json.loads(decision_path.read_text())
    if not isinstance(transaction, dict) or not isinstance(decision, dict):
        raise TypeError("invalid canary recovery record")
    if not has_valid_canary_transaction(transaction):
        raise ValueError("canary transaction has no valid host attestation")
    transaction_sample_ids = transaction.get("evaluation_sample_ids", [])
    transaction_full_hashes = transaction.get("evaluation_sample_content_sha256", [])
    transaction_public_hashes = transaction.get(
        "evaluation_sample_public_input_sha256", []
    )
    if not isinstance(transaction_sample_ids, list) or any(
        not isinstance(value, str) or not value for value in transaction_sample_ids
    ):
        raise ValueError("canary transaction has invalid evaluation sample IDs")
    for name, values in (
        ("full-record", transaction_full_hashes),
        ("public-input", transaction_public_hashes),
    ):
        if not isinstance(values, list) or any(
            not isinstance(value, str)
            or len(value) != 64
            or any(char not in "0123456789abcdef" for char in value)
            for value in values
        ):
            raise ValueError(f"canary transaction has invalid {name} sample hashes")
    if not set(transaction_sample_ids) <= set(
        state.get("consumed_canary_sample_ids", [])
    ):
        raise ValueError("canary transaction samples were not durably reserved")
    if not set(transaction_full_hashes) <= set(
        state.get("consumed_canary_sample_content_sha256", [])
    ):
        raise ValueError("canary transaction record hashes were not durably reserved")
    if not set(transaction_public_hashes) <= set(
        state.get("consumed_canary_public_input_sha256", [])
    ):
        raise ValueError("canary transaction public inputs were not durably reserved")
    transaction_shard_fields = {
        "canary_authority_identity",
        "canary_shard_identity",
        "canary_shard_epoch",
    }
    present_shard_fields = transaction_shard_fields.intersection(transaction)
    if present_shard_fields and present_shard_fields != transaction_shard_fields:
        raise ValueError("canary transaction has incomplete shard identity")
    if present_shard_fields:
        stored_authorities = _stored_evaluator_identity(state)
        expected_identity = canary_gate.expected_evaluation_identity.get(
            "trusted_evaluator_identity"
        )
        if (
            not isinstance(stored_authorities, dict)
            or transaction["canary_authority_identity"]
            != stored_authorities.get("canary")
            or transaction["canary_shard_identity"]
            != state.get("canary_shard_identity")
            or transaction["canary_shard_identity"] != expected_identity
            or transaction["canary_shard_epoch"] != state.get("canary_shard_epoch")
        ):
            raise ValueError(
                "canary transaction shard is not authorized by durable state"
            )
    if canary_gate.promotion_attempt_index is not None:
        attempt_index = canary_gate.promotion_attempt_index
        if (
            transaction.get("promotion_attempt_index") != attempt_index
            or state.get("canary_attempt_count") != attempt_index
        ):
            raise ValueError(
                "canary promotion attempt is not authorized by durable state"
            )
        if "statistical_budget" in state:
            budget = StatisticalBudget.from_dict(state["statistical_budget"])
            budget_digest = budget.digest()
            if (
                budget.attempt_index != attempt_index
                or transaction.get("statistical_budget_sha256") != budget_digest
                or decision.get("statistical_budget_sha256") != budget_digest
            ):
                raise ValueError(
                    "canary evidence does not match the durable statistical budget"
                )
    incumbent = PolicyGenome.from_dict(transaction["incumbent"])
    challenger = PolicyGenome.from_dict(transaction["challenger"])
    if _policy_digest(incumbent) != transaction.get("incumbent_digest"):
        raise ValueError("canary recovery incumbent digest mismatch")
    if _policy_digest(challenger) != transaction.get("candidate_digest"):
        raise ValueError("canary recovery candidate digest mismatch")
    if decision.get("incumbent_digest") != transaction["incumbent_digest"]:
        raise ValueError("canary decision does not match its incumbent transaction")
    if decision.get("candidate_digest") != transaction["candidate_digest"]:
        raise ValueError("canary decision does not match its challenger transaction")
    if canary_gate.promotion_attempt_index is not None and (
        decision.get("promotion_attempt_index") != canary_gate.promotion_attempt_index
    ):
        raise ValueError("canary decision has a different promotion attempt index")
    if phase == "IDLE":
        # Only reconcile the crash window after the durable state commit. Old or
        # unrelated transaction files must never gain authority from their names.
        if (
            state.get("pending_digest") is not None
            or state.get("last_canary") != decision
        ):
            return state
        winner_digest = (
            transaction["candidate_digest"]
            if decision.get("passed")
            else transaction["incumbent_digest"]
        )
        if state.get("incumbent_digest") != winner_digest:
            raise ValueError("committed canary state does not match its decision")
    else:
        if int(transaction.get("round", -1)) != round_no:
            raise ValueError("canary recovery round does not match durable state")
        if state.get("incumbent_digest") != transaction["incumbent_digest"]:
            raise ValueError("canary incumbent is not authorized by durable state")
        if state.get("pending_digest") != transaction["candidate_digest"]:
            raise ValueError("canary challenger is not authorized by durable state")
        incumbent_path = rsi_dir / "incumbent_policy.json"
        pending_path = rsi_dir / "pending_policy.json"
        if not incumbent_path.is_file():
            raise ValueError("authorized incumbent policy is missing during recovery")
        stored_incumbent_digest = _policy_digest(PolicyGenome.load(incumbent_path))
        # The live writer saves the winning policy immediately before committing
        # state. A crash in that narrow window can leave either authorized policy
        # on disk; the attested journals below decide which one may win.
        if stored_incumbent_digest not in {
            transaction["incumbent_digest"],
            transaction["candidate_digest"],
        }:
            raise ValueError(
                "durable incumbent policy does not match canary transaction"
            )
        if pending_path.exists() and (
            pending_path.is_symlink()
            or not pending_path.is_file()
            or _policy_digest(PolicyGenome.load(pending_path))
            != transaction["candidate_digest"]
        ):
            raise ValueError("durable pending policy does not match canary transaction")

    if not has_valid_canary_attestation(decision):
        raise ValueError("canary decision has no valid host attestation")
    if (
        decision.get("transaction_sha256")
        != hashlib.sha256(transaction_path.read_bytes()).hexdigest()
    ):
        raise ValueError("canary transaction digest does not match attested decision")
    gate_config = canary_gate.authority_config()
    gate_config_digest = _stable_digest(gate_config)
    if decision.get("gate_config_sha256") != gate_config_digest:
        raise ValueError("canary gate configuration changed since decision")

    evidence = decision.get("journal_evidence")
    repeats = int(transaction.get("repeats", 0))
    expected_paths = [
        f"rep-{rep:02d}/{side}/journal.json"
        for rep in range(repeats)
        for side in ("challenger", "incumbent")
    ]
    if (
        not isinstance(evidence, list)
        or [x.get("path") for x in evidence if isinstance(x, dict)] != expected_paths
    ):
        raise ValueError("canary decision does not bind every paired journal")
    from aide.journal import Journal
    from aide.utils import serialize

    paired_journals = []
    for rep in range(repeats):
        loaded = {}
        for side in ("challenger", "incumbent"):
            relative = f"rep-{rep:02d}/{side}/journal.json"
            journal_path = canary_root / relative
            if journal_path.is_symlink() or not journal_path.is_file():
                raise ValueError("canary journal evidence is missing")
            evidence_item = evidence[expected_paths.index(relative)]
            if (
                evidence_item.get("sha256")
                != hashlib.sha256(journal_path.read_bytes()).hexdigest()
            ):
                raise ValueError(
                    "canary journal digest does not match attested decision"
                )
            loaded[side] = serialize.load_json(journal_path, Journal)
        paired_journals.append((loaded["challenger"], loaded["incumbent"]))
    recomputed = canary_gate.evaluate_series(paired_journals).to_dict()
    if decision.get("gate_result") != recomputed or bool(
        decision.get("passed")
    ) != bool(recomputed["passed"]):
        raise ValueError("canary gate result does not recompute from attested journals")

    winner = challenger if recomputed["passed"] else incumbent
    if phase == "IDLE":
        pending_path = rsi_dir / "pending_policy.json"
        if pending_path.exists():
            pending_path.unlink()
        return state
    winner.save(rsi_dir / "incumbent_policy.json")
    pending_path = rsi_dir / "pending_policy.json"
    if pending_path.exists():
        pending_path.unlink()
    return state_store.write(
        phase="IDLE",
        current_round=round_no,
        next_round=round_no,
        incumbent_digest=_policy_digest(winner),
        pending_digest=None,
        last_canary=decision,
    )


def _recover_multitask_canary_transaction(
    *,
    state: dict[str, Any],
    state_store: RSIStateStore,
    rsi_dir: Path,
    canary_gate: TaskClusteredCanaryGate,
) -> dict[str, Any]:
    """Verify and recompute the exact reserved multi-task panel decision."""
    if state.get("phase") != "CANARY_RUNNING":
        return state
    round_no = int(state.get("current_round", state.get("next_round", 0)))
    canary_root = rsi_dir.parent / f"round-{round_no:03d}" / "canary"
    transaction_path = canary_root / "transaction.json"
    decision_path = canary_root / "decision.json"
    if not transaction_path.is_file() or not decision_path.is_file():
        return _abort_canary_recovery(
            state=state,
            state_store=state_store,
            rsi_dir=rsi_dir,
            round_no=round_no,
            reason="incomplete_multitask_canary_burned_panel",
            transaction_present=transaction_path.is_file(),
            decision_present=decision_path.is_file(),
        )
    if transaction_path.is_symlink() or decision_path.is_symlink():
        raise ValueError("multi-task canary records must be regular files")
    transaction = json.loads(transaction_path.read_text(encoding="utf-8"))
    decision = json.loads(decision_path.read_text(encoding="utf-8"))
    if not isinstance(transaction, dict) or not isinstance(decision, dict):
        raise TypeError("multi-task canary records must be JSON objects")
    if not has_valid_canary_transaction(transaction):
        raise ValueError("multi-task canary transaction has no host attestation")
    panel = CanaryPanel.from_dict(transaction.get("panel"))
    _verify_panel_sample_identity_reservation(
        transaction.get("evaluation_sample_identity_records"), panel, state
    )
    if (
        panel.to_dict() != canary_gate.panel.to_dict()
        or transaction.get("panel_sha256") != panel.panel_sha256
        or transaction.get("protocol_sha256") != panel.protocol_sha256
        or state.get("active_canary_panel_sha256") != panel.panel_sha256
        or state.get("statistical_protocol_sha256") != panel.protocol_sha256
        or transaction.get("statistical_epoch_sha256")
        != state.get("statistical_epoch_sha256")
        or decision.get("statistical_epoch_sha256")
        != state.get("statistical_epoch_sha256")
        or panel.panel_sha256 not in state.get("consumed_canary_panel_sha256", [])
    ):
        raise ValueError("reserved canary panel does not match durable authority")
    budget = StatisticalBudget.from_dict(state.get("statistical_budget", {}))
    budget_digest = budget.digest()
    if (
        budget.panel_sha256 != panel.panel_sha256
        or budget.protocol_sha256 != panel.protocol_sha256
        or transaction.get("statistical_budget_sha256") != budget_digest
        or decision.get("statistical_budget_sha256") != budget_digest
        or transaction.get("promotion_attempt_index") != budget.attempt_index
        or decision.get("promotion_attempt_index") != budget.attempt_index
        or transaction.get("allocated_alpha") != budget.last_allocation
        or decision.get("allocated_alpha") != budget.last_allocation
        or state.get("canary_attempt_count") != budget.attempt_index
        or budget.attempt_index != canary_gate.promotion_attempt_index
    ):
        raise ValueError("multi-task canary alpha reservation does not match state")
    task_digests = {task.task_sha256 for task in panel.tasks}
    if (
        not task_digests <= set(state.get("consumed_canary_task_sha256", []))
        or set(transaction.get("task_sha256s", [])) != task_digests
    ):
        raise ValueError("reserved task identities were not durably consumed")
    stored_authorities = _stored_evaluator_identity(state)
    if (
        not isinstance(stored_authorities, dict)
        or transaction.get("canary_authority_identity")
        != stored_authorities.get("canary")
        or transaction.get("canary_shard_identity") != panel.panel_sha256
        or transaction.get("canary_shard_epoch") != panel.epoch
        or transaction.get("gate_policy_sha256")
        != state.get("canary_gate_policy_sha256")
        or decision.get("panel_sha256") != panel.panel_sha256
        or decision.get("protocol_sha256") != panel.protocol_sha256
    ):
        raise ValueError("multi-task canary authority does not match durable state")
    for name, panel_values in (
        (
            "evaluation_sample_ids",
            [f"{t.task_sha256}:{s}" for t in panel.tasks for s in t.sample_ids],
        ),
        (
            "evaluation_sample_content_sha256",
            [h for t in panel.tasks for h in t.sample_content_sha256],
        ),
        (
            "evaluation_sample_public_input_sha256",
            [h for t in panel.tasks for h in t.public_input_sha256],
        ),
    ):
        recorded = transaction.get(name)
        if not isinstance(recorded, list) or set(recorded) != set(panel_values):
            raise ValueError(f"multi-task transaction {name} do not match its panel")
    if int(transaction.get("round", -1)) != round_no:
        raise ValueError("multi-task canary round does not match durable state")
    seed_schedule_sha256 = _panel_seed_schedule_sha256(panel)
    execution_schedule = _panel_execution_schedule(panel)
    if (
        transaction.get("seed_schedule_sha256") != seed_schedule_sha256
        or decision.get("seed_schedule_sha256") != seed_schedule_sha256
        or transaction.get("canary_execution_schedule") != execution_schedule
        or transaction.get("canary_schedule_sha256")
        != _panel_execution_schedule_sha256(panel)
        or decision.get("canary_schedule_sha256")
        != _panel_execution_schedule_sha256(panel)
    ):
        raise ValueError(
            "multi-task canary execution schedule does not match its panel"
        )
    incumbent = PolicyGenome.from_dict(transaction["incumbent"])
    challenger = PolicyGenome.from_dict(transaction["challenger"])
    incumbent_digest = _policy_digest(incumbent)
    challenger_digest = _policy_digest(challenger)
    if (
        incumbent_digest != transaction.get("incumbent_digest")
        or challenger_digest != transaction.get("candidate_digest")
        or state.get("incumbent_digest") != incumbent_digest
        or state.get("pending_digest") != challenger_digest
        or decision.get("incumbent_digest") != incumbent_digest
        or decision.get("candidate_digest") != challenger_digest
    ):
        raise ValueError("multi-task canary policy identities do not match state")
    if not has_valid_canary_attestation(decision):
        raise ValueError("multi-task canary decision has no host attestation")
    transaction_digest = hashlib.sha256(transaction_path.read_bytes()).hexdigest()
    if decision.get("transaction_sha256") != transaction_digest:
        raise ValueError("multi-task decision does not bind its reservation")
    gate_config_digest = _stable_digest(canary_gate.authority_config())
    if decision.get("gate_config_sha256") != gate_config_digest:
        raise ValueError("multi-task gate configuration changed after reservation")

    expected_paths = []
    for task in sorted(panel.tasks, key=lambda item: item.task_id):
        for replicate in sorted(task.replicate_ids):
            for side in ("challenger", "incumbent"):
                expected_paths.append(
                    f"task-{_task_path_component(task.task_id)}/rep-{replicate:04d}/{side}/journal.json"
                )
    evidence = decision.get("journal_evidence")
    if (
        not isinstance(evidence, list)
        or [item.get("path") for item in evidence if isinstance(item, dict)]
        != expected_paths
    ):
        raise ValueError("multi-task decision does not bind every task journal")
    from aide.journal import Journal
    from aide.utils import serialize

    paired_journals: dict[str, list[tuple[Any, Any]]] = {
        task_id: [] for task_id in panel.task_ids
    }
    for task in sorted(panel.tasks, key=lambda item: item.task_id):
        for replicate in sorted(task.replicate_ids):
            loaded = {}
            for side in ("challenger", "incumbent"):
                relative = f"task-{_task_path_component(task.task_id)}/rep-{replicate:04d}/{side}/journal.json"
                journal_path = canary_root / relative
                if journal_path.is_symlink() or not journal_path.is_file():
                    raise ValueError("multi-task canary journal is missing")
                item = evidence[expected_paths.index(relative)]
                if (
                    item.get("sha256")
                    != hashlib.sha256(journal_path.read_bytes()).hexdigest()
                ):
                    raise ValueError("multi-task canary journal digest mismatch")
                loaded[side] = serialize.load_json(journal_path, Journal)
            paired_journals[task.task_id].append(
                (loaded["challenger"], loaded["incumbent"])
            )
    recomputed = canary_gate.evaluate_panel(paired_journals).to_dict()
    if decision.get("gate_result") != recomputed or bool(
        decision.get("passed")
    ) != bool(recomputed["passed"]):
        raise ValueError("multi-task canary decision does not recompute")
    winner = challenger if recomputed["passed"] else incumbent
    winner.save(rsi_dir / "incumbent_policy.json")
    try:
        (rsi_dir / "pending_policy.json").unlink()
    except FileNotFoundError:
        pass
    return state_store.write(
        phase="IDLE",
        current_round=round_no,
        next_round=round_no,
        incumbent_digest=_policy_digest(winner),
        pending_digest=None,
        active_canary_panel_sha256=None,
        last_canary=decision,
    )


def _abort_canary_recovery(
    *,
    state: dict[str, Any],
    state_store: RSIStateStore,
    rsi_dir: Path,
    round_no: int,
    reason: str,
    transaction_present: bool,
    decision_present: bool,
) -> dict[str, Any]:
    """Retire an uncertain canary attempt and remove challenger authority."""
    try:
        (rsi_dir / "pending_policy.json").unlink()
    except FileNotFoundError:
        pass
    aborted = {
        "status": "aborted",
        "reason": reason,
        "round": round_no,
        "transaction_present": transaction_present,
        "decision_present": decision_present,
    }
    state = state_store.write(
        phase="IDLE",
        current_round=round_no,
        next_round=round_no,
        pending_digest=None,
        active_canary_panel_sha256=None,
        last_canary=aborted,
    )
    _write_json(
        rsi_dir.parent / f"round-{round_no:03d}" / "canary" / "aborted.json", aborted
    )
    return state


def _node_score(node: Any) -> float | None:
    metric = getattr(node, "metric", None)
    if (
        metric is None
        or getattr(metric, "is_worst", False)
        or getattr(node, "is_buggy", False)
    ):
        return None
    try:
        value = float(metric.value)
    except (TypeError, ValueError, AttributeError):
        return None
    return value if math.isfinite(value) else None


def _validate_trusted_evaluator_roles(search, canary, task_metric) -> None:
    """Require canary evidence to use an independent split of the same metric."""
    if canary is not None and search is None:
        raise ValueError(
            "a canary evaluator requires the trusted search evaluator to be enabled"
        )
    for role, evaluator_instance in (("search", search), ("canary", canary)):
        if evaluator_instance is not None and (
            evaluator_instance.metric_id != task_metric.name
            or evaluator_instance.metric_maximize is not task_metric.maximize
        ):
            raise ValueError(
                f"trusted {role} evaluator metric must match the task metric"
            )
    if (
        search is not None
        and canary is not None
        and search.dataset_sha256 == canary.dataset_sha256
        and search.split_sha256 == canary.split_sha256
    ):
        raise ValueError(
            "trusted canary evaluator must use a different pinned dataset or split"
        )
    if search is not None and canary is not None:
        search_ids = getattr(search, "evaluation_sample_ids", None)
        canary_ids = getattr(canary, "evaluation_sample_ids", None)
        if (
            search_ids is not None
            and canary_ids is not None
            and set(search_ids).intersection(canary_ids)
        ):
            raise ValueError("trusted search and canary sample IDs overlap")
        search_public = getattr(search, "evaluation_sample_public_input_sha256", None)
        canary_public = getattr(canary, "evaluation_sample_public_input_sha256", None)
        if (
            search_public is not None
            and canary_public is not None
            and search_public.intersection(canary_public)
        ):
            raise ValueError(
                "trusted canary evaluator contains duplicate candidate-visible input"
            )
        search_content = getattr(search, "evaluation_sample_content_sha256", None)
        canary_content = getattr(canary, "evaluation_sample_content_sha256", None)
        if (
            search_content is not None
            and canary_content is not None
            and search_content.intersection(canary_content)
        ):
            raise ValueError(
                "trusted canary evaluator contains duplicate sample content"
            )
        search_task = getattr(search, "task_sha256", None)
        canary_task = getattr(canary, "task_sha256", None)
        if (
            search_task is not None
            and canary_task is not None
            and search_task != canary_task
        ):
            raise ValueError("trusted search and canary task identities differ")


def _stored_evaluator_identity(state: dict[str, Any]) -> Any:
    """Normalize single-evaluator state saved by v1.3.3 and earlier."""
    identity = state.get("trusted_evaluator_identity")
    if isinstance(identity, str):
        return {"search": identity, "canary": None}
    if identity is None and "trusted_evaluator_identity" in state:
        return {"search": None, "canary": None}
    return identity


def _external_memory(worlds, mode: str) -> str:
    mode = str(mode or "none").lower()
    if mode == "none":
        return ""
    if mode == "top":
        return summarize_worlds(worlds)
    if mode == "failures":
        lines = ["Measured prior failures (do not infer hidden outcomes):"]
        for world in worlds[-5:]:
            for node in world.nodes.values():
                if node.is_buggy:
                    lines.append(
                        f"- {node.fail_class}: {node.analysis or node.error or '(no detail)'}"
                    )
        return "\n".join(lines[:20])
    raise ValueError(f"unsupported rsi.memory_mode: {mode}")


def _episode_cfg(
    cfg,
    *,
    log_dir: Path,
    workspace_dir: Path,
    data_dir: Path | None = None,
):
    round_cfg = copy.deepcopy(cfg)
    round_cfg.log_dir = log_dir.resolve()
    round_cfg.workspace_dir = workspace_dir.resolve()
    if data_dir is not None:
        round_cfg.data_dir = data_dir.resolve()
    return round_cfg


def _prepare_workspace(round_cfg, prep_agent_workspace, *, fresh: bool) -> None:
    if fresh and round_cfg.workspace_dir.exists():
        shutil.rmtree(round_cfg.workspace_dir)
    if not (round_cfg.workspace_dir / "input").exists():
        prep_agent_workspace(round_cfg)


def _run_live_episode(
    *,
    cfg,
    task_desc,
    task_metric,
    policy: PolicyGenome,
    prior_worlds,
    grid,
    budget: int,
    log_dir: Path,
    workspace_dir: Path,
    candidate_artifact_root: Path | None = None,
    state_store: RSIStateStore | None = None,
    resume: bool = False,
    provenance: dict[str, Any] | None = None,
    trusted_evaluator=None,
    data_dir_override: Path | None = None,
    seed: int | None = None,
):
    """Run one real online episode under exactly one exploration policy."""
    from omegaconf import OmegaConf

    from aide.agent import Agent
    from aide.journal import Journal
    from aide.utils import serialize
    from aide.utils.config import prep_agent_workspace, save_run

    if seed is not None:
        if isinstance(seed, bool) or not isinstance(seed, int) or seed < 0:
            raise ValueError("episode seed must be a nonnegative integer")
        random.seed(seed)
        try:
            import numpy as np
        except ImportError:
            pass
        else:
            np.random.seed(seed % (2**32))

    round_cfg = _episode_cfg(
        cfg,
        log_dir=log_dir,
        workspace_dir=workspace_dir,
        data_dir=data_dir_override,
    )
    _prepare_workspace(round_cfg, prep_agent_workspace, fresh=not resume)

    journal_path = round_cfg.log_dir / "journal.json"
    if resume and journal_path.exists():
        journal = serialize.load_json(journal_path, Journal)
    else:
        journal = Journal(
            metric_maximize=task_metric.maximize if task_metric is not None else None
        )

    agent = Agent(
        task_desc=task_desc,
        cfg=round_cfg,
        journal=journal,
        external_memory=_external_memory(prior_worlds, cfg.rsi.memory_mode),
    )
    scfg = cfg.rsi.sandbox
    exec_cfg = OmegaConf.to_container(round_cfg.exec)  # type: ignore
    interpreter = SecureInterpreter(
        round_cfg.workspace_dir,
        timeout=int(exec_cfg.get("timeout", 3600)),
        agent_file_name=str(exec_cfg.get("agent_file_name", "runfile.py")),
        format_tb_ipython=bool(exec_cfg.get("format_tb_ipython", False)),
        mode=scfg.mode,
        backend=scfg.backend,
        container_runtime=scfg.container_runtime,
        container_image=scfg.container_image,
        allow_insecure_process=bool(scfg.allow_insecure_process),
        limits=SandboxLimits(
            memory_mb=int(scfg.memory_mb),
            seatbelt_memory_mb=int(scfg.seatbelt_memory_mb),
            cpu_seconds=int(scfg.cpu_seconds),
            file_size_mb=int(scfg.file_size_mb),
            workspace_mb=int(scfg.workspace_mb),
            max_output_mb=int(scfg.max_output_mb),
            nproc=int(scfg.nproc),
            nofile=int(scfg.nofile),
        ),
    )

    # Optional JEV/SystemOne advisory layer.  It is deliberately outside the
    # authority chain: it cannot create legal actions, execute tools, change the
    # evaluator, or promote a policy.  In v1.3 only high-confidence failure
    # repairability may influence recovery classification; other decisions are
    # shadow telemetry for later qualification.
    advisor = None
    if hasattr(cfg.rsi, "jev"):
        advisor = JevAdvisor.from_config(
            cfg.rsi.jev,
            log_path=round_cfg.log_dir / "rsi" / "jev_advisory.jsonl",
        )

    # The reference runner does not pretend sequential work is parallel.  A future
    # worker-pool executor can raise this once actual concurrent execution exists.
    effective_parallelism = 1
    controller = LiveExplorationController(
        policy,
        max_parallelism=effective_parallelism,
        width_cap=grid.branch_count,
        depth_cap=max(1, grid.refine_count + 1),
        support_index=ReplaySupportIndex(list(prior_worlds)) if prior_worlds else None,
        advisor=advisor,
    )

    episode_provenance = {
        "policy_digest": _policy_digest(policy),
        "generation_model": str(cfg.agent.code.model),
        "feedback_model": str(cfg.agent.feedback.model),
        "task_digest": _stable_digest(task_desc),
        "sandbox_mode": str(cfg.rsi.sandbox.mode),
        "trusted_evaluator_identity": (
            trusted_evaluator.identity if trusted_evaluator is not None else None
        ),
        "agent_config_digest": _stable_digest(OmegaConf.to_container(cfg.agent)),
        "exec_config_digest": _stable_digest(OmegaConf.to_container(cfg.exec)),
        "episode_log": str(log_dir),
        "jev_enabled": bool(getattr(getattr(cfg.rsi, "jev", None), "enabled", False)),
        "jev_model": str(getattr(getattr(cfg.rsi, "jev", None), "model", "")),
    }
    episode_provenance.update(dict(provenance or {}))

    attempts = len(journal.nodes)
    try:
        while attempts < int(budget):
            parents = controller.select_parents(journal)
            if not parents:
                break
            parents = parents[: max(0, int(budget) - attempts)]
            # Selection is made from one prefix. With effective_parallelism=1 the
            # execution semantics are also truthful rather than simulated parallelism.
            batch_nodes = []
            for parent in parents:
                route_advice = None
                if advisor is not None:
                    route_advice = advisor.shadow_model_route(
                        {
                            "parent_exists": parent is not None,
                            "parent_buggy": (
                                bool(getattr(parent, "is_buggy", False))
                                if parent is not None
                                else False
                            ),
                            "parent_depth": (
                                controller._depth(parent) if parent is not None else 0
                            ),
                            "task_digest": episode_provenance["task_digest"],
                            "configured_model": str(cfg.agent.code.model),
                        }
                    )
                node = agent.generate_for_parent(parent)
                if route_advice is not None:
                    node.rsi_jev_advisory = {
                        "model_route_shadow": route_advice.to_dict(),
                    }
                batch_nodes.append(node)

            for node in batch_nodes:
                candidate_sha256 = store_candidate(
                    node.code,
                    candidate_artifact_root
                    or (Path(log_dir).parent / "rsi" / "artifacts"),
                )
                node.rsi_provenance = {
                    **dict(getattr(node, "rsi_provenance", {}) or {}),
                    **episode_provenance,
                    "candidate_sha256": candidate_sha256,
                    "evaluation_authority": "feedback_model_interpreted_candidate_output",
                }
                agent.evaluate_generated_node(
                    node,
                    interpreter.run,
                    trusted_evaluator=trusted_evaluator,
                    candidate_sha256=candidate_sha256,
                )
                if advisor is not None and bool(getattr(node, "is_buggy", False)):
                    fail_class = controller._failure_class(node)
                    fail_error = (
                        str(
                            getattr(node, "analysis", "")
                            or getattr(node, "exc_info", "")
                            or ""
                        )
                        or None
                    )
                    controller._failure_advice(node, fail_class, fail_error)
                if advisor is not None:
                    verify_advice = advisor.shadow_verification_depth(
                        {
                            "candidate_buggy": bool(getattr(node, "is_buggy", False)),
                            "candidate_has_metric": _node_score(node) is not None,
                            "failure_class": controller._failure_class(node),
                            "plan": str(getattr(node, "plan", "") or "")[:1200],
                            "task_digest": episode_provenance["task_digest"],
                        }
                    )
                    if verify_advice is not None:
                        merged = dict(getattr(node, "rsi_jev_advisory", {}) or {})
                        merged["verification_depth_shadow"] = verify_advice.to_dict()
                        node.rsi_jev_advisory = merged
            for node in batch_nodes:
                journal.append(node)
            attempts += len(batch_nodes)
            save_run(round_cfg, journal)
            if state_store is not None:
                state_store.write(phase="LIVE_RUNNING", attempts=attempts)
    finally:
        interpreter.cleanup_session()
    return journal, round_cfg


def _run_rsi_unlocked() -> None:
    """Run AIDE under replay-improved, qualified exploration control."""
    from omegaconf import OmegaConf

    from aide.agent import TaskMetric, add_task_metric, determine_task_metric
    from aide.utils.config import load_cfg, load_task_desc

    from .trusted_evaluator import create_trusted_evaluator

    cfg = load_cfg()
    if not cfg.rsi.enabled:
        raise ValueError(
            "rsi.enabled=false; use the standard `aide` entry point or enable RSI"
        )
    if int(cfg.rsi.max_parallelism) != 1:
        raise ValueError(
            "AIDE-DREAM-RSI v1.3 has truthful serial live execution only; "
            "set rsi.max_parallelism=1. A later worker-pool release can safely raise it."
        )

    task_desc = load_task_desc(cfg)
    trusted_cfg = cfg.rsi.trusted_evaluator
    if bool(trusted_cfg.enabled):
        if not isinstance(trusted_cfg.metric_maximize, bool):
            raise ValueError(
                "trusted evaluator requires a fixed metric_maximize boolean"
            )
        task_metric = TaskMetric(
            name=str(trusted_cfg.metric_id or "").strip() or None,
            maximize=trusted_cfg.metric_maximize,
        )
        if task_metric.name is None:
            raise ValueError("trusted evaluator requires a nonempty metric_id")
    else:
        task_metric = determine_task_metric(task_desc, cfg.agent)
    task_desc = add_task_metric(task_desc, task_metric)

    base_log = Path(cfg.log_dir)
    base_workspace = Path(cfg.workspace_dir)
    rsi_dir = base_log / "rsi"
    pool = ReplayWorldPool(rsi_dir / "worlds")
    trusted_evaluator = create_trusted_evaluator(
        trusted_cfg,
        task_description=task_desc,
        artifact_root=rsi_dir / "artifacts",
    )
    if bool(getattr(cfg.rsi.canary_evaluator, "enabled", False)):
        raise ValueError(
            "single-task canary_evaluator is not authorized for promotions; configure rsi.canary_panel"
        )
    canary_panel_runtime = _build_canary_panel(
        cfg,
        task_metric_type=TaskMetric,
        add_metric=add_task_metric,
        artifact_root=rsi_dir / "artifacts",
    )
    if canary_panel_runtime is not None:
        _validate_search_panel_roles(trusted_evaluator, canary_panel_runtime)
    state_store = RSIStateStore(
        rsi_dir / "state.json",
        require_attestation=(
            trusted_evaluator is not None or canary_panel_runtime is not None
        ),
        anchor_url=os.environ.get("AIDE_RSI_STATE_ANCHOR_URL"),
        anchor_token=os.environ.get("AIDE_RSI_STATE_ANCHOR_TOKEN"),
        anchor_id=os.environ.get("AIDE_RSI_STATE_ANCHOR_ID"),
        anchor_tls_certificate_sha256=os.environ.get(
            "AIDE_RSI_STATE_ANCHOR_TLS_CERT_SHA256"
        ),
    )
    incumbent_path = rsi_dir / "incumbent_policy.json"
    pending_path = rsi_dir / "pending_policy.json"
    split_manager = PersistentSplitManager(
        rsi_dir / "split_manifest.json", epoch=str(cfg.rsi.split_epoch)
    )

    state_file_exists = state_store.path.exists()
    state = state_store.load()
    configured_canary_epoch = getattr(cfg.rsi, "canary_panel_epoch", 0)
    if configured_canary_epoch is None:
        configured_canary_epoch = 0
    if isinstance(configured_canary_epoch, bool) or not isinstance(
        configured_canary_epoch, int
    ):
        raise TypeError("rsi.canary_panel_epoch must be an integer")
    canary_epoch = configured_canary_epoch
    if canary_epoch < 0:
        raise ValueError("canary_evaluator.shard_epoch must be nonnegative")
    configured_evaluator_identity = {
        "search": trusted_evaluator.identity if trusted_evaluator is not None else None,
        "canary": (
            canary_panel_runtime.authority_identity
            if canary_panel_runtime is not None
            else None
        ),
    }
    configured_canary_shard_identity = (
        canary_panel_runtime.identity if canary_panel_runtime is not None else None
    )
    stored_evaluator_identity = _stored_evaluator_identity(state)
    existing_worlds = pool.load_all()
    legacy_current_identity = {
        "search": trusted_evaluator.identity if trusted_evaluator is not None else None,
        "canary": configured_evaluator_identity["canary"],
    }
    legacy_canary_upgrade = (
        state_file_exists
        and bool(existing_worlds)
        and stored_evaluator_identity
        == {
            "search": configured_evaluator_identity["search"],
            "canary": None,
        }
        and configured_evaluator_identity["canary"] is not None
    )
    identity_updates = {
        "trusted_evaluator_identity": configured_evaluator_identity,
        "canary_shard_identity": configured_canary_shard_identity,
        "canary_shard_epoch": canary_epoch,
    }
    if stored_evaluator_identity is None:
        if state_file_exists or existing_worlds:
            raise ValueError(
                "trusted evaluator identity is missing from an existing RSI run"
            )
        state = state_store.write(**identity_updates, canary_attempt_count=0)
    elif stored_evaluator_identity == configured_evaluator_identity:
        stored_shard = state.get("canary_shard_identity")
        stored_epoch = state.get("canary_shard_epoch")
        if "canary_shard_identity" not in state:
            # Migrate an existing single-shard state only when it is still using
            # the exact evaluator identity recorded by the prior schema.
            if stored_evaluator_identity != legacy_current_identity:
                raise ValueError(
                    "legacy canary identity cannot be migrated after its shard changed"
                )
            state = state_store.write(**identity_updates)
        elif stored_shard != configured_canary_shard_identity:
            _validate_canary_shard_rotation(
                state=state,
                canary_evaluator=canary_panel_runtime,
                shard_identity=configured_canary_shard_identity,
                shard_epoch=canary_epoch,
                base_log=base_log,
            )
            state = state_store.write(**identity_updates)
        elif canary_epoch != stored_epoch:
            raise ValueError("canary shard_epoch changed without rotating the shard")
    elif legacy_canary_upgrade:
        # The previous schema stored a full canary identity where this schema
        # stores stable evaluator authority plus a separately rotating shard.
        state = state_store.write(**identity_updates)
    elif stored_evaluator_identity == legacy_current_identity:
        state = state_store.write(**identity_updates)
    else:
        raise ValueError(
            "trusted evaluator authority changed for an existing RSI run; "
            "start a fresh experiment and split epoch"
        )
    if "canary_attempt_count" not in state:
        # Preserve a conservative attempt index when opening state written by
        # an earlier schema. A completed outer round could have contained one
        # canary; a pristine state has no current round and starts at zero.
        legacy_round = state.get("current_round")
        if isinstance(legacy_round, int) and not isinstance(legacy_round, bool):
            legacy_attempt_count = max(0, legacy_round + 1)
        elif existing_worlds:
            legacy_attempt_count = max(0, int(state.get("next_round", 0)))
        else:
            legacy_attempt_count = 0
        state = state_store.write(canary_attempt_count=legacy_attempt_count)
    configured_experiment_alpha = float(cfg.rsi.canary.experiment_alpha)
    if (
        not math.isfinite(configured_experiment_alpha)
        or not 0 < configured_experiment_alpha < 1
    ):
        raise ValueError("rsi.canary.experiment_alpha must be finite and in (0, 1)")
    if "canary_experiment_alpha" not in state:
        state = state_store.write(canary_experiment_alpha=configured_experiment_alpha)
    elif float(state["canary_experiment_alpha"]) != configured_experiment_alpha:
        raise ValueError("rsi.canary.experiment_alpha changed for an existing RSI run")
    configured_protocol_sha256 = (
        canary_panel_runtime.panel.protocol_sha256
        if canary_panel_runtime is not None
        else None
    )
    if configured_protocol_sha256 is not None:
        stored_protocol_sha256 = state.get("statistical_protocol_sha256")
        if stored_protocol_sha256 is None:
            state = state_store.write(
                statistical_protocol_sha256=configured_protocol_sha256
            )
        elif stored_protocol_sha256 != configured_protocol_sha256:
            raise ValueError(
                "multi-task statistical protocol changed; start a new statistical epoch"
            )
        expected_statistical_epoch = statistical_epoch_sha256(
            configured_experiment_alpha, configured_protocol_sha256
        )
        stored_statistical_epoch = state.get("statistical_epoch_sha256")
        if stored_statistical_epoch is None:
            state = state_store.write(
                statistical_epoch_sha256=expected_statistical_epoch
            )
        elif stored_statistical_epoch != expected_statistical_epoch:
            raise ValueError("statistical epoch changed; start a fresh RSI experiment")
    if "statistical_budget" not in state:
        statistical_budget = StatisticalBudget.migrate_legacy(
            configured_experiment_alpha, int(state.get("canary_attempt_count", 0))
        )
        state = state_store.write(statistical_budget=statistical_budget.to_dict())
    else:
        statistical_budget = StatisticalBudget.from_dict(state["statistical_budget"])
        if (
            statistical_budget.family_alpha != configured_experiment_alpha
            or statistical_budget.attempt_index != state.get("canary_attempt_count", 0)
        ):
            raise ValueError("durable statistical budget does not match RSI state")
    canary_block_reason = None
    if trusted_evaluator is None or canary_panel_runtime is None:
        canary_block_reason = "promotion requires a trusted search evaluator and a reserved multi-task canary panel"
    elif (
        state.get("phase") == "CANARY_RUNNING"
        and state.get("active_canary_panel_sha256")
        != canary_panel_runtime.panel.panel_sha256
    ):
        raise ValueError("active canary transaction panel changed on restart")
    elif canary_panel_runtime is not None:
        retired_ids, retired_content, retired_public = _used_canary_retirements(
            base_log, state
        )
        if (
            _canary_shard_overlaps_retired(
                canary_panel_runtime.evaluation_sample_ids,
                canary_panel_runtime.evaluation_sample_content_sha256,
                retired_ids,
                retired_content,
                canary_panel_runtime.evaluation_sample_public_input_sha256,
                retired_public,
            )
            and state.get("phase") != "CANARY_RUNNING"
        ):
            canary_block_reason = (
                "a canary sample in this panel has already been consumed"
            )
        panel_sha = canary_panel_runtime.panel.panel_sha256
        if (
            panel_sha in state.get("consumed_canary_panel_sha256", [])
            and state.get("phase") != "CANARY_RUNNING"
        ):
            canary_block_reason = (
                "the multi-task canary panel has already been consumed"
            )
        prior_tasks = set(state.get("consumed_canary_task_sha256", []))
        panel_tasks = {task.task_sha256 for task in canary_panel_runtime.panel.tasks}
        if (
            prior_tasks.intersection(panel_tasks)
            and state.get("phase") != "CANARY_RUNNING"
        ):
            canary_block_reason = "a task identity from this panel was already used for promotion evidence"
    canary_attempt_count = state.get("canary_attempt_count", 0)
    if (
        isinstance(canary_attempt_count, bool)
        or not isinstance(canary_attempt_count, int)
        or canary_attempt_count < 0
    ):
        raise ValueError("durable canary attempt count is invalid")

    def build_canary_gate(attempt_index: int) -> TaskClusteredCanaryGate:
        if canary_panel_runtime is None:
            raise ValueError("a multi-task canary panel is required for promotion")
        pair_gates = {}
        for task in canary_panel_runtime.tasks:
            pair_gates[task.task_id] = _task_pair_gate_template(
                cfg,
                artifact_root=rsi_dir / "artifacts",
                expected_identity={
                    **task.evaluator._identity_fields(),
                    "trusted_evaluator_identity": task.evaluator.identity,
                },
            )
        return TaskClusteredCanaryGate(
            panel=canary_panel_runtime.panel,
            pair_gates=pair_gates,
            promotion_attempt_index=attempt_index,
            family_alpha=configured_experiment_alpha,
            allocated_alpha=sequential_alpha(
                configured_experiment_alpha, attempt_index
            ),
            min_effect_size=float(cfg.rsi.canary.min_effect_size),
            max_task_regression=float(cfg.rsi.canary.max_single_task_regression),
        )

    gate_template = (
        build_canary_gate(max(1, statistical_budget.attempt_index))
        if canary_panel_runtime is not None
        else None
    )
    gate_policy_digest = (
        _stable_digest(gate_template.policy_config())
        if gate_template is not None
        else None
    )
    stored_gate_policy_digest = state.get("canary_gate_policy_sha256")
    if gate_policy_digest is not None and stored_gate_policy_digest is None:
        state = state_store.write(canary_gate_policy_sha256=gate_policy_digest)
    elif (
        gate_policy_digest is not None
        and stored_gate_policy_digest != gate_policy_digest
    ):
        raise ValueError("canary promotion gate policy changed for an existing RSI run")
    if state.get("phase") == "CANARY_RUNNING":
        if gate_template is None:
            raise ValueError("active multi-task canary panel is not configured")
        active_index = StatisticalBudget.from_dict(
            state["statistical_budget"]
        ).attempt_index
        active_gate = build_canary_gate(active_index)
        try:
            state = _recover_multitask_canary_transaction(
                state=state,
                state_store=state_store,
                rsi_dir=rsi_dir,
                canary_gate=active_gate,
            )
        except Exception as exc:
            state = _abort_canary_recovery(
                state=state,
                state_store=state_store,
                rsi_dir=rsi_dir,
                round_no=int(state.get("current_round", state.get("next_round", 0))),
                reason=f"multitask_canary_recovery_rejected_{type(exc).__name__}",
                transaction_present=True,
                decision_present=True,
            )
    retired_worlds = state.get("retired_qualification_worlds", [])
    if retired_worlds:
        split_manager.retire_qualification(list(retired_worlds))
    incumbent = (
        PolicyGenome.load(incumbent_path) if incumbent_path.exists() else PolicyGenome()
    )
    pending = PolicyGenome.load(pending_path) if pending_path.exists() else None
    if "incumbent_digest" in state and state["incumbent_digest"] != _policy_digest(
        incumbent
    ):
        raise ValueError("incumbent policy digest does not match durable RSI state")
    if "pending_digest" in state and state["pending_digest"] != _policy_digest(pending):
        raise ValueError("pending policy digest does not match durable RSI state")

    ecfg = cfg.rsi.evolution
    # No parallel reward until the live executor is actually concurrent.
    evaluator = ReplayEvaluator(work_penalty=ecfg.work_penalty, parallel_bonus=0.0)
    evolver = PolicyEvolutionEngine(
        evaluator,
        population=ecfg.population,
        generations=ecfg.generations,
        elite_count=ecfg.elite_count,
        seed=ecfg.seed,
        beta_grid=ecfg.beta_grid,
    )
    qualifier = QualificationGate(
        evaluator,
        min_validation_margin=ecfg.min_validation_margin,
        max_qualification_regression=ecfg.max_qualification_regression,
        max_single_world_regression=ecfg.max_single_world_regression,
        min_qualification_worlds=ecfg.min_qualification_worlds,
        beta_grid=ecfg.beta_grid,
        artifact_root=rsi_dir / "artifacts",
        require_artifacts=True,
    )

    all_worlds = existing_worlds
    current_split = split_manager.split(all_worlds)
    live_prior_worlds = current_split.development
    cycle_summaries = [live_cycle_summary(w) for w in live_prior_worlds]
    global_best_score, global_best_meta = _publish_best_from_worlds(
        live_prior_worlds, base_log
    )
    if state.get("phase") == "COMPLETED":
        print(f"AIDE-RSI already completed. Logs: {base_log}")
        return
    start_round = int(state.get("next_round", len(all_worlds)))

    state_store.write(
        phase=state.get("phase", "IDLE"),
        next_round=start_round,
        base_log=str(base_log),
        base_workspace=str(base_workspace),
        incumbent_digest=_policy_digest(incumbent),
        pending_digest=_policy_digest(pending),
    )

    for outer in range(start_round, int(cfg.rsi.outer_rounds)):
        state = state_store.load()
        same_round = int(state.get("current_round", outer)) == outer
        phase = state.get("phase", "IDLE") if same_round else "IDLE"

        if pending is not None and phase == "IDLE" and canary_block_reason:
            skipped = {"reason": canary_block_reason}
            _write_json(
                base_log / f"round-{outer:03d}" / "canary" / "skipped.json", skipped
            )
            pending = None
            if pending_path.exists():
                pending_path.unlink()
            state_store.write(
                phase="IDLE",
                current_round=outer,
                next_round=outer,
                pending_digest=None,
                last_canary=skipped,
            )

        # Replay qualification only grants pending status. General-policy
        # promotion requires one entire predeclared, multi-task panel.
        if pending is not None and phase in {"IDLE", "CANARY_RUNNING"}:
            if canary_panel_runtime is None:
                raise ValueError(
                    "pending policy reached canary without a multi-task panel"
                )
            state = state_store.load()
            panel = canary_panel_runtime.panel
            panel_sha256 = panel.panel_sha256
            consumed_tasks = set(state.get("consumed_canary_task_sha256", []))
            panel_task_hashes = {task.task_sha256 for task in panel.tasks}
            panel_already_used = panel_sha256 in state.get(
                "consumed_canary_panel_sha256", []
            ) or bool(consumed_tasks.intersection(panel_task_hashes))
            if phase == "IDLE" and panel_already_used:
                skipped = {
                    "reason": "canary panel or task identities were already consumed; rotate to a fresh panel"
                }
                _write_json(
                    base_log / f"round-{outer:03d}" / "canary" / "skipped.json",
                    skipped,
                )
                pending = None
                if pending_path.exists():
                    pending_path.unlink()
                state = state_store.write(
                    phase="IDLE",
                    current_round=outer,
                    next_round=outer,
                    pending_digest=None,
                    last_canary=skipped,
                )
            else:
                canary_grid = AdaptiveReplayPolicy(incumbent).plan_grid(
                    cycle_summaries,
                    fallback_width=cfg.rsi.fallback_width,
                    fallback_depth=cfg.rsi.fallback_depth,
                    hard_max_width=cfg.rsi.hard_max_width,
                    hard_max_depth=cfg.rsi.hard_max_depth,
                )
                active_index = (
                    StatisticalBudget.from_dict(
                        state["statistical_budget"]
                    ).attempt_index
                    + 1
                )
                reserved_budget = StatisticalBudget.from_dict(
                    state["statistical_budget"]
                ).reserve(
                    panel_sha256=panel_sha256,
                    protocol_sha256=panel.protocol_sha256,
                )
                if reserved_budget.attempt_index != active_index:
                    raise ValueError(
                        "statistical budget did not reserve the next attempt"
                    )
                active_canary_gate = build_canary_gate(active_index)
                if (
                    active_canary_gate.allocated_alpha
                    != reserved_budget.last_allocation
                ):
                    raise ValueError("gate alpha differs from the durable reservation")
                canary_root = base_log / f"round-{outer:03d}" / "canary"
                canary_root.mkdir(parents=True, exist_ok=True)

                from .trusted_evaluator import tree_sha256

                for task in canary_panel_runtime.tasks:
                    if (
                        tree_sha256(task.public_data_dir)
                        != task.definition.public_data_sha256
                    ):
                        raise ValueError(
                            f"canary task {task.task_id} public data changed after panel construction"
                        )
                sample_ids = sorted(canary_panel_runtime.evaluation_sample_ids)
                content_hashes = sorted(
                    canary_panel_runtime.evaluation_sample_content_sha256
                )
                public_hashes = sorted(
                    canary_panel_runtime.evaluation_sample_public_input_sha256
                )
                sample_identity_records = _panel_sample_identity_records(panel)
                sample_identity_digests = sorted(
                    _sample_identity_record_sha256(record)
                    for record in sample_identity_records
                )
                all_sample_ids = set(state.get("consumed_canary_sample_ids", []))
                all_sample_ids.update(sample_ids)
                all_content_hashes = set(
                    state.get("consumed_canary_sample_content_sha256", [])
                )
                all_content_hashes.update(content_hashes)
                all_public_hashes = set(
                    state.get("consumed_canary_public_input_sha256", [])
                )
                all_public_hashes.update(public_hashes)
                all_sample_identity_digests = set(
                    state.get("consumed_canary_sample_identity_sha256", [])
                )
                all_sample_identity_digests.update(sample_identity_digests)
                all_panel_hashes = set(state.get("consumed_canary_panel_sha256", []))
                all_panel_hashes.add(panel_sha256)
                all_task_hashes = set(state.get("consumed_canary_task_sha256", []))
                all_task_hashes.update(panel_task_hashes)
                # The complete panel, all task identities, and alpha allocation
                # are durable before the first authoritative result is observed.
                state = state_store.write(
                    phase="CANARY_RUNNING",
                    current_round=outer,
                    next_round=outer,
                    active_canary_panel_sha256=panel_sha256,
                    statistical_protocol_sha256=panel.protocol_sha256,
                    consumed_canary_panel_sha256=sorted(all_panel_hashes),
                    consumed_canary_task_sha256=sorted(all_task_hashes),
                    consumed_canary_sample_ids=sorted(all_sample_ids),
                    consumed_canary_sample_content_sha256=sorted(all_content_hashes),
                    consumed_canary_public_input_sha256=sorted(all_public_hashes),
                    consumed_canary_sample_identity_sha256=sorted(
                        all_sample_identity_digests
                    ),
                    canary_attempt_count=active_index,
                    statistical_budget=reserved_budget.to_dict(),
                )
                transaction = sign_canary_transaction(
                    {
                        "round": outer,
                        "panel": panel.to_dict(),
                        "panel_sha256": panel_sha256,
                        "protocol_sha256": panel.protocol_sha256,
                        "statistical_epoch_sha256": state.get(
                            "statistical_epoch_sha256"
                        ),
                        "incumbent": incumbent.to_dict(),
                        "challenger": pending.to_dict(),
                        "incumbent_digest": _policy_digest(incumbent),
                        "candidate_digest": _policy_digest(pending),
                        "evaluation_sample_ids": sample_ids,
                        "evaluation_sample_content_sha256": content_hashes,
                        "evaluation_sample_public_input_sha256": public_hashes,
                        "evaluation_sample_identity_records": sample_identity_records,
                        "task_sha256s": sorted(panel_task_hashes),
                        "seed_schedule_sha256": _panel_seed_schedule_sha256(panel),
                        "canary_execution_schedule": _panel_execution_schedule(panel),
                        "canary_schedule_sha256": _panel_execution_schedule_sha256(
                            panel
                        ),
                        "canary_authority_identity": canary_panel_runtime.authority_identity,
                        "canary_shard_identity": panel_sha256,
                        "canary_shard_epoch": panel.epoch,
                        "promotion_attempt_index": active_index,
                        "allocated_alpha": reserved_budget.last_allocation,
                        "statistical_budget_sha256": reserved_budget.digest(),
                        "gate_policy_sha256": gate_policy_digest,
                    }
                )
                _write_json(canary_root / "transaction.json", transaction)

                task_pairs: dict[str, list[tuple[Any, Any]]] = {
                    task_id: [] for task_id in panel.task_ids
                }
                journal_evidence = []
                schedule_by_key = {
                    (entry["task_id"], entry["replicate_id"]): entry
                    for entry in _panel_execution_schedule(panel)
                }
                for task_runtime in sorted(
                    canary_panel_runtime.tasks, key=lambda runtime: runtime.task_id
                ):
                    task = task_runtime.definition
                    task_component = _task_path_component(task.task_id)
                    for replicate in sorted(task.replicate_ids):
                        pair_root = (
                            canary_root
                            / f"task-{task_component}"
                            / f"rep-{replicate:04d}"
                        )
                        outcomes = {}
                        order = schedule_by_key[(task.task_id, replicate)]["order"]
                        for side in order:
                            policy = pending if side == "challenger" else incumbent
                            side_workspace = (
                                f"round-{outer:03d}-canary-{panel_sha256[:12]}-"
                                f"task-{task_component}-rep-{replicate:04d}-{side}"
                            )
                            if (
                                tree_sha256(task_runtime.public_data_dir)
                                != task.public_data_sha256
                            ):
                                raise ValueError(
                                    f"canary task {task.task_id} public data changed before evaluation"
                                )
                            journal, _ = _run_live_episode(
                                cfg=cfg,
                                task_desc=task_runtime.task_description,
                                task_metric=task_runtime.task_metric,
                                policy=policy,
                                prior_worlds=[],
                                grid=canary_grid,
                                budget=task.budget_per_run,
                                log_dir=pair_root / side,
                                workspace_dir=base_workspace / side_workspace,
                                candidate_artifact_root=rsi_dir / "artifacts",
                                provenance={
                                    "round": outer,
                                    "episode_role": f"multitask_canary_{side}",
                                    "canary_panel_sha256": panel_sha256,
                                    "canary_protocol_sha256": panel.protocol_sha256,
                                    "canary_task_id": task.task_id,
                                    "canary_task_sha256": task.task_sha256,
                                    "canary_task_family": task.task_family,
                                    "canary_replicate_id": replicate,
                                    "canary_replicate_seed": task.seed_for(replicate),
                                    "provider_rng_seeded": False,
                                },
                                trusted_evaluator=task_runtime.evaluator,
                                data_dir_override=task_runtime.public_data_dir,
                                seed=task.seed_for(replicate),
                            )
                            if (
                                tree_sha256(task_runtime.public_data_dir)
                                != task.public_data_sha256
                            ):
                                raise ValueError(
                                    f"canary task {task.task_id} public data changed during evaluation"
                                )
                            outcomes[side] = journal
                        task_pairs[task.task_id].append(
                            (outcomes["challenger"], outcomes["incumbent"])
                        )
                        for side in ("challenger", "incumbent"):
                            relative = (
                                f"task-{task_component}/rep-{replicate:04d}/"
                                f"{side}/journal.json"
                            )
                            journal_path = canary_root / relative
                            if journal_path.is_symlink() or not journal_path.is_file():
                                raise ValueError(
                                    "canary live run did not persist its journal"
                                )
                            journal_evidence.append(
                                {
                                    "path": relative,
                                    "sha256": hashlib.sha256(
                                        journal_path.read_bytes()
                                    ).hexdigest(),
                                }
                            )

                result = active_canary_gate.evaluate_panel(task_pairs)
                canary_payload = {
                    **result.to_dict(),
                    "candidate_digest": _policy_digest(pending),
                    "incumbent_digest": _policy_digest(incumbent),
                    "panel_sha256": panel_sha256,
                    "protocol_sha256": panel.protocol_sha256,
                    "statistical_epoch_sha256": state.get("statistical_epoch_sha256"),
                    "promotion_attempt_index": active_index,
                    "allocated_alpha": reserved_budget.last_allocation,
                    "statistical_budget_sha256": reserved_budget.digest(),
                    "seed_schedule_sha256": _panel_seed_schedule_sha256(panel),
                    "canary_schedule_sha256": _panel_execution_schedule_sha256(panel),
                    "gate_result": result.to_dict(),
                    "transaction_sha256": hashlib.sha256(
                        (canary_root / "transaction.json").read_bytes()
                    ).hexdigest(),
                    "gate_config_sha256": _stable_digest(
                        active_canary_gate.authority_config()
                    ),
                    "journal_evidence": journal_evidence,
                }
                signed_canary_payload = sign_canary_decision(canary_payload)
                _write_json(canary_root / "decision.json", signed_canary_payload)
                if result.passed:
                    incumbent = pending
                    incumbent.save(incumbent_path)
                state_store.write(
                    phase="IDLE",
                    current_round=outer,
                    next_round=outer,
                    incumbent_digest=_policy_digest(incumbent),
                    pending_digest=None,
                    active_canary_panel_sha256=None,
                    last_canary=signed_canary_payload,
                )
                pending = None
                if pending_path.exists():
                    pending_path.unlink()
                phase = "IDLE"

        # The qualified incumbent alone controls the real round's width/depth. If a
        # challenger just failed canary, its grid cannot leak into live authority.
        grid = AdaptiveReplayPolicy(incumbent).plan_grid(
            cycle_summaries,
            fallback_width=cfg.rsi.fallback_width,
            fallback_depth=cfg.rsi.fallback_depth,
            hard_max_width=cfg.rsi.hard_max_width,
            hard_max_depth=cfg.rsi.hard_max_depth,
        )

        # If a crash occurred in LIVE_RUNNING, resume the saved journal rather than
        # silently starting another world. Other incomplete phases are deterministic
        # and can be rerun from their committed inputs.
        if phase in {"IDLE", "LIVE_RUNNING"}:
            round_log = base_log / f"round-{outer:03d}"
            round_workspace = base_workspace / f"round-{outer:03d}"
            resume_live = (
                phase == "LIVE_RUNNING" and (round_log / "journal.json").exists()
            )
            state_store.write(
                phase="LIVE_RUNNING",
                current_round=outer,
                next_round=outer,
                attempts=int(state.get("attempts", 0)) if resume_live else 0,
                incumbent_digest=_policy_digest(incumbent),
            )
            journal, _round_cfg = _run_live_episode(
                cfg=cfg,
                task_desc=task_desc,
                task_metric=task_metric,
                policy=incumbent,
                prior_worlds=live_prior_worlds,
                grid=grid,
                budget=int(cfg.rsi.steps_per_round),
                log_dir=round_log,
                workspace_dir=round_workspace,
                candidate_artifact_root=rsi_dir / "artifacts",
                state_store=state_store,
                resume=resume_live,
                provenance={"round": outer, "episode_role": "discovery"},
                trusted_evaluator=trusted_evaluator,
            )

            world = world_from_journal(
                journal,
                world_id=f"{cfg.exp_name}:round:{outer}",
                max_parallelism=1,
                metadata={
                    "round": outer,
                    "planned_width": grid.branch_count,
                    "planned_depth": grid.refine_count,
                    "grid_reason": grid.reason,
                    "policy_digest": _policy_digest(incumbent),
                    "sandbox_mode": cfg.rsi.sandbox.mode,
                    "effective_parallelism": 1,
                    "generation_model": str(cfg.agent.code.model),
                    "feedback_model": str(cfg.agent.feedback.model),
                    "task_digest": _stable_digest(task_desc),
                    "trusted_evaluator_identity": (
                        trusted_evaluator.identity
                        if trusted_evaluator is not None
                        else None
                    ),
                    "agent_config_digest": _stable_digest(
                        OmegaConf.to_container(cfg.agent)
                    ),
                    "exec_config_digest": _stable_digest(
                        OmegaConf.to_container(cfg.exec)
                    ),
                },
            )
            world.metadata["replay_support"] = (
                ReplaySupportIndex(list(live_prior_worlds)).support(world)
                if live_prior_worlds
                else 0.0
            )
            pool.add(world)
            state_store.write(
                phase="WORLD_COMMITTED",
                current_round=outer,
                next_round=outer,
                world_id=world.world_id,
                attempts=len(journal.nodes),
            )

        # WORLD_COMMITTED and later phases can resume here without the live
        # journal in memory. Publish from the immutable pool on every pass.
        all_worlds = pool.load_all()
        current_split = split_manager.split(all_worlds)
        live_prior_worlds = current_split.development
        cycle_summaries = [live_cycle_summary(w) for w in live_prior_worlds]
        global_best_score, global_best_meta = _publish_best_from_worlds(
            live_prior_worlds, base_log
        )

        # Policy improvement can be deterministically rerun after a crash because it
        # consumes only the immutable replay pool and split manifest.
        state_store.write(
            phase="POLICY_EVALUATING", current_round=outer, next_round=outer
        )
        split = current_split
        round_rsi_dir = base_log / f"round-{outer:03d}" / "rsi"

        seed_candidates = []
        if bool(getattr(ecfg, "use_llm_developer", False)) and split.development:
            try:
                from .llm_developer import LLMPolicyDeveloper

                llm_model = ecfg.llm_model or cfg.agent.code.model
                developer = LLMPolicyDeveloper(
                    model=llm_model, temperature=ecfg.llm_temp
                )
                seed_candidates = developer.propose(
                    incumbent, split.development, evaluator, count=ecfg.llm_candidates
                )
            except Exception as exc:  # optional proposer is best-effort
                _write_json(
                    round_rsi_dir / "llm_policy_developer_error.json",
                    {"error": repr(exc)},
                )

        candidate, evolution_history = evolver.evolve(
            incumbent,
            split.development,
            split.validation,
            seed_candidates=seed_candidates,
        )
        record = qualifier.compare(candidate, incumbent, split)
        _write_json(round_rsi_dir / "evolution_history.json", evolution_history)
        _write_json(
            round_rsi_dir / "beta_sweep.json",
            evaluator.beta_sweep(
                AdaptiveReplayPolicy(candidate),
                split.validation or split.development,
                ecfg.beta_grid,
            ),
        )
        record.save(round_rsi_dir / "promotion_record.json")
        candidate.save(round_rsi_dir / "candidate_policy.json")

        final_round = outer + 1 >= int(cfg.rsi.outer_rounds)
        if (
            record.promoted
            and candidate.to_dict() != incumbent.to_dict()
            and not final_round
        ):
            pending = candidate
            pending.save(pending_path)
            state_store.write(
                phase="CANDIDATE_PENDING",
                current_round=outer,
                next_round=outer + 1,
                pending_digest=_policy_digest(pending),
            )
        else:
            # A policy discovered after the final online round has no remaining live
            # canary opportunity in this run. Preserve it as shadow evidence but do
            # not leave an apparently promotable pending authority behind.
            if (
                final_round
                and record.promoted
                and candidate.to_dict() != incumbent.to_dict()
            ):
                candidate.save(round_rsi_dir / "shadow_candidate_policy.json")
                _write_json(
                    round_rsi_dir / "shadow_candidate_status.json",
                    {
                        "reason": "final online round completed; replay-qualified candidate was not live-canaried",
                        "candidate_digest": _policy_digest(candidate),
                    },
                )
            pending = None
            if pending_path.exists():
                pending_path.unlink()

        retire_qualification_ids = []
        if len(split.qualification) >= int(ecfg.min_qualification_worlds) and all(
            has_trusted_world_evidence(
                world,
                artifact_root=rsi_dir / "artifacts",
                require_artifacts=True,
            )
            for world in (split.development + split.validation + split.qualification)
        ):
            retire_qualification_ids = [world.world_id for world in split.qualification]

        incumbent.save(incumbent_path)
        state_store.write(
            phase="IDLE" if outer + 1 < int(cfg.rsi.outer_rounds) else "COMPLETED",
            current_round=outer,
            next_round=outer + 1,
            attempts=0,
            world_pool=pool.manifest(),
            incumbent_digest=_policy_digest(incumbent),
            pending_digest=_policy_digest(pending),
            retired_qualification_worlds=sorted(
                set(state.get("retired_qualification_worlds", []))
                | set(retire_qualification_ids)
            ),
            global_best=global_best_meta,
            last_grid={
                "width": grid.branch_count,
                "depth": grid.refine_count,
                "reason": grid.reason,
            },
        )
        if retire_qualification_ids:
            split_manager.retire_qualification(retire_qualification_ids)
            current_split = split_manager.split(all_worlds)
            live_prior_worlds = current_split.development
            cycle_summaries = [live_cycle_summary(w) for w in live_prior_worlds]

    print(f"AIDE-RSI completed. Logs: {base_log}")
    if global_best_score is not None:
        print(f"Best real metric: {global_best_score}")
        print(f"Best solution: {base_log / 'best_solution.py'}")


def run_rsi() -> None:
    """Run one serialized RSI controller against the configured log directory."""
    from aide.utils.config import load_cfg

    cfg = load_cfg()
    lock_path = Path(cfg.log_dir) / "rsi" / "writer.lock"
    with rsi_writer_lock(lock_path):
        _run_rsi_unlocked()


if __name__ == "__main__":
    run_rsi()
