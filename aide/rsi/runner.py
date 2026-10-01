from __future__ import annotations

import copy
import hashlib
import json
import math
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any

from .artifacts import load_candidate, store_candidate
from .canary import RealCanaryGate
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
from .state import RSIStateStore
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


def _used_canary_sample_ids(base_log: Path) -> set[str]:
    """Recover consumed canary populations from signed reservation records."""
    used: set[str] = set()
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
    return used


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
        return state
    if transaction_path.is_symlink() or decision_path.is_symlink():
        raise ValueError("canary recovery evidence must be regular files")
    transaction = json.loads(transaction_path.read_text())
    decision = json.loads(decision_path.read_text())
    if not isinstance(transaction, dict) or not isinstance(decision, dict):
        raise TypeError("invalid canary recovery record")
    if not has_valid_canary_transaction(transaction):
        raise ValueError("canary transaction has no valid host attestation")
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
        if not incumbent_path.is_file() or not pending_path.is_file():
            raise ValueError("authorized canary policies are missing during recovery")
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
        if (
            _policy_digest(PolicyGenome.load(pending_path))
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
    gate_config = {
        "max_normalized_regression": canary_gate.max_normalized_regression,
        "min_valid": canary_gate.min_valid,
        "min_pass_fraction": canary_gate.min_pass_fraction,
        "score_scale_floor": canary_gate.score_scale_floor,
        "require_artifacts": canary_gate.require_artifacts,
        "expected_evaluation_identity": canary_gate.expected_evaluation_identity,
        "promotion_block_reason": canary_gate.promotion_block_reason,
    }
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


def _episode_cfg(cfg, *, log_dir: Path, workspace_dir: Path):
    round_cfg = copy.deepcopy(cfg)
    round_cfg.log_dir = log_dir.resolve()
    round_cfg.workspace_dir = workspace_dir.resolve()
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
):
    """Run one real online episode under exactly one exploration policy."""
    from omegaconf import OmegaConf

    from aide.agent import Agent
    from aide.journal import Journal
    from aide.utils import serialize
    from aide.utils.config import prep_agent_workspace, save_run

    round_cfg = _episode_cfg(cfg, log_dir=log_dir, workspace_dir=workspace_dir)
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


def run_rsi() -> None:
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
    canary_evaluator = create_trusted_evaluator(
        cfg.rsi.canary_evaluator,
        task_description=task_desc,
        artifact_root=rsi_dir / "artifacts",
    )
    state_store = RSIStateStore(
        rsi_dir / "state.json",
        require_attestation=(
            trusted_evaluator is not None or canary_evaluator is not None
        ),
    )
    _validate_trusted_evaluator_roles(trusted_evaluator, canary_evaluator, task_metric)
    incumbent_path = rsi_dir / "incumbent_policy.json"
    pending_path = rsi_dir / "pending_policy.json"
    split_manager = PersistentSplitManager(
        rsi_dir / "split_manifest.json", epoch=str(cfg.rsi.split_epoch)
    )

    state_file_exists = state_store.path.exists()
    state = state_store.load()
    configured_evaluator_identity = {
        "search": trusted_evaluator.identity if trusted_evaluator is not None else None,
        "canary": canary_evaluator.identity if canary_evaluator is not None else None,
    }
    stored_evaluator_identity = _stored_evaluator_identity(state)
    existing_worlds = pool.load_all()
    if configured_evaluator_identity != stored_evaluator_identity:
        legacy_canary_upgrade = (
            state_file_exists
            and existing_worlds
            and stored_evaluator_identity
            == {
                "search": configured_evaluator_identity["search"],
                "canary": None,
            }
            and configured_evaluator_identity["canary"] is not None
        )
        if (state_file_exists or existing_worlds) and not legacy_canary_upgrade:
            raise ValueError(
                "trusted evaluator identity changed for an existing RSI run; "
                "start a fresh experiment and split epoch"
            )
        state = state_store.write(
            trusted_evaluator_identity=configured_evaluator_identity
        )
    canary_block_reason = None
    if trusted_evaluator is None or canary_evaluator is None:
        canary_block_reason = "promotion requires separately configured trusted search and canary evaluators"
    elif (
        trusted_evaluator.evaluation_sample_ids is None
        or canary_evaluator.evaluation_sample_ids is None
    ):
        canary_block_reason = (
            "promotion requires canonical evaluation_sample_ids in both split manifests"
        )
    elif set(trusted_evaluator.evaluation_sample_ids) & set(
        canary_evaluator.evaluation_sample_ids
    ):
        canary_block_reason = "search and canary evaluation samples overlap"
    elif (
        trusted_evaluator.metric_id != canary_evaluator.metric_id
        or trusted_evaluator.metric_maximize != canary_evaluator.metric_maximize
        or trusted_evaluator.task_sha256 != canary_evaluator.task_sha256
    ):
        canary_block_reason = (
            "search and canary evaluators do not share task and metric identity"
        )
    if canary_evaluator is not None and canary_evaluator.evaluation_sample_ids:
        used_ids = _used_canary_sample_ids(base_log)
        active = state.get("phase") == "CANARY_RUNNING"
        if set(canary_evaluator.evaluation_sample_ids) & used_ids and not active:
            canary_block_reason = "canary sample shard has already been consumed"
    canary_gate = RealCanaryGate(
        max_normalized_regression=cfg.rsi.canary.max_normalized_regression,
        min_valid=cfg.rsi.canary.min_valid,
        min_pass_fraction=cfg.rsi.canary.min_pass_fraction,
        score_scale_floor=cfg.rsi.canary.score_scale_floor,
        artifact_root=rsi_dir / "artifacts",
        require_artifacts=True,
        expected_evaluation_identity=(
            {
                **canary_evaluator._identity_fields(),
                "trusted_evaluator_identity": canary_evaluator.identity,
            }
            if canary_evaluator is not None
            else {}
        ),
        promotion_block_reason=canary_block_reason,
    )
    state = _recover_canary_transaction(
        state=state,
        state_store=state_store,
        rsi_dir=rsi_dir,
        canary_gate=canary_gate,
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

        # Replay qualification only grants pending status. Before it can control a
        # discovery world it must beat the incumbent in a paired real canary from
        # fresh, equivalent starting states.
        if pending is not None and phase in {"IDLE", "CANARY_RUNNING"}:
            # Resource envelope is chosen by the incumbent authority, not by the
            # unqualified challenger. Both policies receive exactly the same grid.
            canary_grid = AdaptiveReplayPolicy(incumbent).plan_grid(
                cycle_summaries,
                fallback_width=cfg.rsi.fallback_width,
                fallback_depth=cfg.rsi.fallback_depth,
                hard_max_width=cfg.rsi.hard_max_width,
                hard_max_depth=cfg.rsi.hard_max_depth,
            )
            state_store.write(
                phase="CANARY_RUNNING", current_round=outer, next_round=outer
            )
            canary_budget = min(
                int(cfg.rsi.steps_per_round), max(1, int(cfg.rsi.canary.attempts))
            )
            canary_repeats = max(1, int(cfg.rsi.canary.repeats))
            canary_root = base_log / f"round-{outer:03d}" / "canary"
            canary_sample_ids = (
                sorted(canary_evaluator.evaluation_sample_ids)
                if canary_evaluator is not None
                and canary_evaluator.evaluation_sample_ids is not None
                else []
            )
            _write_json(
                canary_root / "transaction.json",
                sign_canary_transaction(
                    {
                        "round": outer,
                        "repeats": canary_repeats,
                        "incumbent": incumbent.to_dict(),
                        "challenger": pending.to_dict(),
                        "incumbent_digest": _policy_digest(incumbent),
                        "candidate_digest": _policy_digest(pending),
                        "evaluation_sample_ids": canary_sample_ids,
                    }
                ),
            )
            paired_journals = []
            for rep in range(canary_repeats):
                rep_root = canary_root / f"rep-{rep:02d}"
                # Alternate execution order so persistent external conditions do not
                # always favor the policy that runs first. Each side still starts
                # from a fresh equivalent workspace with the same real-attempt budget.
                if rep % 2 == 0:
                    challenger_journal, _ = _run_live_episode(
                        cfg=cfg,
                        task_desc=task_desc,
                        task_metric=task_metric,
                        policy=pending,
                        prior_worlds=live_prior_worlds,
                        grid=canary_grid,
                        budget=canary_budget,
                        log_dir=rep_root / "challenger",
                        workspace_dir=base_workspace
                        / f"round-{outer:03d}-canary-{rep:02d}-challenger",
                        candidate_artifact_root=rsi_dir / "artifacts",
                        provenance={
                            "round": outer,
                            "episode_role": "canary_challenger",
                            "canary_rep": rep,
                        },
                        trusted_evaluator=canary_evaluator,
                    )
                    incumbent_journal, _ = _run_live_episode(
                        cfg=cfg,
                        task_desc=task_desc,
                        task_metric=task_metric,
                        policy=incumbent,
                        prior_worlds=live_prior_worlds,
                        grid=canary_grid,
                        budget=canary_budget,
                        log_dir=rep_root / "incumbent",
                        workspace_dir=base_workspace
                        / f"round-{outer:03d}-canary-{rep:02d}-incumbent",
                        candidate_artifact_root=rsi_dir / "artifacts",
                        provenance={
                            "round": outer,
                            "episode_role": "canary_incumbent",
                            "canary_rep": rep,
                        },
                        trusted_evaluator=canary_evaluator,
                    )
                else:
                    incumbent_journal, _ = _run_live_episode(
                        cfg=cfg,
                        task_desc=task_desc,
                        task_metric=task_metric,
                        policy=incumbent,
                        prior_worlds=live_prior_worlds,
                        grid=canary_grid,
                        budget=canary_budget,
                        log_dir=rep_root / "incumbent",
                        workspace_dir=base_workspace
                        / f"round-{outer:03d}-canary-{rep:02d}-incumbent",
                        candidate_artifact_root=rsi_dir / "artifacts",
                        provenance={
                            "round": outer,
                            "episode_role": "canary_incumbent",
                            "canary_rep": rep,
                        },
                        trusted_evaluator=canary_evaluator,
                    )
                    challenger_journal, _ = _run_live_episode(
                        cfg=cfg,
                        task_desc=task_desc,
                        task_metric=task_metric,
                        policy=pending,
                        prior_worlds=live_prior_worlds,
                        grid=canary_grid,
                        budget=canary_budget,
                        log_dir=rep_root / "challenger",
                        workspace_dir=base_workspace
                        / f"round-{outer:03d}-canary-{rep:02d}-challenger",
                        candidate_artifact_root=rsi_dir / "artifacts",
                        provenance={
                            "round": outer,
                            "episode_role": "canary_challenger",
                            "canary_rep": rep,
                        },
                        trusted_evaluator=canary_evaluator,
                    )
                paired_journals.append((challenger_journal, incumbent_journal))

            result = canary_gate.evaluate_series(paired_journals)
            canary_payload = result.to_dict()
            canary_payload.update(
                {
                    "candidate_digest": _policy_digest(pending),
                    "incumbent_digest": _policy_digest(incumbent),
                    "budget_each": canary_budget,
                    "repeats": canary_repeats,
                    "execution_order": "alternating",
                    "gate_result": result.to_dict(),
                    "transaction_sha256": hashlib.sha256(
                        (canary_root / "transaction.json").read_bytes()
                    ).hexdigest(),
                    "gate_config_sha256": _stable_digest(
                        {
                            "max_normalized_regression": canary_gate.max_normalized_regression,
                            "min_valid": canary_gate.min_valid,
                            "min_pass_fraction": canary_gate.min_pass_fraction,
                            "score_scale_floor": canary_gate.score_scale_floor,
                            "require_artifacts": canary_gate.require_artifacts,
                            "expected_evaluation_identity": canary_gate.expected_evaluation_identity,
                            "promotion_block_reason": canary_gate.promotion_block_reason,
                        }
                    ),
                    "journal_evidence": [
                        {
                            "path": f"rep-{rep:02d}/{side}/journal.json",
                            "sha256": hashlib.sha256(
                                (
                                    canary_root
                                    / f"rep-{rep:02d}"
                                    / side
                                    / "journal.json"
                                ).read_bytes()
                            ).hexdigest(),
                        }
                        for rep in range(canary_repeats)
                        for side in ("challenger", "incumbent")
                    ],
                }
            )
            signed_canary_payload = sign_canary_decision(canary_payload)
            _write_json(canary_root / "decision.json", signed_canary_payload)
            if result.passed:
                incumbent = pending
                incumbent.save(incumbent_path)
            # Commit the recovery state before deleting the pending policy. If a
            # crash lands here, the transaction and decision reconcile the winner.
            state_store.write(
                phase="IDLE",
                current_round=outer,
                next_round=outer,
                incumbent_digest=_policy_digest(incumbent),
                pending_digest=None,
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
            except Exception as exc:  # noqa: BLE001 - optional proposer is best-effort
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


if __name__ == "__main__":
    run_rsi()
