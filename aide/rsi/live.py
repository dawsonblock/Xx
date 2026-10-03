from __future__ import annotations

import math
from typing import Any

from .policy import AdaptiveReplayPolicy
from .types import Observation, PolicyGenome, ROOT_ID


class LiveExplorationController:
    """Adapter that runs the *same* policy implementation used by replay.

    The previous implementation duplicated replay scoring logic in live execution,
    which meant an offline-evolved genome could behave differently online.  This
    adapter only translates a live AIDE Journal into the exact prefix state consumed
    by :class:`AdaptiveReplayPolicy`; all ranking, recovery, exploration, batching,
    and stopping decisions therefore share one implementation.
    """

    def __init__(
        self,
        genome: PolicyGenome,
        *,
        max_parallelism: int = 1,
        width_cap: int = 8,
        depth_cap: int = 12,
        support_score: float | None = None,
        support_index=None,
        advisor=None,
    ):
        self.policy = AdaptiveReplayPolicy(genome)
        self.support_score = support_score
        self.support_index = support_index
        self.max_parallelism = max(1, int(max_parallelism))
        self.width_cap = max(1, int(width_cap))
        self.depth_cap = max(1, int(depth_cap))
        self.advisor = advisor
        self._jev_failure_cache: dict[
            tuple[str, str, str], tuple[str | None, float | None]
        ] = {}

    @staticmethod
    def _depth(node: Any) -> int:
        d = 1
        cur = node
        seen: set[str] = set()
        while getattr(cur, "parent", None) is not None:
            cid = str(getattr(cur, "id", id(cur)))
            if cid in seen:
                break
            seen.add(cid)
            d += 1
            cur = cur.parent
        return d

    @staticmethod
    def _branch_id(node: Any) -> str:
        cur = node
        seen: set[str] = set()
        while getattr(cur, "parent", None) is not None:
            cid = str(getattr(cur, "id", id(cur)))
            if cid in seen:
                break
            seen.add(cid)
            cur = cur.parent
        return str(getattr(cur, "id", "unknown"))

    @staticmethod
    def _raw_score(node: Any) -> float | None:
        metric = getattr(node, "metric", None)
        if metric is None or getattr(metric, "is_worst", False):
            return None
        try:
            value = float(metric.value)
        except (TypeError, ValueError, AttributeError):
            return None
        return value if math.isfinite(value) else None

    @staticmethod
    def _failure_class(node: Any) -> str:
        if not bool(getattr(node, "is_buggy", False)):
            return "ok"
        text = (
            f"{getattr(node, 'exc_type', '')} {getattr(node, 'analysis', '')}".lower()
        )
        if "timeout" in text:
            return "timeout"
        if "memory" in text or "oom" in text or "resource" in text:
            return "resource"
        if "syntax" in text or "compile" in text:
            return "compile"
        if "permission" in text:
            return "permission"
        if "dependency" in text or "module" in text:
            return "dependency"
        return "runtime"

    def _failure_advice(
        self, node: Any, fail_class: str, error: str | None
    ) -> tuple[str | None, float | None]:
        if not bool(getattr(node, "is_buggy", False)) or self.advisor is None:
            return None, None
        existing = dict(getattr(node, "rsi_jev_advisory", {}) or {})
        existing_failure = existing.get("failure_classification")
        if isinstance(existing_failure, dict):
            repairability = existing.get("repairability")
            confidence = existing_failure.get("confidence")
            return (
                str(repairability) if repairability is not None else None,
                float(confidence) if confidence is not None else None,
            )

        node_id = str(getattr(node, "id", id(node)))
        analysis = str(getattr(node, "analysis", "") or "")
        cache_key = (node_id, fail_class, f"{error or ''}|{analysis}")
        if cache_key in self._jev_failure_cache:
            return self._jev_failure_cache[cache_key]
        repairability, advice = self.advisor.repairability(
            fail_class=fail_class,
            error=error,
            analysis=analysis,
        )
        confidence = None if advice is None else float(advice.confidence)
        advisory = {} if advice is None else advice.to_dict()
        if repairability is not None:
            advisory["repairability"] = repairability
        if advisory:
            # Persist the exact bounded advisory used for this observed node so the
            # resulting replay world can reproduce the same prefix signal without
            # calling JEV during offline dreaming. Preserve earlier shadow routing /
            # verification evidence attached at generation time.
            merged = dict(getattr(node, "rsi_jev_advisory", {}) or {})
            merged["failure_classification"] = advisory
            if repairability is not None:
                merged["repairability"] = repairability
            node.rsi_jev_advisory = merged
        self._jev_failure_cache[cache_key] = (repairability, confidence)
        return repairability, confidence

    def _prefix_state(
        self, journal: Any
    ) -> tuple[dict[str, Any], dict[str, Any | None]]:
        nodes = list(getattr(journal, "nodes", []))
        maximize = (
            True
            if getattr(journal, "metric_maximize", None) is None
            else bool(journal.metric_maximize)
        )
        observed: dict[str, Observation] = {}
        bindings: dict[str, Any | None] = {}

        for node in nodes:
            node_id = str(getattr(node, "id"))
            parent = getattr(node, "parent", None)
            parent_id = ROOT_ID if parent is None else str(getattr(parent, "id"))
            score = self._raw_score(node)
            parent_score = self._raw_score(parent) if parent is not None else None
            delta = None
            if score is not None and parent_score is not None:
                delta = (score - parent_score) if maximize else (parent_score - score)
            fail_class = self._failure_class(node)
            error = (
                str(
                    getattr(node, "analysis", "") or getattr(node, "exc_info", "") or ""
                )
                or None
            )
            repairability, advisory_confidence = self._failure_advice(
                node, fail_class, error
            )
            observed[node_id] = Observation(
                id=node_id,
                parent_id=parent_id,
                step=int(getattr(node, "step", 0) or 0),
                depth=self._depth(node),
                branch_id=self._branch_id(node),
                score=score,
                valid=(
                    score is not None and not bool(getattr(node, "is_buggy", False))
                ),
                is_buggy=bool(getattr(node, "is_buggy", score is None)),
                fail_class=fail_class,
                error=error,
                delta_vs_parent=delta,
                # Live policy does not receive a hidden first-attempt baseline.
                delta_vs_baseline=None,
                exec_time=getattr(node, "exec_time", None),
                repairability=repairability,
                advisory_confidence=advisory_confidence,
            )

        legal_actions: list[dict[str, str]] = []
        roots_opened = sum(1 for n in nodes if getattr(n, "parent", None) is None)
        root_slots = max(0, self.width_cap - roots_opened)
        # Each root slot receives a distinct action id.  Mapping by action id fixes
        # the old ``None`` deduplication bug that could exceed width_cap.
        for slot in range(root_slots):
            action_id = f"root:live:{roots_opened + slot}"
            legal_actions.append(
                {"action_id": action_id, "parent_id": ROOT_ID, "kind": "open_root"}
            )
            bindings[action_id] = None

        for node in nodes:
            if not bool(getattr(node, "is_leaf", True)):
                continue
            if self._depth(node) >= self.depth_cap:
                continue
            node_id = str(getattr(node, "id"))
            action_id = f"refine:live:{node_id}"
            legal_actions.append(
                {"action_id": action_id, "parent_id": node_id, "kind": "refine"}
            )
            bindings[action_id] = node

        if self.support_index is not None:
            support_score = self.support_index.support_observations(observed)
        elif self.support_score is not None:
            support_score = float(self.support_score)
        else:
            support_score = 1.0
        state = {
            "observed": observed,
            "legal_actions": legal_actions,
            "probes": len(nodes),
            "rounds": 0,
            "baseline_score": None,
            "maximize": maximize,
            "max_parallelism": (
                min(self.max_parallelism, max(1, len(legal_actions)))
                if legal_actions
                else self.max_parallelism
            ),
            "support_score": support_score,
        }
        return state, bindings

    def select_parents(self, journal: Any) -> list[Any | None]:
        state, bindings = self._prefix_state(journal)
        action_ids = self.policy.select_batch(state)
        if self.advisor is not None:
            # Shadow-only: JEV may rank the already-legal actions for measurement,
            # but it cannot alter the deterministic DREAM policy's selected batch.
            self.advisor.shadow_rank_actions(state, list(action_ids))
        # The policy can only return ids in the public legal action set.  Fail
        # closed on an invalid id rather than silently changing semantics.
        unknown = [aid for aid in action_ids if aid not in bindings]
        if unknown:
            raise RuntimeError(f"policy selected unknown live actions: {unknown}")
        return [bindings[aid] for aid in action_ids]
