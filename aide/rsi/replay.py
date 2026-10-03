from __future__ import annotations

import math
from typing import Iterable

from .types import ROOT_ID, Observation, ReplayAction, ReplayWorld


class ReplayInvariantError(RuntimeError):
    pass


class ReplaySimulator:
    """Prefix-only deterministic replay over a completed discovery tree.

    The simulator never fabricates a new outcome. Legal actions only reveal nodes
    that already exist in the recorded world, and policy code receives no access to
    unrevealed node contents.
    """

    def __init__(self, world: ReplayWorld, *, support_index=None):
        # Live AIDE-RSI can open many independent roots, but with truthful serial
        # execution each non-root frontier can produce only one continuation before
        # it stops being a leaf. Reject histories that cannot be replayed through the
        # same decision interface instead of granting the offline policy extra actions.
        world.validate(require_chain_branches=True)
        self.world = world
        self.support_index = support_index
        self._children = world.children_map()
        self._revealed: set[str] = {ROOT_ID}
        self._observations: dict[str, Observation] = {}
        self.probes = 0
        self.rounds = 0

    def reset(self) -> None:
        self._revealed = {ROOT_ID}
        self._observations = {}
        self.probes = 0
        self.rounds = 0

    def observed(self) -> dict[str, Observation]:
        return dict(self._observations)

    def revealed_ids(self) -> set[str]:
        return set(self._revealed)

    def _delta(self, score: float | None, ref: float | None) -> float | None:
        if score is None or ref is None:
            return None
        delta = score - ref
        return delta if self.world.maximize else -delta

    def _to_observation(self, node_id: str) -> Observation:
        node = self.world.nodes[node_id]
        parent_score = None
        if node.parent_id != ROOT_ID and node.parent_id in self._observations:
            parent_score = self._observations[node.parent_id].score
        return Observation(
            id=node.id,
            parent_id=node.parent_id,
            step=node.step,
            depth=node.depth,
            branch_id=node.branch_id,
            score=node.score,
            valid=node.valid,
            is_buggy=node.is_buggy,
            fail_class=node.fail_class,
            error=node.error,
            delta_vs_parent=self._delta(node.score, parent_score),
            delta_vs_baseline=self._delta(node.score, self.world.baseline_score),
            exec_time=node.exec_time,
            repairability=node.repairability,
            advisory_confidence=(
                float(
                    (node.advisory.get("failure_classification") or node.advisory).get(
                        "confidence"
                    )
                )
                if isinstance(node.advisory, dict)
                and isinstance(
                    (node.advisory.get("failure_classification") or node.advisory), dict
                )
                and (node.advisory.get("failure_classification") or node.advisory).get(
                    "confidence"
                )
                is not None
                else None
            ),
        )

    def legal_actions(self) -> list[ReplayAction]:
        actions: list[ReplayAction] = []
        # Action IDs are deliberately opaque with respect to unrevealed node IDs.
        # The target stays private inside ReplayAction. This prevents a future, more
        # expressive policy from using hidden child identifiers as a side channel.
        unopened_roots = [
            child_id
            for child_id in self._children.get(ROOT_ID, [])
            if child_id not in self._revealed
        ]
        for ordinal, child_id in enumerate(unopened_roots):
            actions.append(
                ReplayAction(
                    action_id=f"root:{ordinal}",
                    parent_id=ROOT_ID,
                    target_id=child_id,
                    kind="open_root",
                )
            )

        # Match the live controller: only currently revealed leaves may be refined.
        # Strict replay worlds have at most one recorded child per non-root node.
        for parent_id in sorted(self._revealed - {ROOT_ID}):
            if any(
                child in self._revealed for child in self._children.get(parent_id, [])
            ):
                continue
            hidden = [
                c for c in self._children.get(parent_id, []) if c not in self._revealed
            ]
            if not hidden:
                continue
            child_id = hidden[0]
            actions.append(
                ReplayAction(
                    action_id=f"refine:{parent_id}",
                    parent_id=parent_id,
                    target_id=child_id,
                    kind="refine",
                )
            )
        return actions

    def public_legal_actions(self) -> list[dict[str, str]]:
        """Policy-safe action view. target_id is deliberately omitted."""
        return [
            {"action_id": a.action_id, "parent_id": a.parent_id, "kind": a.kind}
            for a in self.legal_actions()
        ]

    def probe_batch(self, action_ids: Iterable[str]) -> list[Observation]:
        action_ids = list(action_ids)
        if len(action_ids) > self.world.max_parallelism:
            raise ReplayInvariantError("batch exceeds max_parallelism")
        if len(action_ids) != len(set(action_ids)):
            raise ReplayInvariantError("duplicate actions in a batch")

        legal = {a.action_id: a for a in self.legal_actions()}
        if any(aid not in legal for aid in action_ids):
            illegal = [aid for aid in action_ids if aid not in legal]
            raise ReplayInvariantError(
                f"illegal or already-revealed actions: {illegal}"
            )

        # Prevent selecting two refinements from the same parent in one decision
        # round; this preserves a meaningful prefix frontier.
        parents = [
            legal[aid].parent_id for aid in action_ids if legal[aid].kind == "refine"
        ]
        if len(parents) != len(set(parents)):
            raise ReplayInvariantError("a batch cannot refine the same parent twice")

        if action_ids:
            self.rounds += 1

        out: list[Observation] = []
        for aid in action_ids:
            target = legal[aid].target_id
            self._revealed.add(target)
            obs = self._to_observation(target)
            self._observations[target] = obs
            self.probes += 1
            out.append(obs)
        return out

    def done(self) -> bool:
        return not self.legal_actions()

    def best_score(self) -> float | None:
        values = [
            o.score
            for o in self._observations.values()
            if o.valid and o.score is not None and math.isfinite(o.score)
        ]
        if not values:
            return None
        return (max if self.world.maximize else min)(values)

    def snapshot(self) -> dict[str, object]:
        return {
            "observed": self.observed(),
            "legal_actions": self.public_legal_actions(),
            "probes": self.probes,
            "rounds": self.rounds,
            # This is either an explicitly public pre-search baseline or None; it
            # is never inferred from hidden replay outcomes.
            "baseline_score": self.world.baseline_score,
            "maximize": self.world.maximize,
            "max_parallelism": self.world.max_parallelism,
            "support_score": (
                self.support_index.support_observations(self._observations)
                if self.support_index is not None
                else 1.0
            ),
        }
