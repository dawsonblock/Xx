from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import replace
from statistics import mean
from typing import Any, Iterable

from .types import GridPlan, Observation, PolicyGenome, ROOT_ID


def _is_repairable(fail_class: str, error: str | None = None) -> bool:
    text = f"{fail_class} {error or ''}".lower()
    hard = ("dependency", "permission", "missing data", "unsupported", "sandbox")
    if any(x in text for x in hard):
        return False
    repairable = (
        "compile",
        "syntax",
        "runtime",
        "evaluation",
        "resource",
        "timeout",
        "shape",
        "mask",
        "layout",
    )
    return any(x in text for x in repairable)


def _direction(value: float | None, maximize: bool) -> float | None:
    if value is None or not math.isfinite(value):
        return None
    return value if maximize else -value


def _norm(value: float, lo: float, hi: float) -> float:
    if hi <= lo + 1e-12:
        return 0.5
    return (value - lo) / (hi - lo)


class AdaptiveReplayPolicy:
    """Prefix-only exploration controller with a small typed policy DSL.

    The policy is intentionally non-Turing-complete. Offline evolution may change
    three structural operators (scoring, allocation, and stopping) plus bounded
    numeric parameters, but it cannot access files, networks, evaluators, hidden
    replay outcomes, or qualification state.
    """

    def __init__(self, genome: PolicyGenome | None = None):
        self.genome = (genome or PolicyGenome()).bounded()

    def _effective_beta(self, state: dict[str, Any]) -> float:
        support = float(state.get("support_score", 1.0))
        if not math.isfinite(support):
            support = 0.0
        support = min(1.0, max(0.0, support))
        return min(
            1.0, self.genome.beta + self.genome.ood_explore_boost * (1.0 - support)
        )

    def _branch_trace(
        self, parent_id: str, observed: dict[str, Observation]
    ) -> list[Observation]:
        if parent_id == ROOT_ID or parent_id not in observed:
            return []
        trace: list[Observation] = []
        cur = observed[parent_id]
        seen: set[str] = set()
        while cur.id not in seen:
            seen.add(cur.id)
            trace.append(cur)
            if cur.parent_id == ROOT_ID or cur.parent_id not in observed:
                break
            cur = observed[cur.parent_id]
        return list(reversed(trace))

    def _features(
        self,
        parent_id: str,
        observed: dict[str, Observation],
        maximize: bool,
        beta: float,
        total_probes: int,
    ) -> dict[str, float | bool | str]:
        g = self.genome
        trace = self._branch_trace(parent_id, observed)
        if not trace:
            return {"valid": False}

        valid_direction_scores = [
            _direction(o.score, maximize)
            for o in observed.values()
            if o.valid and _direction(o.score, maximize) is not None
        ]
        lo = min(valid_direction_scores) if valid_direction_scores else 0.0
        hi = max(valid_direction_scores) if valid_direction_scores else 1.0

        success = [
            o for o in trace if o.valid and _direction(o.score, maximize) is not None
        ]
        anchor = max((_direction(o.score, maximize) for o in success), default=lo)
        anchor_norm = _norm(float(anchor), lo, hi)

        gains: list[float] = []
        for obs in success[-6:]:
            if obs.delta_vs_parent is not None and math.isfinite(obs.delta_vs_parent):
                gains.append(obs.delta_vs_parent)
        trend = mean(gains[-3:]) if gains else 0.0
        scale = max(1e-9, abs(hi - lo))
        trend_norm = max(-1.0, min(1.0, trend / scale))
        last_gain = max(-1.0, min(1.0, (gains[-1] / scale) if gains else 0.0))

        latest = trace[-1]
        failure = 0.0
        recovery = 0.0
        if latest.is_buggy:
            # High-confidence JEV repairability is a bounded advisory signal that
            # may refine recovery classification. It never adds an action or grants
            # authority. Historical replay stores the resolved signal with the node.
            repairability = getattr(latest, "repairability", None)
            if repairability == "repairable":
                recovery = 1.0
            elif repairability == "hard":
                failure = 1.0
            elif _is_repairable(latest.fail_class, latest.error):
                recovery = 1.0
            else:
                failure = 1.0

        patience = max(1, int(round(g.stagnation_patience * (0.65 + 0.7 * beta))))
        recent_gains = gains[-patience:]
        stagnant = bool(recent_gains) and all(
            x <= g.min_relative_gain * scale for x in recent_gains
        )
        underexplored = 1.0 / max(1.0, float(latest.depth))
        # UCB-style optimism over a branch frontier. This is not a probabilistic
        # claim; it is a bounded exploration bonus based only on prefix-visible work.
        ucb = math.sqrt(
            math.log1p(max(1, total_probes)) / max(1.0, float(latest.depth))
        )

        return {
            "valid": True,
            "anchor_norm": anchor_norm,
            "trend_norm": trend_norm,
            "last_gain": last_gain,
            "failure": failure,
            "recovery": recovery,
            "stagnant": stagnant,
            "underexplored": underexplored,
            "depth": float(latest.depth),
            "ucb": ucb,
        }

    def _score_refine(
        self,
        parent_id: str,
        observed: dict[str, Observation],
        maximize: bool,
        beta: float,
        total_probes: int = 0,
    ) -> tuple[float, str]:
        g = self.genome
        f = self._features(parent_id, observed, maximize, beta, total_probes)
        if not f.get("valid"):
            return -math.inf, "missing-prefix"

        anchor_norm = float(f["anchor_norm"])
        trend_norm = float(f["trend_norm"])
        last_gain = float(f["last_gain"])
        underexplored = float(f["underexplored"])
        recovery = float(f["recovery"])
        failure = float(f["failure"])
        depth = float(f["depth"])
        stagnant = bool(f["stagnant"])
        ucb = float(f["ucb"])

        if g.score_rule == "ucb":
            # Quality plus explicit optimism for less-explored frontiers.
            quality = g.exploit_weight * anchor_norm + g.last_gain_weight * last_gain
            exploration = g.ucb_weight * ucb * (0.5 + beta)
            trend_term = 0.5 * g.trend_weight * trend_norm
        elif g.score_rule == "trend":
            # Momentum/racing rule: favor branches still improving, while keeping a
            # smaller anchor term so one noisy step cannot dominate.
            quality = (
                0.55 * g.exploit_weight * anchor_norm
                + 1.35 * g.last_gain_weight * last_gain
            )
            exploration = g.underexplored_weight * underexplored * beta
            trend_term = 1.5 * g.trend_weight * trend_norm
        else:
            quality = g.exploit_weight * anchor_norm + g.last_gain_weight * last_gain
            exploration = g.underexplored_weight * underexplored * beta
            trend_term = g.trend_weight * trend_norm

        score = (
            quality
            + trend_term
            + exploration
            + g.recovery_weight * recovery * (0.5 + beta)
            - g.failure_penalty * failure
            - g.depth_penalty * depth * (1.15 - beta)
            - g.stagnation_penalty * float(stagnant) * (1.25 - beta)
        )
        role = "recovery" if recovery else "exploit"
        return score, role

    def _root_score(
        self,
        observed: dict[str, Observation],
        beta: float,
        root_ordinal: int,
        total_probes: int = 0,
    ) -> float:
        g = self.genome
        opened_branches = len({o.branch_id for o in observed.values()})
        novelty_pressure = 1.0 / (1.0 + opened_branches)
        duplicate_root_penalty = 0.05 * root_ordinal
        score = (
            g.exploration_weight * (0.35 + beta)
            + g.underexplored_weight * novelty_pressure
            - duplicate_root_penalty
        )
        if g.score_rule == "ucb":
            score += (
                g.ucb_weight
                * math.sqrt(math.log1p(max(1, total_probes + 1)))
                * (0.5 + beta)
            )
        elif g.score_rule == "trend":
            # Trend policies still need a nonzero opening pressure or they collapse
            # before enough branches exist to estimate momentum.
            score += 0.25 * g.exploration_weight * (1.0 + beta)
        return score

    def _should_stop(
        self,
        ranked: list[tuple[float, str, str]],
        observed: dict[str, Observation],
        beta: float,
    ) -> bool:
        if not ranked or not observed:
            return not ranked
        best_score = ranked[0][0]
        g = self.genome
        if g.stop_rule == "conservative":
            # Do not stop while an explore/recovery action remains remotely viable.
            special = [x for x in ranked if x[1] in {"explore", "recovery"}]
            if special and max(x[0] for x in special) >= g.stop_threshold - 0.35 * beta:
                return False
            return best_score < g.stop_threshold
        if g.stop_rule == "patience":
            # Require several observed attempts before a low score can stop the run.
            if len(observed) < max(2, g.stagnation_patience):
                return False
            return best_score < g.stop_threshold - 0.10 * beta
        return best_score < g.stop_threshold

    def select_batch(self, state: dict[str, Any]) -> list[str]:
        observed: dict[str, Observation] = state["observed"]
        legal: list[dict[str, str]] = state["legal_actions"]
        maximize = bool(state["maximize"])
        max_parallelism = max(1, int(state["max_parallelism"]))
        total_probes = max(0, int(state.get("probes", len(observed))))
        beta = self._effective_beta(state)

        ranked: list[tuple[float, str, str]] = []
        root_ordinal = 0
        for action in legal:
            if action["kind"] == "open_root":
                score = self._root_score(observed, beta, root_ordinal, total_probes)
                root_ordinal += 1
                ranked.append((score, "explore", action["action_id"]))
            else:
                score, role = self._score_refine(
                    action["parent_id"], observed, maximize, beta, total_probes
                )
                ranked.append((score, role, action["action_id"]))

        if not ranked:
            return []
        ranked.sort(key=lambda x: (-x[0], x[2]))
        if self._should_stop(ranked, observed, beta):
            return []

        g = self.genome
        if g.allocation_rule == "greedy":
            return [
                aid
                for score, _, aid in ranked
                if score >= g.stop_threshold - 0.15 * beta
            ][:max_parallelism]

        if g.allocation_rule == "race":
            opened = len({o.branch_id for o in observed.values()})
            roots = [x for x in ranked if x[1] == "explore"]
            # During the racing phase, deliberately establish multiple independent
            # roots before concentrating budget on the best observed frontiers.
            if roots and opened < g.race_min_roots:
                return [x[2] for x in roots[:max_parallelism]]
            batch: list[str] = []
            exploit = [x for x in ranked if x[1] == "exploit"]
            recovery = [x for x in ranked if x[1] == "recovery"]
            if exploit:
                batch.append(exploit[0][2])
            if (
                recovery
                and len(batch) < max_parallelism
                and recovery[0][0] >= ranked[0][0] - g.recovery_floor
            ):
                batch.append(recovery[0][2])
            if roots and len(batch) < max_parallelism and beta >= 0.35:
                batch.append(roots[0][2])
            for _, _, aid in ranked:
                if len(batch) >= max_parallelism:
                    break
                if aid not in batch:
                    batch.append(aid)
            return batch

        # Default dynamic portfolio: guarantee exploration/recovery representation
        # when justified, then fill remaining slots by ranked priority.
        batch: list[str] = []
        used_roles: defaultdict[str, int] = defaultdict(int)
        best_score = ranked[0][0]
        explore = [x for x in ranked if x[1] == "explore"]
        recovery = [x for x in ranked if x[1] == "recovery"]

        if (
            explore
            and beta >= 0.25
            and explore[0][0] >= best_score - g.exploration_floor
        ):
            batch.append(explore[0][2])
            used_roles["explore"] += 1
        if (
            recovery
            and recovery[0][0] >= best_score - g.recovery_floor
            and len(batch) < max_parallelism
        ):
            batch.append(recovery[0][2])
            used_roles["recovery"] += 1

        for score, role, action_id in ranked:
            if len(batch) >= max_parallelism:
                break
            if action_id in batch:
                continue
            if role == "recovery" and used_roles["recovery"] >= 1:
                continue
            selectivity = g.stop_threshold - 0.15 * beta
            if score < selectivity and batch:
                continue
            batch.append(action_id)
            used_roles[role] += 1
        return batch

    def plan_grid(
        self,
        history: Iterable[dict[str, Any]],
        *,
        fallback_width: int,
        fallback_depth: int,
        hard_max_width: int,
        hard_max_depth: int,
    ) -> GridPlan:
        """Choose next live width/depth from prior live cycle summaries only."""
        history = list(history)
        fw = min(hard_max_width, max(1, int(fallback_width)))
        fd = min(hard_max_depth, max(0, int(fallback_depth)))
        if len(history) < 2:
            return GridPlan(fw, fd, "insufficient history; conservative bootstrap")

        recent = history[-3:]
        root_early_gain = mean(
            float(x.get("early_root_gain_rate", 0.0)) for x in recent
        )
        deep_gain = mean(float(x.get("deep_gain_rate", 0.0)) for x in recent)
        plateau = mean(float(x.get("plateau_rate", 0.0)) for x in recent)
        hard_fail = mean(float(x.get("hard_failure_rate", 0.0)) for x in recent)
        coverage = mean(float(x.get("direction_coverage", 0.0)) for x in recent)

        width, depth = fw, fd
        reason: list[str] = []
        if hard_fail > 0.45:
            width = max(1, width - 1)
            depth = max(0, depth - 1)
            reason.append("repeated hard failures")
        elif root_early_gain > deep_gain * 1.25:
            width = min(hard_max_width, width + 1)
            depth = max(1, depth - 1)
            reason.append("early gains favor width")
        elif deep_gain > root_early_gain * 1.25:
            width = max(1, width - 1)
            depth = min(hard_max_depth, depth + 2)
            reason.append("late gains favor depth")
        elif plateau > 0.6 and coverage < 0.8:
            width = min(hard_max_width, width + 2)
            reason.append("plateau with uncovered directions")
        else:
            reason.append("mixed evidence; hold near prior grid")
        return GridPlan(width, depth, "; ".join(reason))

    def with_beta(self, beta: float) -> "AdaptiveReplayPolicy":
        return AdaptiveReplayPolicy(replace(self.genome, beta=beta).bounded())
