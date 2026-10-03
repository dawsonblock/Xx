from __future__ import annotations

from dataclasses import fields
from typing import Any, cast

from .evaluator import ReplayEvaluator
from .policy import AdaptiveReplayPolicy
from .types import PolicyGenome, ReplayWorld


class LLMPolicyDeveloper:
    """Optional semantic candidate generator constrained to the typed policy DSL.

    The model cannot emit executable policy code. It may choose only verified
    structural operators and bounded parameters, all parsed through
    ``PolicyGenome.from_dict`` before replay evaluation.
    """

    def __init__(self, *, model: str, temperature: float = 0.4):
        self.model = model
        self.temperature = float(temperature)

    @staticmethod
    def _function_spec():
        # Delayed import keeps replay-only installs dependency-light.
        from aide.backend import FunctionSpec

        props: dict[str, Any] = {}
        defaults = PolicyGenome().to_dict()
        enums = {
            "score_rule": ["linear", "ucb", "trend"],
            "allocation_rule": ["portfolio", "greedy", "race"],
            "stop_rule": ["threshold", "patience", "conservative"],
        }
        for f in fields(PolicyGenome):
            value = defaults[f.name]
            if f.name in enums:
                props[f.name] = {"type": "string", "enum": enums[f.name]}
            elif isinstance(value, int):
                props[f.name] = {"type": "integer"}
            else:
                props[f.name] = {"type": "number"}
        return FunctionSpec(
            name="submit_policy_genome",
            json_schema={
                "type": "object",
                "properties": props,
                "required": list(props),
            },
            description="Submit a complete bounded exploration-policy genome.",
        )

    def propose(
        self,
        incumbent: PolicyGenome,
        worlds: list[ReplayWorld],
        evaluator: ReplayEvaluator,
        *,
        count: int = 4,
    ) -> list[PolicyGenome]:
        from aide.backend import query

        inc_score = evaluator.evaluate_pool(AdaptiveReplayPolicy(incumbent), worlds)
        episode_feedback = [
            {
                "world": ep.world_id,
                "reward": ep.reward,
                "attainment": ep.attainment,
                "probes": ep.probes,
                "rounds": ep.rounds,
                "parallel_efficiency": ep.parallel_efficiency,
                "stopped": ep.stopped,
            }
            for ep in inc_score.episodes
        ]
        prompt = {
            "Role": "Improve an exploration controller for grounded discovery-tree replay.",
            "Invariant": [
                "The replay world contains only previously measured outcomes; do not assume unseen outcomes.",
                "Improve branch allocation, recovery, width/depth pressure, batching, and stopping.",
                "Do not change the evaluator or qualification rules.",
                "Prefer concrete changes justified by replay behavior; avoid arbitrary large parameter shifts.",
            ],
            "Incumbent genome": incumbent.to_dict(),
            "Incumbent replay summary": {
                "mean_reward": inc_score.mean_reward,
                "mean_attainment": inc_score.mean_attainment,
                "mean_work_fraction": inc_score.mean_work_fraction,
                "mean_parallel_efficiency": inc_score.mean_parallel_efficiency,
                "episodes": episode_feedback,
            },
        }
        out: list[PolicyGenome] = []
        for _ in range(max(0, int(count))):
            raw = cast(
                dict,
                query(
                    system_message=prompt,
                    user_message=None,
                    func_spec=self._function_spec(),
                    model=self.model,
                    temperature=self.temperature,
                ),
            )
            out.append(PolicyGenome.from_dict(raw))
        return out
