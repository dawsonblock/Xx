"""AIDE package.

Heavy runtime dependencies are imported lazily so the replay-only RSI tooling can
operate on saved discovery trees without installing the full coding-agent stack.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .agent import Agent
    from .interpreter import Interpreter
    from .journal import Journal


@dataclass
class Solution:
    code: str
    valid_metric: float


class Experiment:
    def __init__(self, data_dir: str, goal: str, eval: str | None = None):
        from omegaconf import OmegaConf
        from rich.status import Status

        from .agent import Agent, add_task_metric, determine_task_metric
        from .interpreter import Interpreter
        from .journal import Journal
        from .utils.config import (
            _load_cfg,
            load_task_desc,
            prep_agent_workspace,
            prep_cfg,
        )

        _cfg = _load_cfg(use_cli_args=False)
        _cfg.data_dir = data_dir
        _cfg.goal = goal
        _cfg.eval = eval
        self.cfg = prep_cfg(_cfg)

        self.task_desc = load_task_desc(self.cfg)
        task_metric = determine_task_metric(self.task_desc, self.cfg.agent)
        self.task_desc = add_task_metric(self.task_desc, task_metric)

        with Status("Preparing agent workspace (copying and extracting files) ..."):
            prep_agent_workspace(self.cfg)

        self.journal = Journal(
            metric_maximize=task_metric.maximize if task_metric is not None else None
        )
        self.agent = Agent(
            task_desc=self.task_desc,
            cfg=self.cfg,
            journal=self.journal,
        )
        self.interpreter = Interpreter(
            self.cfg.workspace_dir,
            **OmegaConf.to_container(self.cfg.exec),  # type: ignore
        )

    def run(self, steps: int) -> Solution:
        from .utils.config import save_run

        for _i in range(steps):
            self.agent.step(exec_callback=self.interpreter.run)
            save_run(self.cfg, self.journal)
        self.interpreter.cleanup_session()

        best_node = self.journal.get_best_node(only_good=False)
        return Solution(code=best_node.code, valid_metric=best_node.metric.value)


def __getattr__(name: str) -> Any:
    if name == "Agent":
        from .agent import Agent

        return Agent
    if name == "Interpreter":
        from .interpreter import Interpreter

        return Interpreter
    if name == "Journal":
        from .journal import Journal

        return Journal
    raise AttributeError(name)


__all__ = ["Agent", "Experiment", "Interpreter", "Journal", "Solution"]
