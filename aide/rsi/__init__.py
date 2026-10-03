"""DREAM-RSI inspired replay-based recursive improvement for AIDE.

This package intentionally does *not* implement a learned latent world model.
Historical discovery trees are the replay worlds, and only the narrow exploration
policy is recursively improved.
"""

from .evaluator import ReplayEvaluator
from .evolution import PolicyEvolutionEngine
from .policy import AdaptiveReplayPolicy
from .qualification import QualificationGate
from .replay import ReplaySimulator
from .split import PersistentSplitManager, WorldSplit, split_worlds
from .statistics import StatisticalBudget
from .types import GridPlan, PolicyGenome, ReplayNode, ReplayWorld
from .world import world_from_journal, world_from_journal_json

__all__ = [
    "AdaptiveReplayPolicy",
    "GridPlan",
    "PersistentSplitManager",
    "PolicyEvolutionEngine",
    "PolicyGenome",
    "QualificationGate",
    "ReplayEvaluator",
    "ReplayNode",
    "ReplaySimulator",
    "ReplayWorld",
    "StatisticalBudget",
    "WorldSplit",
    "split_worlds",
    "world_from_journal",
    "world_from_journal_json",
]
