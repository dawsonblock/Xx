from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from aide.version import package_version

from .evaluator import ReplayEvaluator
from .evolution import PolicyEvolutionEngine
from .policy import AdaptiveReplayPolicy
from .pool import ReplayWorldPool
from .qualification import QualificationGate
from .split import PersistentSplitManager
from .types import PolicyGenome, ReplayWorld
from .world import world_from_journal_json


def _load_world_dir(path: Path) -> list[ReplayWorld]:
    if path.is_file():
        return [ReplayWorldPool.load_flat_strict(path)]
    if not path.exists():
        raise FileNotFoundError(path)
    if (path / "manifest.json").exists():
        return ReplayWorldPool(path).load_all()
    worlds = []
    for p in sorted(path.glob("*.world.json")):
        worlds.append(ReplayWorldPool.load_flat_strict(p))
    return worlds


def _write_flat_strict(world: ReplayWorld, path: Path) -> None:
    world.validate(require_chain_branches=True)
    world.save(path)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    path.with_suffix(path.suffix + ".sha256").write_text(digest + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="aide-rsi-replay", description="Offline DREAM-RSI replay tools"
    )
    parser.add_argument("--version", action="version", version=package_version())
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_build = sub.add_parser(
        "build-world",
        help="convert AIDE journal.json to an integrity-protected replay world",
    )
    p_build.add_argument("journal", type=Path)
    p_build.add_argument("output", type=Path)
    p_build.add_argument("--parallelism", type=int, default=1)
    p_build.add_argument(
        "--world-id", default=None, help="optional explicit logical world id"
    )

    p_eval = sub.add_parser(
        "evaluate", help="evaluate a declarative policy over a world pool"
    )
    p_eval.add_argument("world_dir", type=Path)
    p_eval.add_argument("--policy", type=Path)

    p_evolve = sub.add_parser(
        "evolve", help="offline-evolve and qualify an exploration policy"
    )
    p_evolve.add_argument("world_dir", type=Path)
    p_evolve.add_argument("output", type=Path)
    p_evolve.add_argument("--policy", type=Path)
    p_evolve.add_argument("--population", type=int, default=48)
    p_evolve.add_argument("--generations", type=int, default=5)
    p_evolve.add_argument("--epoch", default="0001")

    args = parser.parse_args()
    if args.cmd == "build-world":
        world = world_from_journal_json(
            args.journal, world_id=args.world_id, max_parallelism=args.parallelism
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        _write_flat_strict(world, args.output)
        print(args.output)
        return

    worlds = _load_world_dir(args.world_dir)
    genome = (
        PolicyGenome.load(args.policy)
        if getattr(args, "policy", None)
        else PolicyGenome()
    )
    evaluator = ReplayEvaluator()

    if args.cmd == "evaluate":
        score = evaluator.evaluate_pool(AdaptiveReplayPolicy(genome), worlds)
        print(
            json.dumps(
                {
                    "mean_reward": score.mean_reward,
                    "mean_attainment": score.mean_attainment,
                    "mean_work_fraction": score.mean_work_fraction,
                    "mean_parallel_efficiency": score.mean_parallel_efficiency,
                    "worlds": len(worlds),
                },
                indent=2,
            )
        )
        return

    args.output.mkdir(parents=True, exist_ok=True)
    split = PersistentSplitManager(
        args.output / "split_manifest.json", epoch=args.epoch
    ).split(worlds)
    engine = PolicyEvolutionEngine(
        evaluator, population=args.population, generations=args.generations
    )
    candidate, history = engine.evolve(genome, split.development, split.validation)
    gate = QualificationGate(evaluator)
    record = gate.compare(candidate, genome, split)
    candidate.save(args.output / "candidate_policy.json")
    record.save(args.output / "promotion_record.json")
    (args.output / "evolution_history.json").write_text(json.dumps(history, indent=2))
    print(
        json.dumps(
            {"promoted_to_canary": record.promoted, "reason": record.reason}, indent=2
        )
    )


if __name__ == "__main__":
    main()
