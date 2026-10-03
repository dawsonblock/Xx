"""Check the normative V6 documentation table against executable constants."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from aide.rsi.statistics import (
    MAX_PROMOTION_ATTEMPTS,
    MULTITASK_MIN_FAMILIES_PER_STRATUM,
    MULTITASK_MIN_INDEPENDENT_FAMILIES,
    MULTITASK_MIN_RUNS_PER_TASK,
    MULTITASK_MIN_STRATA,
    MULTITASK_MIN_TASKS,
    MULTITASK_PROTOCOL,
)

ROOT = Path(__file__).resolve().parents[1]
START = "<!-- BEGIN GENERATED V6 POLICY -->"
END = "<!-- END GENERATED V6 POLICY -->"


def table() -> str:
    alpha = MULTITASK_PROTOCOL["family_alpha"]
    rows = [
        ("Minimum distinct tasks", MULTITASK_MIN_TASKS),
        ("Minimum independent families", MULTITASK_MIN_INDEPENDENT_FAMILIES),
        ("Minimum strata", MULTITASK_MIN_STRATA),
        ("Minimum families per stratum", MULTITASK_MIN_FAMILIES_PER_STRATUM),
        ("Paired runs per task", MULTITASK_MIN_RUNS_PER_TASK),
        ("Promotion attempt horizon", MAX_PROMOTION_ATTEMPTS),
        ("Family alpha", alpha),
        ("Per-attempt alpha", alpha / MAX_PROMOTION_ATTEMPTS),
    ]
    return "\n".join(
        [
            START,
            "| Policy | V6 value |",
            "| --- | ---: |",
            *(f"| {name} | {value} |" for name, value in rows),
            END,
        ]
    )


def check(root: Path = ROOT) -> None:
    text = (root / "docs/STATISTICAL_QUALIFICATION.md").read_text()
    start = text.index(START)
    end = text.index(END, start) + len(END)
    if text[start:end] != table():
        raise ValueError("normative V6 table differs from executable protocol")
    architecture = (root / "docs/ARCHITECTURE.md").read_text()
    if "20-task and 20-family minimums" in architecture:
        raise ValueError("architecture still claims V5 minima")
    calibration = (root / "tools/qualify_canary_statistics.py").read_text()
    if "protocol V5 requires" in calibration:
        raise ValueError("calibration still reports V5")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    check()
    print("normative V6 documentation matches executable constants")
