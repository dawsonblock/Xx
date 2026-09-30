from aide.rsi.policy import AdaptiveReplayPolicy
from aide.rsi.types import PolicyGenome


def test_genome_bounds_are_fail_closed():
    g = PolicyGenome(beta=99, stagnation_patience=-10, stop_threshold=999).bounded()
    assert g.beta == 1.0
    assert g.stagnation_patience == 1
    assert g.stop_threshold == 2.0


def test_grid_planner_chooses_width_when_early_gains_dominate():
    p = AdaptiveReplayPolicy()
    history = [
        {"early_root_gain_rate": 0.5, "deep_gain_rate": 0.1, "plateau_rate": 0.1, "hard_failure_rate": 0.0, "direction_coverage": 0.4},
        {"early_root_gain_rate": 0.4, "deep_gain_rate": 0.1, "plateau_rate": 0.1, "hard_failure_rate": 0.0, "direction_coverage": 0.5},
    ]
    plan = p.plan_grid(history, fallback_width=6, fallback_depth=8, hard_max_width=20, hard_max_depth=20)
    assert plan.branch_count == 7
    assert plan.refine_count == 7
