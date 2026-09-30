from pathlib import Path

from aide.rsi.pool import ReplayWorldPool
from aide.rsi.types import ReplayNode, ReplayWorld, ROOT_ID


def test_world_pool_detects_tampering(tmp_path: Path):
    pool = ReplayWorldPool(tmp_path)
    w = ReplayWorld("w", {"a": ReplayNode("a", ROOT_ID, 0, 1, "a", 1.0, True, False)})
    p = pool.add(w)
    assert pool.load_all()[0].world_id == "w"
    p.write_text(p.read_text() + " ")
    try:
        pool.load_all()
    except ValueError:
        pass
    else:
        raise AssertionError("tampered replay world must fail integrity check")
