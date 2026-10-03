from __future__ import annotations

import json
import math
import statistics
from collections import Counter, defaultdict, deque
from pathlib import Path
from typing import Any, Iterable, Mapping

DRIFT_PROFILE_VERSION = 1


def _js_divergence(p: Mapping[str, float], q: Mapping[str, float]) -> float:
    keys = set(p) | set(q)
    if not keys:
        return 0.0
    eps = 1e-12
    pp = {k: max(eps, float(p.get(k, 0.0))) for k in keys}
    qq = {k: max(eps, float(q.get(k, 0.0))) for k in keys}
    ps = sum(pp.values()); qs = sum(qq.values())
    pp = {k: v / ps for k, v in pp.items()}; qq = {k: v / qs for k, v in qq.items()}
    m = {k: (pp[k] + qq[k]) / 2.0 for k in keys}
    def kl(a, b):
        return sum(a[k] * math.log2(a[k] / b[k]) for k in keys)
    return 0.5 * kl(pp, m) + 0.5 * kl(qq, m)


def build_profiles(rows: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    grouped: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for row in rows:
        sig = str(row.get('signature') or '')
        score = row.get('score')
        key = row.get('answer_key')
        if not sig or not isinstance(score, (int, float)) or not math.isfinite(float(score)) or key is None:
            continue
        grouped[sig].append(row)
    profiles: dict[str, Any] = {}
    for sig, items in grouped.items():
        scores = [float(x['score']) for x in items]
        counts = Counter(str(x['answer_key']) for x in items)
        total = sum(counts.values())
        profiles[sig] = {
            'samples': len(items),
            'score_mean': statistics.fmean(scores),
            'score_std': statistics.pstdev(scores) if len(scores) > 1 else 0.0,
            'answer_distribution': {k: v / total for k, v in sorted(counts.items())},
        }
    return {'version': DRIFT_PROFILE_VERSION, 'profiles': profiles}


def load_profile(path: str | None) -> dict[str, Any]:
    if not path:
        return {'version': DRIFT_PROFILE_VERSION, 'profiles': {}}
    value = json.loads(Path(path).read_text())
    if int(value.get('version', 0)) != DRIFT_PROFILE_VERSION or not isinstance(value.get('profiles'), dict):
        raise ValueError('unsupported or malformed drift profile')
    return value


class DriftMonitor:
    """Windowed score/output drift detector.

    This intentionally does not claim hidden-state drift when the backend does not expose hidden
    activations. It monitors observable decision behavior: score distribution and answer mix.
    """

    def __init__(self, profile: Mapping[str, Any] | None = None, *, window: int = 100, min_samples: int = 30,
                 degraded_z: float = 2.5, disabled_z: float = 4.0,
                 degraded_js: float = 0.15, disabled_js: float = 0.30):
        self.profile = dict((profile or {}).get('profiles', {}))
        self.window = max(5, int(window)); self.min_samples = max(5, int(min_samples))
        self.degraded_z = float(degraded_z); self.disabled_z = float(disabled_z)
        self.degraded_js = float(degraded_js); self.disabled_js = float(disabled_js)
        self._windows: dict[str, deque[tuple[float, str]]] = defaultdict(lambda: deque(maxlen=self.window))
        self._last: dict[str, dict[str, Any]] = {}

    def observe(self, signature: str, *, score: float, answer_key: str) -> dict[str, Any]:
        self._windows[signature].append((float(score), str(answer_key)))
        result = self._compute(signature)
        self._last[signature] = result
        return result

    def status(self, signature: str) -> str:
        return str(self._last.get(signature, {}).get('status', 'normal'))

    def details(self, signature: str) -> dict[str, Any]:
        return dict(self._last.get(signature, {'status': 'normal', 'samples': 0, 'reference': signature in self.profile}))

    def snapshot(self) -> dict[str, Any]:
        return {sig: self.details(sig) for sig in sorted(set(self.profile) | set(self._last))}

    def _compute(self, signature: str) -> dict[str, Any]:
        ref = self.profile.get(signature)
        items = list(self._windows[signature])
        base = {'status': 'normal', 'samples': len(items), 'reference': ref is not None, 'score_z': 0.0, 'js_divergence': 0.0}
        if not isinstance(ref, Mapping) or len(items) < self.min_samples:
            return base
        scores = [x[0] for x in items]
        live_mean = statistics.fmean(scores)
        ref_mean = float(ref.get('score_mean', live_mean))
        ref_std = max(float(ref.get('score_std', 0.0)), 0.05)
        z = abs(live_mean - ref_mean) / ref_std
        counts = Counter(x[1] for x in items); n = len(items)
        live_dist = {k: v / n for k, v in counts.items()}
        ref_dist = ref.get('answer_distribution') if isinstance(ref.get('answer_distribution'), Mapping) else {}
        js = _js_divergence(live_dist, ref_dist)
        status = 'normal'
        if z >= self.disabled_z or js >= self.disabled_js:
            status = 'disabled'
        elif z >= self.degraded_z or js >= self.degraded_js:
            status = 'degraded'
        return {
            **base, 'status': status, 'score_z': z, 'js_divergence': js,
            'live_score_mean': live_mean, 'reference_score_mean': ref_mean,
        }
