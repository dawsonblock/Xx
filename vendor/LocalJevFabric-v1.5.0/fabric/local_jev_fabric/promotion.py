from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import statistics
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from .registry import canonical_json, question_signature

QUALIFICATION_VERSION = 1


def _utcnow() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_json(value: Any) -> str:
    return _sha256_bytes(canonical_json(value).encode('utf-8'))


def _atomic_write(path: str | Path, data: str, mode: int = 0o600) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f'.{target.name}.', suffix='.tmp', dir=str(target.parent))
    tmp = Path(tmp_name)
    try:
        try:
            os.fchmod(fd, mode)
        except OSError:
            pass
        with os.fdopen(fd, 'w', encoding='utf-8') as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, target)
        try:
            dfd = os.open(target.parent, os.O_RDONLY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
        except OSError:
            pass
    finally:
        if tmp.exists():
            tmp.unlink(missing_ok=True)


class PromotionJournal:
    """Opt-in, non-authoritative journal for discovering repeated unregistered tasks.

    The journal never stores request state. It records only the SystemOne question definition,
    signature and decision metadata. Journal entries can nominate a task for qualification, but
    they can never authorize registry mutation or direct execution.
    """

    def __init__(self, path: str | None):
        self.path = Path(path) if path else None

    def append(self, *, request_id: str, questions: Mapping[str, Any], trace: Mapping[str, Any]) -> int:
        if self.path is None:
            return 0
        decisions = trace.get('decisions')
        if not isinstance(decisions, Mapping):
            return 0
        rows: list[str] = []
        timestamp = _utcnow()
        for qid, meta in decisions.items():
            if not isinstance(meta, Mapping) or meta.get('registered') is True:
                continue
            question = questions.get(qid)
            if not isinstance(question, Mapping):
                continue
            sig = question_signature(question)
            # Defensive consistency check: never log a mismatched signature as a candidate.
            if meta.get('signature') not in (None, sig):
                continue
            row = {
                'version': 1,
                'timestamp': timestamp,
                'request_id': request_id,
                'question_id': str(qid),
                'signature': sig,
                'question': dict(question),
                'backend': meta.get('backend'),
                'score': meta.get('score'),
                'score_semantics': meta.get('score_semantics'),
                'evidence_sha256': trace.get('evidence_sha256'),
            }
            rows.append(json.dumps(row, sort_keys=True, separators=(',', ':'), ensure_ascii=False) + '\n')
        if not rows:
            return 0
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            for row in rows:
                os.write(fd, row.encode('utf-8'))
            os.fsync(fd)
        finally:
            os.close(fd)
        return len(rows)


def mine_candidates(path: str | Path, *, min_observations: int = 10) -> list[dict[str, Any]]:
    groups: dict[str, dict[str, Any]] = {}
    for line_no, line in enumerate(Path(path).read_text().splitlines(), start=1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except Exception as exc:
            raise ValueError(f'promotion journal line {line_no} is not valid JSON') from exc
        if int(row.get('version', 0)) != 1:
            raise ValueError(f'promotion journal line {line_no} has unsupported version')
        question = row.get('question')
        if not isinstance(question, Mapping):
            raise ValueError(f'promotion journal line {line_no} lacks a question object')
        sig = question_signature(question)
        if row.get('signature') != sig:
            raise ValueError(f'promotion journal line {line_no} signature mismatch')
        g = groups.setdefault(sig, {
            'signature': sig,
            'question': dict(question),
            'observations': 0,
            'scores': [],
            'backends': set(),
            'first_seen': row.get('timestamp'),
            'last_seen': row.get('timestamp'),
        })
        if canonical_json(g['question']) != canonical_json(question):
            raise ValueError(f'promotion journal signature collision/inconsistent question at line {line_no}')
        g['observations'] += 1
        score = row.get('score')
        if isinstance(score, (int, float)) and math.isfinite(float(score)):
            g['scores'].append(float(score))
        if row.get('backend'):
            g['backends'].add(str(row['backend']))
        g['last_seen'] = row.get('timestamp')

    out: list[dict[str, Any]] = []
    for g in groups.values():
        if g['observations'] < min_observations:
            continue
        scores = g.pop('scores')
        backends = sorted(g.pop('backends'))
        g['backends'] = backends
        g['mean_score'] = statistics.fmean(scores) if scores else None
        g['min_score'] = min(scores) if scores else None
        g['max_score'] = max(scores) if scores else None
        out.append(g)
    out.sort(key=lambda x: (-int(x['observations']), str(x['signature'])))
    return out


def expected_calibration_error(records: Iterable[tuple[float, bool]], *, bins: int = 10) -> float:
    items = list(records)
    if not items:
        return 0.0
    total = len(items)
    error = 0.0
    for i in range(bins):
        lo, hi = i / bins, (i + 1) / bins
        bucket = [(c, y) for c, y in items if lo <= c < hi or (i == bins - 1 and c == 1.0)]
        if not bucket:
            continue
        conf = statistics.fmean(c for c, _ in bucket)
        acc = statistics.fmean(1.0 if y else 0.0 for _, y in bucket)
        error += (len(bucket) / total) * abs(acc - conf)
    return error


def wilson_upper_error(errors: int, n: int, *, z: float = 1.96) -> float:
    if n <= 0:
        return 1.0
    p = errors / n
    denom = 1.0 + z * z / n
    center = p + z * z / (2.0 * n)
    radius = z * math.sqrt((p * (1.0 - p) + z * z / (4.0 * n)) / n)
    return min(1.0, (center + radius) / denom)


@dataclass(frozen=True)
class QualificationPolicy:
    min_samples: int = 100
    min_accuracy: float = 0.95
    max_ece: float = 0.08
    max_brier: float = 0.10
    max_wilson_error_upper: float = 0.10
    operating_threshold: float = 0.80

    def __post_init__(self) -> None:
        if self.min_samples < 1:
            raise ValueError('min_samples must be >= 1')
        for name in ('min_accuracy', 'max_ece', 'max_brier', 'max_wilson_error_upper', 'operating_threshold'):
            value = float(getattr(self, name))
            if not 0.0 <= value <= 1.0:
                raise ValueError(f'{name} must be in [0,1]')


def load_eval_records(path: str | Path) -> tuple[list[tuple[float, bool]], str]:
    raw = Path(path).read_bytes()
    records: list[tuple[float, bool]] = []
    for line_no, line in enumerate(raw.decode('utf-8').splitlines(), start=1):
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except Exception as exc:
            raise ValueError(f'evaluation line {line_no} is invalid JSON') from exc
        if not isinstance(item.get('correct'), bool):
            raise ValueError(f'evaluation line {line_no}: correct must be boolean')
        confidence = item.get('confidence')
        if not isinstance(confidence, (int, float)) or not math.isfinite(float(confidence)):
            raise ValueError(f'evaluation line {line_no}: confidence must be finite numeric')
        confidence = float(confidence)
        if not 0.0 <= confidence <= 1.0:
            raise ValueError(f'evaluation line {line_no}: confidence must be in [0,1]')
        records.append((confidence, item['correct']))
    if not records:
        raise ValueError('evaluation set is empty')
    return records, 'sha256:' + _sha256_bytes(raw)


def qualification_payload(*, question: Mapping[str, Any], task_id: str, backend: str,
                          backend_model: str, artifact_digest: str, backend_fingerprint: str,
                          calibration_digest: str | None, eval_records: list[tuple[float, bool]],
                          eval_digest: str, policy: QualificationPolicy) -> dict[str, Any]:
    n = len(eval_records)
    correct = sum(1 for _, y in eval_records if y)
    errors = n - correct
    accuracy = correct / n
    brier = statistics.fmean((confidence - (1.0 if y else 0.0)) ** 2 for confidence, y in eval_records)
    ece = expected_calibration_error(eval_records)
    upper = wilson_upper_error(errors, n)
    metrics = {
        'samples': n,
        'accuracy': accuracy,
        'error_rate': errors / n,
        'ece_10bin': ece,
        'brier': brier,
        'wilson_error_upper_95': upper,
    }
    gates = {
        'samples': n >= policy.min_samples,
        'accuracy': accuracy >= policy.min_accuracy,
        'ece': ece <= policy.max_ece,
        'brier': brier <= policy.max_brier,
        'wilson_error_upper': upper <= policy.max_wilson_error_upper,
    }
    qualified = all(gates.values())
    return {
        'version': QUALIFICATION_VERSION,
        'created_at': _utcnow(),
        'task_id': task_id,
        'question_signature': question_signature(question),
        'question_sha256': 'sha256:' + _sha256_json(question),
        'backend': backend,
        'backend_model': backend_model,
        'artifact_digest': artifact_digest,
        'backend_fingerprint': backend_fingerprint,
        'calibration_digest': calibration_digest,
        'evaluation_digest': eval_digest,
        'policy': {
            'min_samples': policy.min_samples,
            'min_accuracy': policy.min_accuracy,
            'max_ece': policy.max_ece,
            'max_brier': policy.max_brier,
            'max_wilson_error_upper': policy.max_wilson_error_upper,
            'operating_threshold': policy.operating_threshold,
        },
        'metrics': metrics,
        'gates': gates,
        'qualified': qualified,
    }


def sign_qualification(payload: Mapping[str, Any], hmac_key: str) -> dict[str, Any]:
    body = dict(payload)
    digest = _sha256_json(body)
    mac = hmac.new(hmac_key.encode('utf-8'), canonical_json(body).encode('utf-8'), hashlib.sha256).hexdigest()
    return {
        **body,
        'integrity': {
            'payload_sha256': digest,
            'algorithm': 'hmac-sha256',
            'mac': mac,
        },
    }


def verify_qualification(value: Mapping[str, Any], *, hmac_key: str, require_qualified: bool = True) -> dict[str, Any]:
    if int(value.get('version', 0)) != QUALIFICATION_VERSION:
        raise ValueError('unsupported qualification version')
    integrity = value.get('integrity')
    if not isinstance(integrity, Mapping) or integrity.get('algorithm') != 'hmac-sha256':
        raise ValueError('qualification is not HMAC authenticated')
    payload = {k: v for k, v in value.items() if k != 'integrity'}
    digest = _sha256_json(payload)
    if integrity.get('payload_sha256') != digest:
        raise ValueError('qualification payload digest mismatch')
    expected = hmac.new(hmac_key.encode('utf-8'), canonical_json(payload).encode('utf-8'), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(str(integrity.get('mac') or ''), expected):
        raise ValueError('qualification HMAC verification failed')
    if require_qualified and payload.get('qualified') is not True:
        raise ValueError('qualification gates did not pass')
    return payload


def qualification_digest(value: Mapping[str, Any]) -> str:
    return 'sha256:' + _sha256_json(value)


def write_json(path: str | Path, value: Mapping[str, Any]) -> None:
    _atomic_write(path, json.dumps(value, indent=2, ensure_ascii=False) + '\n')
