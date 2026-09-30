from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping


def _utcnow() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def answer_key(question: Mapping[str, Any], answer: Mapping[str, Any]) -> str:
    typ = question.get('type')
    if typ == 'noul':
        return 'yes' if float(answer.get('noul', 0.0)) >= 0.5 else 'no'
    if typ == 'choice':
        return str(answer.get('choice'))
    if typ == 'score':
        return f"{float(answer.get('score')):.12g}"
    return json.dumps(answer, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


class ShadowJournal:
    """Privacy-minimized journal for shadow/canary comparisons.

    It never stores request state. It stores exact task signatures, selected answer keys,
    backend names, scores and evidence identifiers so outcomes can later be joined without
    retaining the original prompt context.
    """

    def __init__(self, path: str | None):
        self.path = Path(path) if path else None

    def append(self, *, request_id: str, shadow_rows: list[Mapping[str, Any]], evidence_sha256: str | None) -> int:
        if self.path is None or not shadow_rows:
            return 0
        self.path.parent.mkdir(parents=True, exist_ok=True)
        lines: list[bytes] = []
        ts = _utcnow()
        for row in shadow_rows:
            value = {
                'version': 1,
                'timestamp': ts,
                'request_id': request_id,
                'question_id': str(row.get('question_id')),
                'signature': str(row.get('signature')),
                'deployment_stage': row.get('deployment_stage'),
                'candidate_backend': row.get('candidate_backend'),
                'baseline_backend': row.get('baseline_backend'),
                'production_backend': row.get('production_backend'),
                'shadow_backend': row.get('shadow_backend'),
                'production_key': row.get('production_key'),
                'shadow_key': row.get('shadow_key'),
                'production_score': row.get('production_score'),
                'shadow_score': row.get('shadow_score'),
                'agreement': bool(row.get('agreement')),
                'evidence_sha256': evidence_sha256,
            }
            lines.append((json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False) + '\n').encode())
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            for line in lines:
                os.write(fd, line)
            os.fsync(fd)
        finally:
            os.close(fd)
        return len(lines)


def load_shadow_rows(path: str | Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for n, line in enumerate(Path(path).read_text().splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except Exception as exc:
            raise ValueError(f'shadow journal line {n} is invalid JSON') from exc
        if int(row.get('version', 0)) != 1:
            raise ValueError(f'shadow journal line {n} has unsupported version')
        rows.append(row)
    return rows
