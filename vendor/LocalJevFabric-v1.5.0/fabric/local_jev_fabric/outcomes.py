from __future__ import annotations

import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from .registry import canonical_json


def _utcnow() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


class OutcomeStore:
    """Append-only labels/outcomes keyed to request evidence, without request state."""
    def __init__(self, path: str | None):
        self.path = Path(path) if path else None
        self._index: dict[tuple[str, str, str], dict[str, Any]] = {}
        if self.path is not None and self.path.exists():
            for n, line in enumerate(self.path.read_text().splitlines(), 1):
                if not line.strip():
                    continue
                try:
                    row = json.loads(line)
                except Exception as exc:
                    raise ValueError(f'outcome store line {n} invalid JSON') from exc
                if int(row.get('version', 0)) != 1:
                    raise ValueError(f'outcome store line {n} unsupported version')
                key = (str(row.get('request_id')), str(row.get('question_id')), str(row.get('signature')))
                prior = self._index.get(key)
                if prior is not None and (prior.get('correct'), prior.get('expected_key')) != (row.get('correct'), row.get('expected_key')):
                    raise ValueError(f'outcome store has conflicting duplicate at line {n}')
                self._index[key] = row

    def append(self, value: Mapping[str, Any]) -> dict[str, Any]:
        if self.path is None:
            raise ValueError('outcome store is not configured')
        required = ('request_id', 'question_id', 'signature', 'evidence_sha256', 'correct')
        missing = [k for k in required if k not in value]
        if missing:
            raise ValueError(f'missing outcome fields: {missing}')
        if not isinstance(value.get('correct'), bool):
            raise ValueError('correct must be boolean')
        signature = str(value.get('signature') or '')
        evidence = str(value.get('evidence_sha256') or '')
        if len(signature) != 64 or any(c not in '0123456789abcdefABCDEF' for c in signature):
            raise ValueError('signature must be a 64-hex exact question signature')
        if len(evidence) != 64 or any(c not in '0123456789abcdefABCDEF' for c in evidence):
            raise ValueError('evidence_sha256 must be 64 hex characters')
        row = {
            'version': 1, 'timestamp': _utcnow(), 'request_id': str(value['request_id'])[:128],
            'question_id': str(value['question_id']), 'signature': signature.lower(),
            'evidence_sha256': evidence.lower(), 'correct': value['correct'],
            'expected_key': None if value.get('expected_key') is None else str(value.get('expected_key')),
            'label_source': str(value.get('label_source') or 'external')[:128],
        }
        key = (row['request_id'], row['question_id'], row['signature'])
        prior = self._index.get(key)
        if prior is not None:
            if (prior.get('correct'), prior.get('expected_key')) != (row.get('correct'), row.get('expected_key')):
                raise ValueError('conflicting outcome already exists for request/question/signature')
            return dict(prior)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, (json.dumps(row, sort_keys=True, separators=(',', ':')) + '\n').encode())
            os.fsync(fd)
        finally:
            os.close(fd)
        self._index[key] = row
        return row


def _read_jsonl(path: str | Path) -> list[dict[str, Any]]:
    rows=[]
    for n,line in enumerate(Path(path).read_text().splitlines(),1):
        if not line.strip(): continue
        try: row=json.loads(line)
        except Exception as exc: raise ValueError(f'{path} line {n} invalid JSON') from exc
        rows.append(row)
    return rows


def _split(example_id: str) -> str:
    bucket = int(hashlib.sha256(example_id.encode()).hexdigest()[:8],16) % 100
    if bucket < 70: return 'train'
    if bucket < 82: return 'validation'
    if bucket < 94: return 'qualification'
    return 'audit_holdout'


def create_dataset_snapshot(*, promotion_journal: str | Path, outcomes: str | Path, output_dir: str | Path) -> dict[str, Any]:
    target=Path(output_dir)
    if target.exists() and any(target.iterdir()):
        raise ValueError('dataset snapshot destination must not already contain files')
    promotion_bytes=Path(promotion_journal).read_bytes(); outcome_bytes=Path(outcomes).read_bytes()
    promotions=_read_jsonl(promotion_journal); labels=_read_jsonl(outcomes)
    questions={(str(r.get('request_id')),str(r.get('question_id')),str(r.get('signature'))):r for r in promotions}
    examples=[]
    for label in labels:
        key=(str(label.get('request_id')),str(label.get('question_id')),str(label.get('signature')))
        source=questions.get(key)
        if source is None: continue
        example_id=hashlib.sha256(canonical_json({'request_id':key[0],'question_id':key[1],'signature':key[2]}).encode()).hexdigest()
        examples.append({
            'example_id': example_id, 'split': _split(example_id), 'task_signature': key[2],
            'question': source.get('question'), 'label': {
                'correct': bool(label.get('correct')), 'expected_key': label.get('expected_key'),
                'label_source': label.get('label_source'),
            },
            'decision': {'backend':source.get('backend'),'score':source.get('score'),'score_semantics':source.get('score_semantics')},
            'provenance': {'request_id':key[0],'question_id':key[1],'evidence_sha256':label.get('evidence_sha256')},
        })
    examples.sort(key=lambda x:x['example_id'])
    target.mkdir(parents=True,exist_ok=True)
    data=''.join(json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=False)+'\n' for x in examples).encode()
    (target/'examples.jsonl').write_bytes(data)
    digest='sha256:'+hashlib.sha256(data).hexdigest()
    counts={s:sum(1 for x in examples if x['split']==s) for s in ('train','validation','qualification','audit_holdout')}
    manifest={'version':1,'created_at':_utcnow(),'examples':len(examples),'splits':counts,'examples_sha256':digest,
              'source_sha256':{'promotion_journal':'sha256:'+hashlib.sha256(promotion_bytes).hexdigest(),'outcomes':'sha256:'+hashlib.sha256(outcome_bytes).hexdigest()},
              'policy':'deterministic sha256 partition: 70/12/12/6; qualification and audit_holdout must never be used for training'}
    mdata=(json.dumps(manifest,indent=2,sort_keys=True)+'\n').encode(); (target/'manifest.json').write_bytes(mdata)
    # Read-only files discourage accidental in-place mutation; new snapshots should get a new directory.
    try:
        os.chmod(target/'examples.jsonl',0o444); os.chmod(target/'manifest.json',0o444)
    except OSError: pass
    return manifest
