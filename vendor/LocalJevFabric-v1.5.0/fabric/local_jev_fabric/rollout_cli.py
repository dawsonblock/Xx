from __future__ import annotations

import argparse
import json
import os
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .registry import TaskRegistry, atomic_write_json
from .shadow import load_shadow_rows


def _now(): return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00','Z')

def _load_registry(args):
    key=os.environ.get(args.registry_hmac_key_env)
    if not key: raise SystemExit(f'{args.registry_hmac_key_env} must contain the registry HMAC key')
    reg=TaskRegistry.load(args.registry,hmac_key=key,require_hmac=True)
    return reg,key

def _commit(args,reg,key):
    reg.revision += 1; reg.updated_at=_now(); reg.integrity_verified=False
    atomic_write_json(args.registry,reg.to_dict(hmac_key=key))
    print(f'new_revision={reg.revision}'); print(f'registry_sha256={reg.digest}')

def _binding(reg,sig):
    b=reg.routes.get(sig)
    if b is None: raise SystemExit('signature is not registered')
    return b

def cmd_shadow(args):
    reg,key=_load_registry(args); b=_binding(reg,args.signature)
    if b.direct_authorized: raise SystemExit('remove direct authority before shadow rollout')
    reg.routes[args.signature]=replace(b,deployment_stage='shadow',baseline_backend=args.baseline_backend,canary_percent=0.0,direct_authorized=False)
    _commit(args,reg,key)

def cmd_canary(args):
    reg,key=_load_registry(args); b=_binding(reg,args.signature)
    if b.direct_authorized: raise SystemExit('remove direct authority before canary rollout')
    reg.routes[args.signature]=replace(b,deployment_stage='canary',baseline_backend=args.baseline_backend,canary_percent=float(args.percent),direct_authorized=False)
    _commit(args,reg,key)

def cmd_stable(args):
    reg,key=_load_registry(args); b=_binding(reg,args.signature)
    reg.routes[args.signature]=replace(b,deployment_stage='stable',baseline_backend=None,canary_percent=0.0)
    _commit(args,reg,key)

def _load_outcomes(path):
    out={}
    for n,line in enumerate(Path(path).read_text().splitlines(),1):
        if not line.strip(): continue
        try:r=json.loads(line)
        except Exception as exc: raise SystemExit(f'outcome line {n}: {exc}')
        out[(str(r.get('request_id')),str(r.get('question_id')),str(r.get('signature')))]=r
    return out

def cmd_evaluate(args):
    reg,key=_load_registry(args); b=_binding(reg,args.signature)
    if b.deployment_stage!='canary': raise SystemExit('evaluate requires a canary binding')
    rows=[r for r in load_shadow_rows(args.shadow_journal) if r.get('signature')==args.signature]
    outcomes=_load_outcomes(args.outcomes); cand=base=used=0
    for r in rows:
        label=outcomes.get((str(r.get('request_id')),str(r.get('question_id')),str(r.get('signature'))))
        expected=None if label is None else label.get('expected_key')
        if expected is None: continue
        candidate_key = r.get('production_key') if r.get('production_backend')==b.backend else r.get('shadow_key') if r.get('shadow_backend')==b.backend else None
        baseline_key = r.get('production_key') if r.get('production_backend')==b.baseline_backend else r.get('shadow_key') if r.get('shadow_backend')==b.baseline_backend else None
        if candidate_key is None or baseline_key is None: continue
        used+=1; cand += int(str(candidate_key)!=str(expected)); base += int(str(baseline_key)!=str(expected))
    candidate_error=cand/used if used else 1.0; baseline_error=base/used if used else 1.0; delta=candidate_error-baseline_error
    verdict='insufficient' if used<args.min_samples else ('rollback' if delta>args.max_error_delta else 'pass')
    print(json.dumps({'samples':used,'candidate_errors':cand,'baseline_errors':base,'candidate_error_rate':candidate_error,'baseline_error_rate':baseline_error,'error_delta':delta,'verdict':verdict},indent=2))
    if verdict=='rollback' and args.rollback:
        # Safe rollback is a new signed higher revision. Specialist evidence is deliberately stripped
        # because the baseline has not been qualified as that specialist artifact.
        reg.routes[args.signature]=replace(b,backend=str(b.baseline_backend),backend_model=None,artifact_digest=None,backend_fingerprint=None,calibration_digest=None,qualification_digest=None,promotion_id=None,min_score=None,fallback_policy='generalist',direct_authorized=False,deployment_stage='stable',baseline_backend=None,canary_percent=0.0,note='Automatic canary rollback to baseline')
        _commit(args,reg,key)
    if verdict=='rollback': raise SystemExit(2)
    if verdict=='insufficient': raise SystemExit(3)

def main(argv=None):
    p=argparse.ArgumentParser(description='Shadow/canary rollout controller')
    p.add_argument('--registry',required=True); p.add_argument('--registry-hmac-key-env',default='FABRIC_REGISTRY_HMAC_KEY')
    sub=p.add_subparsers(dest='cmd',required=True)
    s=sub.add_parser('shadow'); s.add_argument('signature'); s.add_argument('--baseline-backend',required=True); s.set_defaults(func=cmd_shadow)
    c=sub.add_parser('canary'); c.add_argument('signature'); c.add_argument('--baseline-backend',required=True); c.add_argument('--percent',type=float,required=True); c.set_defaults(func=cmd_canary)
    st=sub.add_parser('stable'); st.add_argument('signature'); st.set_defaults(func=cmd_stable)
    e=sub.add_parser('evaluate'); e.add_argument('signature'); e.add_argument('--shadow-journal',required=True); e.add_argument('--outcomes',required=True); e.add_argument('--min-samples',type=int,default=50); e.add_argument('--max-error-delta',type=float,default=0.01); e.add_argument('--rollback',action='store_true'); e.set_defaults(func=cmd_evaluate)
    a=p.parse_args(argv); a.func(a)
if __name__=='__main__': main()
