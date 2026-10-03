from __future__ import annotations
import argparse,asyncio,json
from pathlib import Path
from .independent_qualification import load_cases,evaluate,build_payload,sign_payload,verify,digest
from .promotion import QualificationPolicy

def main(argv=None):
    p=argparse.ArgumentParser(description='Independent held-out qualification with Ed25519 evaluator signature')
    s=p.add_subparsers(dest='cmd',required=True)
    q=s.add_parser('run'); q.add_argument('cases'); q.add_argument('--url',required=True); q.add_argument('--model',required=True); q.add_argument('--task-id',required=True); q.add_argument('--evaluator-id',required=True); q.add_argument('--private-key',required=True); q.add_argument('--api-key'); q.add_argument('--output',required=True); q.add_argument('--min-samples',type=int,default=100); q.add_argument('--min-accuracy',type=float,default=.95); q.add_argument('--max-ece',type=float,default=.08); q.add_argument('--max-brier',type=float,default=.10); q.add_argument('--max-wilson-error-upper',type=float,default=.10); q.add_argument('--operating-threshold',type=float,default=.80)
    v=s.add_parser('verify'); v.add_argument('artifact'); v.add_argument('--public-key',required=True)
    a=p.parse_args(argv)
    if a.cmd=='verify':
        raw=json.loads(Path(a.artifact).read_text()); payload=verify(raw,a.public_key); print(json.dumps(payload,indent=2,sort_keys=True)); print(f'independent_qualification_digest={digest(raw)}'); return
    cases,case_digest=load_cases(a.cases); records,manifest=asyncio.run(evaluate(a.url,a.model,cases,api_key=a.api_key)); policy=QualificationPolicy(min_samples=a.min_samples,min_accuracy=a.min_accuracy,max_ece=a.max_ece,max_brier=a.max_brier,max_wilson_error_upper=a.max_wilson_error_upper,operating_threshold=a.operating_threshold); payload=build_payload(cases=cases,case_digest=case_digest,records=records,manifest=manifest,task_id=a.task_id,evaluator_id=a.evaluator_id,policy=policy); out=sign_payload(payload,a.private_key); Path(a.output).write_text(json.dumps(out,indent=2,sort_keys=True)+'\n'); print(f'qualified={str(payload["qualified"]).lower()}'); print(f'independent_qualification_digest={digest(out)}');
    if not payload['qualified']: raise SystemExit(2)
if __name__=='__main__': main()
