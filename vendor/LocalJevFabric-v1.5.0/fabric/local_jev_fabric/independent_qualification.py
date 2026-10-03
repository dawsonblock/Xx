from __future__ import annotations

import base64, hashlib, json, statistics
from pathlib import Path
from typing import Any, Mapping
import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey,Ed25519PublicKey

from .promotion import QualificationPolicy, expected_calibration_error, wilson_upper_error
from .registry import canonical_json, question_signature
from .shadow import answer_key
from .router import answer_concentration

VERSION=1

def _sha(data:bytes)->str: return 'sha256:'+hashlib.sha256(data).hexdigest()
def _load_private(path):
    k=serialization.load_pem_private_key(Path(path).read_bytes(),password=None)
    if not isinstance(k,Ed25519PrivateKey): raise ValueError('evaluator key is not Ed25519')
    return k
def _load_public(path):
    k=serialization.load_pem_public_key(Path(path).read_bytes())
    if not isinstance(k,Ed25519PublicKey): raise ValueError('evaluator public key is not Ed25519')
    return k
def _kid(k): return _sha(k.public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw))

def load_cases(path: str|Path)->tuple[list[dict[str,Any]],str]:
    raw=Path(path).read_bytes(); rows=[]
    for n,line in enumerate(raw.decode().splitlines(),1):
        if not line.strip(): continue
        obj=json.loads(line)
        if not isinstance(obj,dict) or not isinstance(obj.get('question'),Mapping) or 'expected_key' not in obj or 'state' not in obj:
            raise ValueError(f'case line {n} requires state, question and expected_key')
        rows.append(obj)
    if not rows: raise ValueError('independent qualification set is empty')
    sigs={question_signature(r['question']) for r in rows}
    if len(sigs)!=1: raise ValueError('independent qualification set must contain one exact task signature')
    return rows,_sha(raw)

async def evaluate(url:str, model:str, cases:list[dict[str,Any]], *, api_key:str|None=None, timeout_s:float=10.0)->tuple[list[tuple[float,bool]],dict[str,Any]]:
    headers={'authorization':f'Bearer {api_key}'} if api_key else {}
    root=url.rstrip('/')
    async with httpx.AsyncClient(timeout=timeout_s) as client:
        m=await client.get(root+'/v1/fabric/manifest',headers=headers); m.raise_for_status(); manifest=m.json()
        records=[]
        for i,case in enumerate(cases):
            r=await client.post(root+'/v1/systemone',headers=headers,json={'state':case['state'],'model':model,'questions':{'q':case['question']}}); r.raise_for_status(); body=r.json()
            ans=(body.get('answers') or {}).get('q')
            if not isinstance(ans,Mapping): raise ValueError(f'case {i} backend omitted answer')
            key=answer_key(case['question'],ans); score=answer_concentration(ans)
            records.append((score,key==str(case['expected_key'])))
    return records,manifest

def build_payload(*,cases:list[dict[str,Any]],case_digest:str,records:list[tuple[float,bool]],manifest:Mapping[str,Any],task_id:str,evaluator_id:str,policy:QualificationPolicy)->dict[str,Any]:
    n=len(records); correct=sum(1 for _,ok in records if ok); errors=n-correct
    accuracy=correct/n; brier=statistics.fmean((c-(1.0 if ok else 0.0))**2 for c,ok in records); ece=expected_calibration_error(records); upper=wilson_upper_error(errors,n)
    metrics={'samples':n,'accuracy':accuracy,'error_rate':errors/n,'ece_10bin':ece,'brier':brier,'wilson_error_upper_95':upper}
    gates={'samples':n>=policy.min_samples,'accuracy':accuracy>=policy.min_accuracy,'ece':ece<=policy.max_ece,'brier':brier<=policy.max_brier,'wilson_error_upper':upper<=policy.max_wilson_error_upper}
    return {'version':VERSION,'kind':'independent-qualification','task_id':task_id,'question_signature':question_signature(cases[0]['question']),'evaluation_set_digest':case_digest,'evaluator_id':evaluator_id,
            'backend_model':manifest.get('served_model'),'artifact_digest':'sha256:'+str(manifest.get('artifact_bundle_sha256') or ''),'backend_fingerprint':'sha256:'+str(manifest.get('backend_fingerprint_sha256') or ''),'calibration_digest':'sha256:'+str(manifest.get('calibration_evidence_sha256') or ''),
            'metrics':metrics,'gates':gates,'qualified':all(gates.values()),'policy':vars(policy)}

def sign_payload(payload:Mapping[str,Any],private_key_path:str|Path)->dict[str,Any]:
    private=_load_private(private_key_path); public=private.public_key(); value={**dict(payload),'evaluator_key_id':_kid(public)}; sig=private.sign(canonical_json(value).encode()); return {**value,'signature':{'algorithm':'ed25519','value':base64.b64encode(sig).decode()}}

def verify(value:Mapping[str,Any],public_key_path:str|Path,*,require_qualified=True)->dict[str,Any]:
    if int(value.get('version',0))!=VERSION or value.get('kind')!='independent-qualification': raise ValueError('unsupported independent qualification artifact')
    payload={k:v for k,v in value.items() if k!='signature'}; public=_load_public(public_key_path)
    if payload.get('evaluator_key_id')!=_kid(public): raise ValueError('independent qualification evaluator key mismatch')
    sig=value.get('signature')
    if not isinstance(sig,Mapping) or sig.get('algorithm')!='ed25519': raise ValueError('independent qualification lacks Ed25519 signature')
    try: public.verify(base64.b64decode(str(sig.get('value') or '')),canonical_json(payload).encode())
    except Exception as exc: raise ValueError('independent qualification signature verification failed') from exc
    if require_qualified and payload.get('qualified') is not True: raise ValueError('independent qualification did not pass policy gates')
    return payload

def digest(value:Mapping[str,Any])->str: return _sha(canonical_json(value).encode())
