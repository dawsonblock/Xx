from __future__ import annotations

import asyncio
import json
import math
import statistics
import time
from collections import Counter
from pathlib import Path
from typing import Any, Mapping

import httpx


def _percentile(values: list[float], p: float) -> float:
    if not values: return 0.0
    xs=sorted(values); k=(len(xs)-1)*p; lo=math.floor(k); hi=math.ceil(k)
    if lo==hi: return xs[lo]
    return xs[lo]*(hi-k)+xs[hi]*(k-lo)


def expected_key(question: Mapping[str, Any], answer: Mapping[str, Any]) -> str:
    typ=question.get('type')
    if typ=='noul': return 'yes' if float(answer.get('noul',0.0))>=0.5 else 'no'
    if typ=='choice': return str(answer.get('choice'))
    if typ=='score': return f"{float(answer.get('score')):.12g}"
    return json.dumps(answer,sort_keys=True,separators=(',',':'))


def score_case(case: Mapping[str, Any], response: Mapping[str, Any]) -> tuple[int,int,bool]:
    questions=case.get('questions') or {}; expected=case.get('expected') or {}; answers=response.get('answers') or {}
    correct=total=0
    for qid,want in expected.items():
        if qid not in questions: continue
        total+=1; got=answers.get(qid)
        if not isinstance(got,Mapping): continue
        got_key=expected_key(questions[qid],got)
        if isinstance(want,Mapping): want_key=str(want.get('key'))
        else: want_key=str(want)
        if got_key==want_key: correct+=1
    direct=bool((response.get('fabric') or {}).get('direct_authorized'))
    return correct,total,direct


async def run_benchmark(cases: list[Mapping[str, Any]], *, url: str, api_key: str | None=None,
                        concurrency: int=8, timeout_s: float=30.0) -> dict[str, Any]:
    sem=asyncio.Semaphore(max(1,int(concurrency))); latencies=[]; failures=[]; backends=Counter();
    question_correct=question_total=request_correct=request_total=false_direct=direct_count=0
    headers={'authorization':f'Bearer {api_key}'} if api_key else {}
    async with httpx.AsyncClient(timeout=timeout_s) as client:
        async def one(i,case):
            async with sem:
                started=time.perf_counter()
                try:
                    r=await client.post(url.rstrip('/')+'/v1/systemone',json={k:v for k,v in case.items() if k in {'state','model','questions'}},headers=headers)
                    r.raise_for_status(); body=r.json(); latency=(time.perf_counter()-started)*1000
                    return i,body,latency,None
                except Exception as exc:
                    return i,None,(time.perf_counter()-started)*1000,str(exc)
        results=await asyncio.gather(*(one(i,c) for i,c in enumerate(cases)))
    for i,body,latency,error in results:
        latencies.append(latency); case=cases[i]
        if error:
            failures.append({'case':i,'error':error}); continue
        c,t,d=score_case(case,body); question_correct+=c; question_total+=t; request_total+=1; request_correct+=int(t>0 and c==t)
        if d: direct_count+=1
        if d and case.get('allow_direct') is False: false_direct+=1
        for m in ((body.get('fabric') or {}).get('decisions') or {}).values():
            if isinstance(m,Mapping) and m.get('backend'): backends[str(m['backend'])]+=1
    return {
        'version':1,'cases':len(cases),'completed':len(cases)-len(failures),'failures':failures,
        'question_accuracy':(question_correct/question_total if question_total else None),
        'request_accuracy':(request_correct/request_total if request_total else None),
        'question_correct':question_correct,'question_total':question_total,
        'direct_authorized':direct_count,'false_direct_authorized':false_direct,
        'false_direct_rate':(false_direct/direct_count if direct_count else 0.0),
        'latency_ms':{'p50':_percentile(latencies,.50),'p95':_percentile(latencies,.95),'p99':_percentile(latencies,.99),'mean':statistics.fmean(latencies) if latencies else 0.0},
        'backend_decisions':dict(backends),
    }


def load_cases(path: str | Path) -> list[dict[str, Any]]:
    rows=[]
    for n,line in enumerate(Path(path).read_text().splitlines(),1):
        if not line.strip(): continue
        try: row=json.loads(line)
        except Exception as exc: raise ValueError(f'benchmark line {n} invalid JSON') from exc
        if not isinstance(row,dict) or not isinstance(row.get('questions'),dict) or not isinstance(row.get('expected'),dict):
            raise ValueError(f'benchmark line {n} requires questions and expected objects')
        rows.append(row)
    if not rows: raise ValueError('benchmark set is empty')
    return rows
