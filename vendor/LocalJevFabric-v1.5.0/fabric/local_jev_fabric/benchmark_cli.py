from __future__ import annotations
import argparse, asyncio, json, os
from pathlib import Path
from .benchmark import load_cases, run_benchmark

def main(argv=None):
    p=argparse.ArgumentParser(description='End-to-end LocalJevFabric qualification benchmark')
    p.add_argument('cases'); p.add_argument('--url',default='http://127.0.0.1:8090'); p.add_argument('--api-key-env',default='FABRIC_API_KEY')
    p.add_argument('--concurrency',type=int,default=8); p.add_argument('--timeout',type=float,default=30.0); p.add_argument('--output')
    p.add_argument('--min-question-accuracy',type=float); p.add_argument('--max-false-direct-rate',type=float,default=0.0)
    a=p.parse_args(argv); result=asyncio.run(run_benchmark(load_cases(a.cases),url=a.url,api_key=os.environ.get(a.api_key_env),concurrency=a.concurrency,timeout_s=a.timeout))
    text=json.dumps(result,indent=2,sort_keys=True); print(text)
    if a.output: Path(a.output).write_text(text+'\n')
    if a.min_question_accuracy is not None and (result['question_accuracy'] is None or result['question_accuracy'] < a.min_question_accuracy): raise SystemExit(2)
    if result['false_direct_rate'] > a.max_false_direct_rate: raise SystemExit(3)
if __name__=='__main__': main()
