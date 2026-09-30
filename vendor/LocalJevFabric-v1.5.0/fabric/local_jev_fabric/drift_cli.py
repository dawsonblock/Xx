from __future__ import annotations
import argparse, json
from pathlib import Path
from .drift import build_profiles

def main(argv=None):
    p=argparse.ArgumentParser(description='Build drift reference profiles from decision JSONL')
    p.add_argument('input'); p.add_argument('output'); a=p.parse_args(argv)
    rows=[]
    for n,line in enumerate(Path(a.input).read_text().splitlines(),1):
        if line.strip():
            try: rows.append(json.loads(line))
            except Exception as exc: raise SystemExit(f'line {n}: invalid JSON: {exc}')
    profile=build_profiles(rows); Path(a.output).write_text(json.dumps(profile,indent=2,sort_keys=True)+'\n'); print(f"profiles={len(profile['profiles'])}")
if __name__=='__main__': main()
