from __future__ import annotations
import argparse,json
from pathlib import Path
from .replay import ReplayStore,verify_record,incident_bundle

def main(argv=None):
    p=argparse.ArgumentParser(description='Verify sanitized decision replay evidence and build incident bundles')
    s=p.add_subparsers(dest='cmd',required=True)
    v=s.add_parser('verify'); v.add_argument('store'); v.add_argument('request_id'); v.add_argument('--state-json')
    i=s.add_parser('incident'); i.add_argument('store'); i.add_argument('request_id'); i.add_argument('--output',required=True); i.add_argument('--registry'); i.add_argument('--manifest-json')
    a=p.parse_args(argv); row=ReplayStore(a.store).get(a.request_id)
    if row is None: raise SystemExit('request_id not found')
    if a.cmd=='verify':
        state=json.loads(Path(a.state_json).read_text()) if a.state_json else None; print(json.dumps(verify_record(row,state=state),indent=2,sort_keys=True)); return
    manifest=json.loads(Path(a.manifest_json).read_text()) if a.manifest_json else None; print(f'incident_bundle_sha256={incident_bundle(row=row,output=a.output,registry_path=a.registry,manifest=manifest)}')
if __name__=='__main__': main()
