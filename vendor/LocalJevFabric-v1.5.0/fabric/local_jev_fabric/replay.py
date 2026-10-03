from __future__ import annotations
import hashlib,json,os,zipfile
from pathlib import Path
from typing import Any,Mapping
from .registry import canonical_json

class ReplayStore:
    """Sanitized replay index. It stores question schemas and hashes state, never raw state."""
    def __init__(self,path:str|None): self.path=Path(path) if path else None
    def append(self,*,request_id:str,request:Mapping[str,Any],response:Mapping[str,Any],trace:Mapping[str,Any],registry_payload:Mapping[str,Any])->dict[str,Any]|None:
        if self.path is None: return None
        questions=request.get('questions') if isinstance(request.get('questions'),Mapping) else {}
        state_hash=hashlib.sha256(canonical_json(request.get('state')).encode()).hexdigest()
        row={'version':1,'request_id':request_id,'model':request.get('model'),'state_sha256':state_hash,'questions':questions,'answers':response.get('answers'),'request_sha256':trace.get('request_sha256'),'plan_sha256':trace.get('plan_sha256'),'evidence_sha256':trace.get('evidence_sha256'),'direct_authorized':bool(trace.get('direct_authorized')),'decisions':trace.get('decisions'),'registry_revision':registry_payload.get('revision'),'registry_sha256':hashlib.sha256(canonical_json(registry_payload).encode()).hexdigest()}
        row['record_sha256']=hashlib.sha256(canonical_json(row).encode()).hexdigest()
        self.path.parent.mkdir(parents=True,exist_ok=True); fd=os.open(self.path,os.O_WRONLY|os.O_CREAT|os.O_APPEND,0o600)
        try: os.write(fd,(json.dumps(row,sort_keys=True,separators=(',',':'))+'\n').encode()); os.fsync(fd)
        finally: os.close(fd)
        return row
    def get(self,request_id:str)->dict[str,Any]|None:
        if self.path is None or not self.path.exists(): return None
        found=None
        for line in self.path.read_text().splitlines():
            if not line.strip(): continue
            row=json.loads(line)
            if row.get('request_id')==request_id: found=row
        return found

def verify_record(row:Mapping[str,Any],*,state:Any|None=None)->dict[str,Any]:
    base={k:v for k,v in row.items() if k!='record_sha256'}; actual=hashlib.sha256(canonical_json(base).encode()).hexdigest(); ok=actual==row.get('record_sha256')
    state_ok=None
    if state is not None: state_ok=hashlib.sha256(canonical_json(state).encode()).hexdigest()==row.get('state_sha256')
    return {'record_integrity':ok,'state_matches':state_ok,'request_id':row.get('request_id'),'evidence_sha256':row.get('evidence_sha256')}

def incident_bundle(*,row:Mapping[str,Any],output:str|Path,registry_path:str|None=None,manifest:Mapping[str,Any]|None=None)->str:
    target=Path(output); target.parent.mkdir(parents=True,exist_ok=True)
    with zipfile.ZipFile(target,'w',compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr('replay.json',json.dumps(row,indent=2,sort_keys=True)+'\n')
        z.writestr('verification.json',json.dumps(verify_record(row),indent=2,sort_keys=True)+'\n')
        if registry_path and Path(registry_path).exists(): z.write(registry_path,'registry.json')
        if manifest is not None: z.writestr('fabric-manifest.json',json.dumps(manifest,indent=2,sort_keys=True)+'\n')
    return 'sha256:'+hashlib.sha256(target.read_bytes()).hexdigest()
