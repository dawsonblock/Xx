from __future__ import annotations
import json,os,time
from pathlib import Path
from typing import Any,Mapping

class TelemetrySink:
    """Privacy-minimized OTel-style JSONL spans. No prompt/state content is emitted."""
    def __init__(self,path:str|None): self.path=Path(path) if path else None
    def emit_request(self,*,request_id:str,duration_ms:float,trace:Mapping[str,Any])->None:
        if self.path is None: return
        decisions=trace.get('decisions') if isinstance(trace.get('decisions'),Mapping) else {}
        row={'version':1,'name':'localjev.systemone','trace_id':request_id,'timestamp_unix_ns':time.time_ns(),'duration_ms':round(float(duration_ms),3),'attributes':{'jev.request_sha256':trace.get('request_sha256'),'jev.plan_sha256':trace.get('plan_sha256'),'jev.evidence_sha256':trace.get('evidence_sha256'),'jev.direct_authorized':bool(trace.get('direct_authorized')),'jev.question_count':len(decisions),'jev.backends':sorted({str(x.get('backend')) for x in decisions.values() if isinstance(x,Mapping) and x.get('backend')}),'jev.escalations':sum(1 for a in trace.get('attempts',[]) if isinstance(a,Mapping) and a.get('status')=='escalated')}}
        self.path.parent.mkdir(parents=True,exist_ok=True); fd=os.open(self.path,os.O_WRONLY|os.O_CREAT|os.O_APPEND,0o600)
        try: os.write(fd,(json.dumps(row,sort_keys=True,separators=(',',':'))+'\n').encode()); os.fsync(fd)
        finally: os.close(fd)
