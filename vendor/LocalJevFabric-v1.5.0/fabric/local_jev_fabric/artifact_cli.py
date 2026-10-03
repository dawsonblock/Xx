from __future__ import annotations
import argparse,json
from pathlib import Path
from .artifact_signing import generate_keypair,create_attestation,verify_attestation,attestation_digest

def main(argv=None):
    p=argparse.ArgumentParser(description='Ed25519 artifact supply-chain attestations')
    s=p.add_subparsers(dest='cmd',required=True)
    k=s.add_parser('keygen'); k.add_argument('private_key'); k.add_argument('public_key')
    a=s.add_parser('sign-digest'); a.add_argument('digest'); a.add_argument('--kind',required=True); a.add_argument('--private-key',required=True); a.add_argument('--output',required=True); a.add_argument('--metadata-json')
    v=s.add_parser('verify'); v.add_argument('attestation'); v.add_argument('--public-key',required=True); v.add_argument('--kind')
    x=p.parse_args(argv)
    if x.cmd=='keygen':
        kid,pub=generate_keypair(x.private_key,x.public_key); print(f'key_id={kid}'); print(f'public_key_sha256={pub}'); return
    if x.cmd=='sign-digest':
        meta=json.loads(Path(x.metadata_json).read_text()) if x.metadata_json else {}
        out=create_attestation(digest=x.digest,kind=x.kind,private_key_path=x.private_key,metadata=meta)
        Path(x.output).write_text(json.dumps(out,indent=2,sort_keys=True)+'\n'); print(f'attestation_digest={attestation_digest(out)}'); return
    val=json.loads(Path(x.attestation).read_text()); out=verify_attestation(val,x.public_key,expected_kind=x.kind); print(json.dumps(out,indent=2,sort_keys=True)); print(f'attestation_digest={attestation_digest(val)}')
if __name__=='__main__': main()
