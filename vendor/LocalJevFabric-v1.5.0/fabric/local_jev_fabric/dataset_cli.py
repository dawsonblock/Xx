from __future__ import annotations
import argparse, json
from .outcomes import create_dataset_snapshot

def main(argv=None):
    p=argparse.ArgumentParser(description='Create immutable LocalJevFabric decision dataset snapshots')
    sub=p.add_subparsers(dest='cmd',required=True); s=sub.add_parser('snapshot')
    s.add_argument('--promotion-journal',required=True); s.add_argument('--outcomes',required=True); s.add_argument('--output',required=True)
    a=p.parse_args(argv); print(json.dumps(create_dataset_snapshot(promotion_journal=a.promotion_journal,outcomes=a.outcomes,output_dir=a.output),indent=2))
if __name__=='__main__': main()
