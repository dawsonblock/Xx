from __future__ import annotations

import argparse
import os

from .audit import AuditLog


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(description="Verify a LocalJevFabric tamper-evident JSONL audit chain")
    p.add_argument("audit_log")
    p.add_argument("--checkpoint", help="optional HMAC-sealed audit head checkpoint")
    p.add_argument("--hmac-key-env", default="FABRIC_AUDIT_HMAC_KEY")
    args = p.parse_args(argv)
    key = os.environ.get(args.hmac_key_env) if args.checkpoint else None
    if args.checkpoint and not key:
        p.error(f"{args.hmac_key_env} is required with --checkpoint")
    ok, count, error = AuditLog.verify(args.audit_log, checkpoint_path=args.checkpoint, hmac_key=key)
    if not ok:
        raise SystemExit(f"FAILED after {count} records: {error}")
    print(f"OK: {count} records")
    if args.checkpoint:
        print("checkpoint_verified=true")


if __name__ == "__main__":
    main()
