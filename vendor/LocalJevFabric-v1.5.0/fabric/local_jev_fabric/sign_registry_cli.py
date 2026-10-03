from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from .registry import TaskRegistry, atomic_write_json


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(description="Authenticate a LocalJevFabric v2 registry with HMAC-SHA256")
    p.add_argument("registry")
    p.add_argument("--hmac-key-env", default="FABRIC_REGISTRY_HMAC_KEY")
    args = p.parse_args(argv)
    key = os.environ.get(args.hmac_key_env)
    if not key:
        p.error(f"{args.hmac_key_env} is empty/missing")
    path = Path(args.registry)
    if not path.exists():
        p.error("registry does not exist")
    # Existing signed registries are verified with the supplied key before re-signing.
    reg = TaskRegistry.load(str(path), hmac_key=key)
    atomic_write_json(path, reg.to_dict(hmac_key=key))
    checked = TaskRegistry.load(str(path), hmac_key=key, require_hmac=True)
    print(f"registry_sha256={checked.digest}")
    print("hmac_verified=true")


if __name__ == "__main__":
    main()
