"""Record exact qualified checkout identity before release packaging."""

from __future__ import annotations

import json
import platform
import subprocess
import sys
import hashlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.verify_release import ROOT, verify_prebuild


def main() -> int:
    commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
    ).strip()
    verify_prebuild(commit)
    identity = json.loads((ROOT / "IDENTITY_MANIFEST.json").read_text(encoding="utf-8"))
    ledger_hash = hashlib.sha256(
        (ROOT / "SOURCE_QUALIFICATION_LEDGER.json").read_bytes()
    ).hexdigest()
    provenance = {
        "schema_version": 1,
        "source_commit": commit,
        "source_qualification_ledger_sha256": ledger_hash,
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "build_runner_id": "python-build-sdist-wheel-v1",
        **{
            key: value
            for key, value in identity.items()
            if key.endswith("_sha256") or key == "docker_base_image_digest"
        },
    }
    (ROOT / "BUILD_PROVENANCE.json").write_text(
        json.dumps(provenance, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
