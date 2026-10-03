"""Record exact qualified checkout identity before release packaging."""

from __future__ import annotations

import json
import platform
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.verify_release import ROOT, verify_prebuild


def main() -> int:
    commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
    ).strip()
    verify_prebuild(commit)
    identity = json.loads((ROOT / "IDENTITY_MANIFEST.json").read_text(encoding="utf-8"))
    provenance = {
        "schema_version": 1,
        "source_commit": commit,
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "build_command": "python -m build --sdist --wheel",
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
