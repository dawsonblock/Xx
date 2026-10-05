"""Build a deterministic source ZIP only from a current manifest identity."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GENERATED = (
    "BUILD_MANIFEST.json",
    "IDENTITY_MANIFEST.json",
    "RELEASE_FREEZE_MANIFEST.json",
    "SOURCE_TREE_MANIFEST.json",
    "TCB_MANIFEST.json",
)


def build(output: Path) -> None:
    subprocess.run(
        [sys.executable, str(ROOT / "tools/generate_release_manifests.py"), "--check"],
        cwd=ROOT,
        check=True,
    )
    source = json.loads((ROOT / "SOURCE_TREE_MANIFEST.json").read_text())
    paths = set(source["files"]) | {
        name for name in GENERATED if (ROOT / name).is_file()
    }
    paths = sorted(paths)
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for relative in paths:
            info = zipfile.ZipInfo(relative, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, (ROOT / relative).read_bytes())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    build(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
