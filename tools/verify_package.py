"""Verify required runtime components are present in wheel and sdist archives."""

from __future__ import annotations

import argparse
import tarfile
import zipfile
from pathlib import Path

_WHEEL_MEMBERS = {
    "aide/rsi/statistics.py",
    "aide/rsi/runner.py",
    "aide/utils/config.yaml",
    "tools/qualify_canary_statistics.py",
    "tools/generate_release_manifests.py",
    "tools/verify_package.py",
    "rsi_anchor_service.py",
}
_SDIST_MEMBERS = {
    "aide/rsi/statistics.py",
    "aide/rsi/runner.py",
    "tools/qualify_canary_statistics.py",
    "tools/generate_release_manifests.py",
    "tools/verify_package.py",
    "rsi_anchor_service.py",
    "MANIFEST.in",
}


def _check_wheel(path: Path) -> None:
    with zipfile.ZipFile(path) as archive:
        members = set(archive.namelist())
    missing = _WHEEL_MEMBERS - members
    for filename in (
        "TCB_MANIFEST.json",
        "RELEASE_FREEZE_MANIFEST.json",
        "SOURCE_TREE_MANIFEST.json",
        "requirements-rsi-ci.in",
        "requirements-rsi-ci.lock",
    ):
        if not any(
            name.endswith(f".data/data/share/aideml-rsi/{filename}") for name in members
        ):
            missing.add(f"share/aideml-rsi/{filename}")
    vendor_marker = "LocalJevFabric-v1.5.0/BUILD_MANIFEST.json"
    if not any(vendor_marker in name for name in members):
        missing.add(f"bundled/{vendor_marker}")
    if missing:
        raise ValueError(
            "wheel is missing required runtime members: " + ", ".join(sorted(missing))
        )


def _check_sdist(path: Path) -> None:
    with tarfile.open(path, "r:gz") as archive:
        members = {member.name for member in archive.getmembers() if member.isfile()}
    missing = {
        relative
        for relative in _SDIST_MEMBERS
        if not any(name.endswith("/" + relative) for name in members)
    }
    for filename in (
        "TCB_MANIFEST.json",
        "RELEASE_FREEZE_MANIFEST.json",
        "SOURCE_TREE_MANIFEST.json",
        "requirements-rsi-ci.in",
        "requirements-rsi-ci.lock",
    ):
        if not any(name.endswith("/" + filename) for name in members):
            missing.add(filename)
    vendor_marker = "LocalJevFabric-v1.5.0/BUILD_MANIFEST.json"
    if not any(vendor_marker in name for name in members):
        missing.add(vendor_marker)
    if missing:
        raise ValueError(
            "source distribution is missing required members: "
            + ", ".join(sorted(missing))
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel", required=True, type=Path)
    parser.add_argument("--sdist", required=True, type=Path)
    args = parser.parse_args(argv)
    _check_wheel(args.wheel)
    _check_sdist(args.sdist)
    print("wheel and source distribution contain all required runtime components")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
