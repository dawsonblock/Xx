"""Reject stale active release versions in known authority files."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def check(root: Path = ROOT) -> None:
    version = (root / "VERSION").read_text().strip()
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise ValueError("invalid VERSION")
    setup = (root / "setup.py").read_text()
    makefile = (root / "Makefile").read_text()
    config = (root / "aide/utils/config.yaml").read_text()
    if not re.search(r'version=Path\(["\']VERSION["\']\)\.read_text', setup):
        raise ValueError("package version is not derived from VERSION")
    if "SANDBOX_IMAGE = aideml-rsi-sandbox:$(VERSION)" not in makefile:
        raise ValueError("sandbox image tag is not derived from VERSION")
    if "VERSION := $(shell cat VERSION)" not in makefile:
        raise ValueError("Makefile does not read VERSION")
    for name, content in (("Makefile", makefile), ("config.yaml", config)):
        for stale in re.findall(r"aideml-rsi-sandbox:(\d+\.\d+\.\d+)", content):
            if stale != version:
                raise ValueError(f"stale sandbox version in {name}: {stale}")


if __name__ == "__main__":
    check()
    print("active package and sandbox versions derive from VERSION")
