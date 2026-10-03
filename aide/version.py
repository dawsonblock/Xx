"""Installed package version with a source-checkout fallback."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version
from pathlib import Path


def package_version() -> str:
    source_version = Path(__file__).resolve().parents[1] / "VERSION"
    if source_version.is_file():
        return source_version.read_text(encoding="utf-8").strip()
    try:
        return version("aideml-rsi")
    except PackageNotFoundError:
        raise RuntimeError("AIDE-RSI version metadata is unavailable") from None
