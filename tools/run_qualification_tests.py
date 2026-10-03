"""Run the canonical test command and bind JUnit evidence to this source."""

from __future__ import annotations

import hashlib
import json
import platform
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools import generate_release_manifests as manifests


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def main() -> int:
    if sys.version_info[:2] != (3, 12):
        raise SystemExit("qualification requires Python 3.12")
    if manifests.main(["--check"]) != 0:
        raise SystemExit("current manifests are required before qualification")
    identity = manifests.build_manifests()["IDENTITY_MANIFEST.json"]
    tests = manifests._file_hashes(
        [
            path
            for path in manifests._source_paths()
            if path.startswith("tests/") and path.endswith(".py")
        ]
    )
    report = manifests.ROOT / "qualification/repair-1.3.6/pytest-junit.xml"
    envelope = report.with_name("pytest-evidence.json")
    report.parent.mkdir(parents=True, exist_ok=True)
    report.unlink(missing_ok=True)
    envelope.unlink(missing_ok=True)
    started = _now()
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "tests",
            f"--junitxml={report.relative_to(manifests.ROOT)}",
        ],
        cwd=manifests.ROOT,
        check=False,
    )
    ended = _now()
    counts = {name: 0 for name in ("tests", "failures", "errors", "skipped")}
    if report.is_file():
        root = ET.parse(report).getroot()
        suites = [root] if root.tag == "testsuite" else root.findall(".//testsuite")
        for name in counts:
            counts[name] = sum(int(suite.attrib.get(name, "0")) for suite in suites)
    evidence = {
        "schema_version": 1,
        **{key: value for key, value in identity.items() if key.endswith("_sha256")},
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "test_command": manifests.TEST_QUALIFICATION_COMMAND,
        "test_inventory_sha256": manifests._canonical_sha256(tests),
        "junit_sha256": (
            hashlib.sha256(report.read_bytes()).hexdigest()
            if report.is_file()
            else None
        ),
        "passed": counts["tests"]
        - counts["failures"]
        - counts["errors"]
        - counts["skipped"],
        "failed": counts["failures"] + counts["errors"],
        "skipped": counts["skipped"],
        "exit_code": completed.returncode,
        "started_at": started,
        "ended_at": ended,
    }
    envelope.write_text(json.dumps(evidence, sort_keys=True, indent=2) + "\n")
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
