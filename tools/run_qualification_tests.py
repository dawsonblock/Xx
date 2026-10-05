"""Run the canonical test command and bind JUnit evidence to this source."""

from __future__ import annotations

import platform
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools import generate_release_manifests as manifests  # noqa: E402
from tools.evidence_schema import canonical_bytes, sha256  # noqa: E402
from tools.gate_specs import gate_spec  # noqa: E402


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
    envelope = manifests.ROOT / gate_spec("pytest").evidence_path
    report.parent.mkdir(parents=True, exist_ok=True)
    envelope.parent.mkdir(parents=True, exist_ok=True)
    report.unlink(missing_ok=True)
    envelope.unlink(missing_ok=True)
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
    counts = {name: 0 for name in ("tests", "failures", "errors", "skipped")}
    if report.is_file():
        root = ET.parse(report).getroot()
        suites = [root] if root.tag == "testsuite" else root.findall(".//testsuite")
        for name in counts:
            counts[name] = sum(int(suite.attrib.get(name, "0")) for suite in suites)
    spec = gate_spec("pytest")
    evidence = {
        "schema_version": 2,
        "gate_id": spec.gate_id,
        "runner_id": spec.runner_id,
        "verifier_id": spec.verifier_id,
        "phase": spec.phase,
        "identity": {key: identity[key] for key in spec.source_identity_requirements},
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "architecture": platform.machine(),
        },
        "parameters": {},
        "artifacts": (
            [{"artifact_id": "junit", "sha256": sha256(report.read_bytes())}]
            if report.is_file()
            else []
        ),
        "result": {
            "status": "PASS" if completed.returncode == 0 else "FAIL",
            "exit_code": completed.returncode,
            "details": {
                "passed": counts["tests"]
                - counts["failures"]
                - counts["errors"]
                - counts["skipped"],
                "failed": counts["failures"] + counts["errors"],
                "skipped": counts["skipped"],
                "test_inventory_sha256": manifests._canonical_sha256(tests),
            },
        },
    }
    envelope.write_bytes(canonical_bytes(evidence))
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
