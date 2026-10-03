# Source drift decision for the 1.3.6 repair candidate

The forensic baseline in `qualification/forensics/Xx-repair-1.3.6-authority-statistics/` compares this checkout with frozen commit `f4fe8b4a543fdf60a0b8f008e1ba6a3f5e5f3c60`. That commit supplies the previously qualified bytes. The seven differences are fully explained by commits `f35f761b43cbf5d964ff051ccc9c9402879a71ff` and `aeff6c26f0687b56b86a4c2e79fb70209c441fb0`.

| Path | Difference from frozen source | Decision | Authority and invalidation |
| --- | --- | --- | --- |
| `.github/workflows/linux-bubblewrap.yml` | Adds `aide/rsi/sandbox.py` to both path filters. Test command, namespace setup, and mounts are unchanged. | Retain coverage correction. | Sandbox and release TCB; hosted sandbox evidence must rerun. |
| `Dockerfile` | Copies anchor service, tools, vendor, manifests, and RSI lock into image. Runtime contents change; existing base image still uses Python 3.10. | Retain copied files, then repair runtime version and build qualification. | Runtime and release TCB; old container/package evidence is stale. |
| `aide/journal2report.py` | Changes malformed prompt closing tags to `</journal>` and `</task>`. | Retain functional correction. | Source identity changes; previous whole-source tests cannot qualify this tree. |
| `aide/rsi/evolution.py` | Removes one blank line. Candidate generation, mutation, search, incumbent identity, evidence, and recovery statements are byte-for-byte otherwise unchanged. | Retain formatter output. | Runtime TCB byte identity changes; previous TCB-bound evidence is stale. |
| `aide/rsi/jev.py` | Removes one blank line. Advisory boundary, `direct_authorized` handling, evaluator routing, and tool capabilities are otherwise unchanged. | Retain formatter output. | Runtime TCB byte identity changes; previous TCB-bound evidence is stale. |
| `requirements-rsi-ci.in` | Changes Black from 24.3.0 to 26.3.1. | Retain deliberate formatter update. | Dependency and release TCB identities change; previous install and test evidence is stale. |
| `requirements-rsi-ci.lock` | Regenerated hashes for Black 26.3.1 and its `pytokens==0.4.1` dependency. | Retain only with fresh locked-install qualification. | Dependency lock and release TCB identities change. |

The lock header records `uv pip compile requirements-rsi-ci.in --universal --python-version 3.12 --generate-hashes --output-file requirements-rsi-ci.lock`. The exact formatter version, lock contents, and installation result still require Phase 10 qualification.

The canonical intended source for subsequent repairs retains all seven changes. No unexplained drift remains. The old JUnit, hosted run record, dependency install, synthetic calibration, package, and container evidence remain historical evidence for their recorded source only. None qualifies this candidate. Manifest regeneration is deferred until the intended release authority model is implemented.
