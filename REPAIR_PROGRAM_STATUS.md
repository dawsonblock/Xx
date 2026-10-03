# Xx 1.3.6 repair program status

This is an implementation checkpoint, not release qualification. `VERSION` remains 1.3.5. The repair source differs from the last qualified manifest, so `tools/generate_release_manifests.py --check` must fail until the intended source is frozen and new evidence is produced.

| Phase | Current result | Qualification boundary |
| --- | --- | --- |
| 0 forensic baseline | Completed in the committed `FORENSIC_BASELINE` JSON/Markdown. | The named ZIP was unavailable; baseline identifies the Git repair target, not ZIP byte identity. |
| 1 source drift | Seven differences classified in `SOURCE_DRIFT_ANALYSIS.md`; all retained deliberately. | All old source-bound evidence is historical. |
| 2-3 TCB and identities | Runtime, statistical, sandbox, release, and aggregate TCB identities implemented; deterministic identity tests pass. | Current manifests are stale by design during repair. |
| 4-5 packaging and publication gates | `sdist`, wheel, source ZIP, Docker, package smoke, and PyPI workflow require manifest checks. PyPI also calls the future release verifier before publishing. | Final `verify_release.py`, qualification ledger, signed release evidence, and hosted workflow execution remain absent; publication fails closed. |
| 6 package integrity | Wheel and sdist contents are checked against the source manifest, TCB, locks, version, benchmark, RECORD, and trusted checkout. Fake-content and other adversarial unit tests pass. An isolated build passed integrity-only verification. | Strict qualification rejects the current unreviewed benchmark and missing ledger/provenance. |
| 7-8 evidence binding | JUnit now needs an identity-bound envelope. Existing hosted, dependency, and statistical evidence also needs matching source, TCB, lock, protocol, evaluator, and benchmark identities. | Existing 1.3.5 evidence is stale for this source. No new complete source-bound qualification run exists. |
| 9-12 runtime, lock, version, docs | Reference Python is 3.12; package/CLI/image versions derive from VERSION; V6 documentation matches executable constants. Fresh x86_64 macOS Python 3.12.13 CI-lock install and `pip check` passed. A 271-package full-runtime lock was generated with hashes. | The full-runtime lock is an unqualified candidate. A disposable Linux installation was stopped while downloading a 543 MB CUDA component because host free space fell to about 12 GiB. Docker qualification still needs a successful locked install and image verification. |
| 13-15 statistics and JEV | Added duplicate sample-ID rejection, practical-effect decision recording, threshold immutability checks, and adversarial JEV output tests. | Real-task calibration and operationally meaningful threshold selection remain unrun. |
| 16 Linux sandbox | Two hostile candidate tests passed through `SecureInterpreter` Bubblewrap in a privileged ephemeral Linux container. | This is scoped local evidence, not hosted production sandbox qualification. |
| 17 Docker | Python 3.12 base-image index digest pinned; Dockerfile and context enter TCB. | Final image build, image digest, and container verification are blocked by the unqualified runtime lock and unfrozen source. |
| 18 family provenance | Canonical manifest schema, immutable panel/state digest binding, and split-family regression tests added. | Repository manifest is empty and `UNREVIEWED`; live 40-family promotion is rejected. |
| 19-33 real controls through final release | Not run. | Require a frozen reviewed real-task panel, independently operated anchor, final source freeze, hosted runs, ledger, clean-room build, and signed artifacts. |

Local test observation: native arm64 Python 3.12.0 `python -m pytest -q tests` returned **267 passed, 3 skipped** on the current repair files. The hash-locked CI dependency install was separately exercised in an x86_64 Python 3.12.13 virtual environment; its full-suite Seatbelt failures were caused by Rosetta failing to launch child interpreters and are not counted as source qualification. Neither local run supplies a source-bound release PASS envelope.

The qualified release gate remains closed. No v1.3.6 tag, package publication, or production promotion is authorized by this checkpoint.
