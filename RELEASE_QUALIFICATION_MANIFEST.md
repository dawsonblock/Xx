# Unreleased qualification manifest

## Artifact

- Status: **unreleased; do not tag or publish**
- Package: `aideml-rsi` 1.3.5 source distribution
- Source revision: `386b374a8643add87408adb30c88bf020f38ae0b`
- Archive: `dist/aideml_rsi-1.3.5.tar.gz`
- Archive SHA-256: `8624fdfe3087782ce15e68ee8bd0f2e7642d4bf029e295fb9a8f7f4656f519e0`
- Member count: 912 regular files
- Per-file SHA-256 inventory: [`RELEASE_SOURCE_SHA256SUMS`](RELEASE_SOURCE_SHA256SUMS)

The archive was built from the source revision above. The checksum inventory
lists the digest and archive-relative path for every regular file in it. The
manifest is maintained in Git separately to avoid a self-referential archive.

## Qualification evidence

| Platform / scope | Result | Evidence |
|---|---|---|
| macOS local full project suite | 164 passed, 1 skipped | `python -m pytest -q` on the source tree |
| macOS Seatbelt nested-candidate outer timeout | Passed | [GitHub Actions run 36833875355](https://github.com/dawsonblock/Xx/actions/runs/36833875355) |
| Linux Bubblewrap isolation and effective resource-limit identity | Passed | [GitHub Actions run 36834348389](https://github.com/dawsonblock/Xx/actions/runs/36834348389) |
| Python lint | Passed | [GitHub Actions run 36834348509](https://github.com/dawsonblock/Xx/actions/runs/36834348509) |
| Source distribution build | Passed | `python setup.py -q sdist` |
| Compilation | Passed | `python -m compileall -q aide tests` |

Linux CI exercises the reference evaluator isolation suite and focused resource
limit tests. It is not a full Linux project-suite result. The macOS full-suite
result is local; the hosted macOS job specifically qualifies the nested
candidate timeout path.

## Release gates still open

- No independently operated external monotonic state-anchor service is
  configured. Whole-directory rollback detection is not active until one is
  provisioned and the experiment is enrolled with stable authorization.
- The branch still uses package version 1.3.5 and has no release tag.
- This manifest records branch qualification evidence; it does not claim
  deployment qualification for operator datasets or evaluator bundles.
