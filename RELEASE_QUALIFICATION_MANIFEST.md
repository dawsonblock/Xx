# Current statistical-authority qualification

The current source snapshot is frozen at qualified code commit
`c4603ac4128f9e45480c286457ad4a1eeac48ee4` (Git tree
`0587067e04f7d67c1bbbf2f3d491c54ad6885173`). Its package version remains
`1.3.5`; this is an unreleased qualification milestone, not v1.4.0.

The canonical machine-readable identity and qualification record is
[`RELEASE_FREEZE_MANIFEST.json`](RELEASE_FREEZE_MANIFEST.json), with selected
authority-critical file hashes in [`TCB_MANIFEST.json`](TCB_MANIFEST.json) and
the reproducible synthetic campaign in
[`qualification/multitask-statistical-qualification.json`](qualification/multitask-statistical-qualification.json).

Local results on 2026-10-01: 208 passed and 1 skipped in the full project
suite; synthetic family-wise null calibration passed 20,000 100-attempt
lineages (3.37% false-promotion rate; 95% Wilson interval 3.13%–3.63% under
the 5% family alpha); all 25 within-seed/family-correlation scenarios passed;
and an in-memory 500-panel synthetic lineage stress completed. Power is
attempt-dependent and falls at late attempts as the precommitted alpha budget
shrinks. The report and artifact document the observed power rather than
implying all-attempt high power.

Hosted CI for this exact source commit, independent external-anchor deployment and rollback
qualification, real multi-task controls, and real AIDE-RSI lineage qualification
remain unconfirmed or not run. No release tag should be cut from this record.

## Historical qualification snapshots

The sections below preserve older source and CI records. Their test totals and
workflow results apply only to the commits named in those sections.

## Frozen source qualification identity

The authority-closure source snapshot before the next milestone work is frozen at release head
`f21f159ef4b9cca7b2b4db69f73f0934e2eba5a0`. Hosted platform and lint jobs
qualified the executable source at `cd94004385b09fa71fc10f0c9ff8b6b87042b63c`.
The complete-tree comparison confirms that the intervening commit changes only
`BUILD_MANIFEST.json`, `SECURITY_HARDENING_REPORT.md`, and
`VALIDATION_REPORT.md`. The canonical executable/configuration/security digest
is identical across both commits.

Machine-readable records:

- [`RELEASE_FREEZE_MANIFEST.json`](RELEASE_FREEZE_MANIFEST.json) records both
  commit identities, complete-tree digests, the TCB digest, configuration and
  dependency-input hashes, and hosted workflow runs.
- [`SOURCE_TREE_MANIFEST.json`](SOURCE_TREE_MANIFEST.json) inventories every
  Git leaf entry at both commits and supplies the inputs for the complete-tree
  SHA-256 values.
- [`TCB_MANIFEST.json`](TCB_MANIFEST.json) inventories the selected source,
  tests, workflows, configuration, and dependency/build inputs.

The release head in these records means the frozen source/report snapshot, not
the later commit that stores these manifests. These manifests are qualification
metadata and do not alter the source snapshot exercised by CI. There is no
complete root dependency lockfile: the requirements files contain ranged or
unpinned dependencies, so `dependency_lock_sha256` is null and their combined
input digest is recorded separately. Any code committed after `f21f159` is
outside these hashes and CI results until it is qualified separately.

| Hosted workflow | Result | Qualified commit |
|---|---|---|
| [macOS nested candidate timeout](https://github.com/dawsonblock/Xx/actions/runs/36848550589) | Passed | `cd94004385b09fa71fc10f0c9ff8b6b87042b63c` |
| [Linux Bubblewrap](https://github.com/dawsonblock/Xx/actions/runs/36848550461) | Passed | `cd94004385b09fa71fc10f0c9ff8b6b87042b63c` |
| [Windows RSI state lock](https://github.com/dawsonblock/Xx/actions/runs/36848550549) | Passed | `cd94004385b09fa71fc10f0c9ff8b6b87042b63c` |
| [Linter](https://github.com/dawsonblock/Xx/actions/runs/36848550714) | Passed | `cd94004385b09fa71fc10f0c9ff8b6b87042b63c` |

The current source remains unreleased. These records freeze repository and CI
identity; they do not claim that an external anchor service has been deployed,
that multi-task statistical assumptions have been validated, or that a
100–500-generation lineage campaign has passed.

## Post-freeze milestone implementation

The following implementation is work after the frozen `f21f159` snapshot and
is not covered by the hosted runs listed above. It adds a SQLite-backed
reference anchor service, a hash-chained sequential alpha budget committed to
authenticated RSI state before each canary attempt, anchor and budget
conformance tests, and a seeded statistical sensitivity probe. The focused
hosted workflows passed on source commit
`4006d1683ab09c5dd938326e8b3bdec2a8ab2dda`:

| Hosted workflow | Result | Scope |
|---|---|---|
| [Linux Bubblewrap](https://github.com/dawsonblock/Xx/actions/runs/36935981465) | Passed | Candidate isolation, anchor service, and budget tests |
| [macOS nested candidate timeout](https://github.com/dawsonblock/Xx/actions/runs/36935981266) | Passed | Seatbelt nested-timeout, anchor service, and budget tests |
| [Windows RSI state lock](https://github.com/dawsonblock/Xx/actions/runs/36935981267) | Passed | Cross-platform lock, anchor service, and budget tests |
| [Linter](https://github.com/dawsonblock/Xx/actions/runs/36935981213) | Passed | Ruff 0.7.1 and Black 24.3.0 |

These are focused hosted checks, not a complete project suite on all three
platforms. The implementation remains unreleased.

Local validation on 2026-10-01:

| Check | Result | Scope |
|---|---|---|
| Full project suite | 191 passed, 1 skipped | Local environment |
| Black | Passed | Changed Python files |
| Ruff | Passed | Changed Python files |
| `compileall` | Passed | `aide`, `tests`, anchor service, and tools |
| `git diff --check` | Passed | Working tree |
| Source distribution | Passed | Built locally; contents checked |
| Anchor rollback conformance | Passed | 100 anchored revisions; restoring revision 20 after revision 100 failed closed |

The statistical sensitivity run is recorded in
[`qualification/canary-statistics-synthetic.json`](qualification/canary-statistics-synthetic.json)
and described in [`docs/STATISTICAL_QUALIFICATION.md`](docs/STATISTICAL_QUALIFICATION.md).
It is synthetic evidence only: the shared-task-effect null produced a 47.8%
false-promotion rate over 500 lineages. The current single-task canary does not
establish independent task-level signs, so multi-task statistical validity,
external service deployment, and long-lineage qualification remain open.

> Historical snapshot: the artifact digest and checksum inventory below were
> generated from source revision `386b374a8643add87408adb30c88bf020f38ae0b`.
> They do not cover the subsequent authority-closure fixes now on this branch.
> The current source remains unreleased and requires a fresh build and
> qualification manifest before any release.

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
