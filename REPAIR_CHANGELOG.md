# Repair changelog

This file records security-, evaluation-, statistical-, and release-authority
changes after the frozen pre-repair snapshot.

## Baseline

- Frozen tag: `pre-repair-1.3.5-5665eee`
- Baseline commit: `5665eee7957e32865b390c1c001616848d711446`
- Baseline Git tree: `1843f1e5946af1b12b0e2b20eae36032e8f84518`
- Repair branch base: `a2bdaedd0492b98e9ab0ee1726b14008766fc512`
- Evidence file hashes: [`qualification/history/PRE_REPAIR_1_3_5_BASELINE.json`](qualification/history/PRE_REPAIR_1_3_5_BASELINE.json)
- The 15 baseline manifests, reports, dependency files, statistical outputs,
  hosted workflow records, and JUnit output are preserved byte-for-byte under
  [`qualification/history/1.3.5-pre-repair/`](qualification/history/1.3.5-pre-repair/).

## Security and evaluation changes

- Split host-visible and sandbox-only evaluator paths into `HostPathSet` and
  `SandboxPathSet`. The first-party reference adapter receives real host paths
  and does not receive Bubblewrap-only namespace paths. Missing inputs fail
  closed. Custom evaluators continue to receive mounted namespace paths.
- Resolve Python runtime prefixes before building macOS Seatbelt parameters;
  this avoids mismatched `/tmp` symlink paths in clean virtual environments.
- Add tests for the Linux reference-evaluator path domain, missing artifacts,
  host/sandbox path separation, first-party trusted-runner wiring, and
  symlink-resolved Seatbelt runtime prefixes.
- Expand mandatory hosted Linux and macOS jobs to execute the first-party
  trusted-evaluator path and candidate-label boundary. Add the canary schedule
  invariants to Windows CI and changed tests to lint/format coverage.

## Statistical protocol changes

- Advance the protocol identity to `MULTITASK_PROMOTION_PROTOCOL_V4` and
  require exactly four paired runs for every task.
- Separate V4 task-pair authority settings from legacy V1 single-task series
  controls. Legacy bootstrap, pass-fraction, pair-count, and one-pair settings
  no longer enter the V4 panel protocol digest or signed pair-gate authority;
  tests verify that only decision-relevant settings change that digest. Mark
  unused runner settings, legacy series settings, decision inputs, and the
  serialized per-pair diagnostic threshold separately in config and docs.
- Replace caller-selected replicate-ID parity with a canonical task/ordinal
  scheduler using per-task ABBA or BAAB order. The signed transaction contains
  the complete schedule and digest; recovery recomputes and verifies both.
- Add adversarial even, odd, sparse, reordered, and 2,000-case randomized
  replicate-ID schedule tests. Require exact per-task, per-family, and global
  balance.
- Extend sequence-effect calibration to sweep bias magnitudes `0.01`, `0.05`,
  `0.10`, and `0.25` for first/second-run advantage, time/load drift, cache
  warm-up, provider degradation, family-specific order sensitivity, and their
  combined case. Calibration count checks use exact binomial tail probabilities
  with a multiple-scenario threshold; the report retains Wilson intervals.
- Make the release manifest require the full 20,000-lineage null run, 25
  correlation cells, all nuisance-bias sweeps, 5,000-replicate power curves at
  20–60 independent families, and a 500-attempt synthetic lineage stress.

## Reproducibility and release-record changes

- Add `requirements-rsi-ci.in` and a universal Python 3.12 hash lock used with
  `pip --require-hashes` in evaluator, platform, linter, and package workflows.
- Generate a complete per-file `SOURCE_TREE_MANIFEST.json` alongside TCB,
  build, and release-freeze manifests. The generator distinguishes a committed
  source snapshot from a dirty worktree and ignores old release metadata when
  its source digest does not match.
- Move the prior `RELEASE_SOURCE_SHA256SUMS` into clearly historical
  qualification storage. Retire old root-level test and statistical results;
  new outputs live under `qualification/repair-1.3.6/`.
- Update package verification and metadata so wheels and source distributions
  carry the source/TCB/release manifests and locked CI dependencies.
- Replace the README with current architecture, configuration, protocol,
  installation, validation, and release-limit guidance. Keep package version
  at `1.3.5` and the release state `UNRELEASED_QUALIFICATION_INCOMPLETE` until
  hosted, external-anchor, and real-task gates pass.

## Validation evidence

Current repair results are written separately under
`qualification/repair-1.3.6/` and summarized in
[`VALIDATION_REPORT.md`](VALIDATION_REPORT.md). Historical run counts and
workflow links in the preserved pre-repair files do not apply to this source.
