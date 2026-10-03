# Forensic baseline: Xx repair 1.3.6 authority/statistics

## Result

Phase 0 is complete for committed branch state `aeff6c26f0687b56b86a4c2e79fb70209c441fb0`.

The current branch contains exactly seven files that differ from the frozen qualified source. Five belong to the recorded TCB. Every difference is attributable to one of two post-qualification commits, so no unexplained source drift remains. The current manifests are correctly detected as stale, and the existing qualification evidence remains evidence for frozen source `e8949265…`, not for this modified candidate.

The named ZIP bytes were not available locally. The remote branch history contains exactly the seven reported differences, which makes it the repair target used here, but this report does not assert byte identity between the unavailable ZIP and the Git checkout.

Machine-readable evidence is in [`FORENSIC_BASELINE.json`](FORENSIC_BASELINE.json).

## Repository identity

| Field | Value |
|---|---|
| Checkout | `/Users/dawsonblock/Downloads/AIDE-DREAM-RSI-v1.3.0/repair-worktree` |
| Branch | `repair/1.3.6-authority-statistics` |
| Current HEAD | `aeff6c26f0687b56b86a4c2e79fb70209c441fb0` |
| Current Git tree | `a15836a8fe5a16d9c90f2fe4e3d116a266915bf7` |
| Frozen qualified code | `f4fe8b4a543fdf60a0b8f008e1ba6a3f5e5f3c60` |
| Frozen qualified Git tree | `4b3382db21c06f546db38b68c18306325b8afa7c` |
| VERSION | `1.3.5` |
| Canonical Python | 3.12.0 |
| Platform | Darwin 25.2.0 arm64 |

The two post-qualification commits are:

- `f35f761b43cbf5d964ff051ccc9c9402879a71ff` — Address Copilot review feedback.
- `aeff6c26f0687b56b86a4c2e79fb70209c441fb0` — Upgrade Black to patched release.

## Frozen and candidate identities

No manifests were regenerated in Phase 0. Candidate digests were computed in memory with the manifest generator's canonical functions.

| Identity | Frozen qualified value | Current candidate value |
|---|---|---|
| Source snapshot | `e89492654bc9c9ebe04b2f221c0800d4feccffbc7bad78fb561e4842936f9bf4` | `70b9ae27be030c78c23897ca9f1587da43c78ffc891fde4d72bf1e4b9e94979a` |
| TCB files | `8902b3ec896bb6fb917a695585c42b18cde70d67e9e4b8d441fee43ee4ce5f19` | `b9ad7947ee3863f42dd7a0049df98fe2234fef14afc2484e950ee832a50ca165` |
| TCB manifest object | `160ff4583eff605414bad1f88ba3ed815695c499e59d61a3ea6f8129945b1984` | `945ce6df49a198be7384b76b51c619dc4fb541a73d8c03f5b0a786925a2da06d` |
| Dependency lock | `f8ed88219bbf3f5e801bf8cdabe4c732008213150c5197abcccd7b0caa37f1be` | `1fe8cbe0b645c825ff8053454605e5861d2eac95452e484eab96173ea140dc2d` |
| Statistical protocol | `9f7ca2438516b911e6a3625de43b8612e8b7cfe0e717a67ec4b0b276bcdfc861` | unchanged |

`python tools/generate_release_manifests.py --check` exits 1 and reports these stale outputs:

- `BUILD_MANIFEST.json`
- `TCB_MANIFEST.json`
- `RELEASE_FREEZE_MANIFEST.json`
- `SOURCE_TREE_MANIFEST.json`

Independent file verification found 7/917 source-manifest mismatches and 5/50 TCB-manifest mismatches. No file was missing.

## Discrepancy classification

| File | Frozen SHA-256 | Current SHA-256 | Class | TCB | Qualification invalidated |
|---|---|---|---|---:|---:|
| `.github/workflows/linux-bubblewrap.yml` | `f91aab0…521bb29` | `7a58a4d…6cfb0f3` | A | yes | yes |
| `Dockerfile` | `83d06ec…429978` | `d9b9f58…ded5ef` | C | no | yes |
| `aide/journal2report.py` | `e3d70cb…84a52d` | `c29d708…5b08a64` | A | no | yes |
| `aide/rsi/evolution.py` | `33b00b1…a63c08db` | `5c21b8f…8a76d60` | A | yes | yes |
| `aide/rsi/jev.py` | `34bb48c…7f57e9d8` | `b725fe9…b1f3bf9` | A | yes | yes |
| `requirements-rsi-ci.in` | `15cfc1e…a9ec1ab6` | `03a471e…5732c1` | D | yes | yes |
| `requirements-rsi-ci.lock` | `f8ed882…37f1be` | `1fe8cbe…40dc2d` | D | yes | yes |

Classifications follow the repair program: A is an intentional post-qualification source change, C is a packaging mutation, and D is dependency-lock drift.

### `.github/workflows/linux-bubblewrap.yml`

The workflow adds `aide/rsi/sandbox.py` to push and pull-request path filters. This is an intentional coverage correction in `f35f761`. It affects when Linux sandbox qualification runs, so it is TCB-relevant and requires fresh hosted qualification.

### `Dockerfile`

The container build now copies the anchor service, tools, vendor directory, manifests, and RSI lock inputs. This is an intentional packaging mutation in `f35f761`. It changes the built artifact contents and invalidates package evidence for the frozen source.

### `aide/journal2report.py`

The report prompt replaces malformed `<\\journal>` and `<\\task>` endings with proper `</journal>` and `</task>` tags. This is an intentional functional correction in `f35f761`. It is outside the recorded RSI TCB but remains a source-identity change.

### `aide/rsi/evolution.py` and `aide/rsi/jev.py`

Each change removes one blank line as part of the Black upgrade commit. No executable semantic change is present in the diff. Both files are in the TCB, so even formatting-only byte changes invalidate the frozen TCB identity and require requalification.

### `requirements-rsi-ci.in` and `requirements-rsi-ci.lock`

Black changes from `24.3.0` to `26.3.1`; the hash lock is regenerated and adds Black's `pytokens==0.4.1` dependency and artifact hashes. This is dependency-lock drift in `aeff6c2`. The old qualification environment remains reconstructible from Git commit `f4fe8b4`, but the current candidate environment has a new lock identity and has not yet been clean-installed or qualified.

## Protocol and evaluator inventory

The source changes do not alter executable statistical policy:

- Protocol: `MULTITASK_PROMOTION_PROTOCOL_V6`
- Protocol version: 6
- Protocol SHA-256: `9f7ca2438516b911e6a3625de43b8612e8b7cfe0e717a67ec4b0b276bcdfc861`
- Minimum tasks/families: 40 / 40
- Minimum strata: 3
- Runs per task: exactly 4
- Promotion horizon: 500
- Family alpha: 0.05
- Per-attempt alpha: 0.0001
- First-party evaluator entrypoint: `__aide_reference__`
- Frozen reference-evaluator file SHA-256: `1011bce2826b907facca72cacb04517a745b022b79d9ae4179fdbcdf6372e615`

A runtime evaluator identity is configuration-specific and was not synthesized during this read-only phase.

## Evidence scope

The current hosted run record, JUnit report, dependency-install record, and synthetic statistical artifact all refer to frozen source `e8949265…`. They may remain valid historical evidence for that exact source. They do not qualify candidate source `70b9ae27…`.

No release manifest or qualification report should be regenerated merely to hide this mismatch. Phase 1 must decide whether each intentional change is retained and requalified, reverted to its frozen version, or regenerated from an authoritative source.

## Phase gate

- Every current discrepancy has an old and new SHA-256: **yes**.
- Every current discrepancy has a classification and origin commit: **yes**.
- Unexplained source drift: **zero files**.
- Phase 0 acceptance for committed branch state: **met**.
- Phase 1 may begin: **yes**.
- Current source release-qualified: **no**.
- Named ZIP byte identity independently verified: **no**.
