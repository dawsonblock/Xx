# Effective release authority audit

The generated `TCB_MANIFEST.json` now records four overlapping groups and an aggregate digest over their union. All paths come from the sorted source inventory. Each group's digest hashes canonical path-to-content-hash JSON; the aggregate digest hashes each unique trusted path once.

| Authority flow | Trusted inputs |
| --- | --- |
| Candidate execution, JEV advice, evaluator routing, state, signing, recovery, incumbent replacement | All `aide/**/*.py`, `aide/utils/config.yaml`, `rsi_anchor_service.py`, bundled `vendor/**` |
| Task/family selection, alpha, retirement, decision | Statistical modules, runner, config, anchor service, statistical qualification tool |
| Bubblewrap, evaluator confinement, container construction | Sandbox and evaluator modules, config, Linux workflow, Dockerfile, `.dockerignore` |
| Dependency installation, build, package contents, release publication | All workflows, all `tools/*.py`, all `tests/*.py`, requirements and lock, `setup.py`, `MANIFEST.in`, `Makefile`, `Dockerfile`, `.dockerignore`, `VERSION` |

Release and sandbox workflows are explicitly covered. Changing either workflow changes the respective group digest and the aggregate TCB digest. The broader inclusion of tests is deliberate: modifying a test can alter a qualification decision even when runtime code is unchanged.

`IDENTITY_MANIFEST.json` contains identity hashes only. `RELEASE_FREEZE_MANIFEST.json` records current qualification status separately and remains `UNRELEASED_QUALIFICATION_INCOMPLETE`. This audit does not establish that the new TCB has passed qualification.
