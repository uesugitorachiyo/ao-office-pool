# Coherent Release Rebaseline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rebaseline AO Office Pool Task 6 to the seven-component coherent public binary release, preserve the unreleased component locks, and regain exact macOS and physical-Windows qualification before Task 7 starts.

**Architecture:** Treat the independently verified campaign inventory as immutable input. Update only the seven released source/binary entries, retain archive and extracted-binary identities separately, then correct Task 6 producer fixtures to the pinned producer-native contracts before rebuilding one clean Windows qualification package.

**Tech Stack:** Git, Python 3.12 standard library, SHA-256, ZIP/tar archives, PowerShell 5.1, Windows Task Scheduler, existing AO Office Pool tests and SDD evidence scripts.

**Spec:** `docs/superpowers/specs/2026-08-12-task6-governance-witness-design.md`; release authority: Task 1's independently verified coherent-binary campaign final report.

## Global Constraints

- Update only AO2 `v0.5.11`, AO2 Control Plane `v0.1.19`, AO Mission `v0.1.4`, AO Atlas `v0.2.0`, AO Command `v0.1.2`, AO Forge `v0.1.4`, and AO Covenant `v0.1.1`.
- Preserve all other component entries and bytes unchanged.
- Use exact tag targets from `public-release-inventory.json`, never newer `main` heads.
- Verify campaign manifest SHA-256 `4d7dd9ed769063d9bb7c66ac24e8cedb3a3e6d48da6c9523a42237b326bbec0a` and every selected public asset before extraction.
- Keep archive digests distinct from extracted executable digests.
- No publication, deployment, provider call, upstream mutation, Production/public-v1.2.0 claim, Task 7/8 implementation, or Months 7–12 scaffold.
- Task 7 remains held until exact-head macOS and physical-Windows Task 6 evidence plus independent final review both pass.

---

### Task 1: Bind and import the coherent release

**Files:**
- Modify local-only: `.local/sources/{ao2,ao2-control-plane,ao-mission,ao-atlas,ao-command,ao-forge,ao-covenant}`
- Modify local-only: `.local/bin/`
- Modify local-only: `.local/staging/windows-x86_64/components/`
- Create ignored evidence: `.superpowers/sdd/2026-08-13-coherent-release-rebaseline/release-import.json`

**Interfaces:**
- Consumes: `public-release-inventory.json`, `campaign-manifest.json`, and locally retained public assets.
- Produces: exact source, archive, and extracted-binary digest map for seven components on macOS and Windows.

- [ ] Verify campaign manifest and independent verification status with the campaign's `verify-campaign-manifest.py`.
- [ ] Verify each selected asset size and SHA-256 against `public-release-inventory.json` before extraction.
- [ ] Fetch tags in each clean source checkout and detach at the exact release target; reject any dirty checkout or missing commit.
- [ ] Extract into fresh temporary directories, reject absolute/traversal/link members, and record executable SHA-256 values.
- [ ] Replace only the seven local macOS binaries and seven Windows staging component trees using exact verified bytes.
- [ ] Rehash the installed bytes and write `release-import.json`; assert all unreleased component hashes remain unchanged.

### Task 2: Repin the tracked component baseline

**Files:**
- Modify: `manifests/components.lock.json`
- Modify: `tests/test_verify_components.py`
- Modify: `tests/test_release_tree.py` only if the existing public-tree binding requires the new lock digest.

**Interfaces:**
- Consumes: Task 1's exact source and macOS executable digest map.
- Produces: the new tracked source/runtime baseline used by Mission and governance witness verification.

- [ ] Add a RED test that requires all seven release tags, exact target commits, assets, and installed macOS executable digests while asserting the other seven entries are byte-identical to the pre-rebaseline lock.
- [ ] Run `python3.12 -m unittest tests.test_verify_components -v`; require RED against the old lock.
- [ ] Change only the seven released objects in `manifests/components.lock.json`.
- [ ] Run `python3.12 -m unittest tests.test_verify_components tests.test_release_tree -v` and `python3.12 scripts/verify_components.py`; require pass.
- [ ] Commit with `git commit -m "chore: rebaseline coherent AO release"`.

### Task 3: Align Task 6 with producer-native artifacts

**Files:**
- Modify: `internal/governance_witness.py`
- Modify: `tests/test_governance_witness.py`
- Modify: `packaging/runtime/ao-forge/docs/contracts/goal-run-v0.1.schema.json` only if the released Forge schema differs after exact comparison.
- Modify ignored qualification support under `.superpowers/sdd/2026-08-12-task6-governance-witness-correction/qualification-support/`.

**Interfaces:**
- Consumes: locked Blueprint authorization, Atlas workgraph, Forge GoalRun, Covenant `covenant.evidence-pack.v1` plus native ledger, and active Pool authority lease.
- Produces: the existing HMAC-sealed witness envelope with upstream-missing Mission/receipt/project/AO2/workflow/expiry bindings derived by Pool.

- [ ] Add RED tests rejecting the former `covenant.governance-evidence.v1` object and one-line fake ledger when the real Covenant contract is selected.
- [ ] Add producer-native valid Atlas, Forge, and Covenant fixtures derived from the exact released schemas; never copy private campaign paths or identities.
- [ ] Run the real pinned producer commands against those fixtures and bind their exact bounded readbacks/digests.
- [ ] Keep fake producers only for deterministic negative/unit tests; native qualification must execute all real locked producers through `issue_witness()` and `execute()`.
- [ ] Run focused and full macOS suites, clean-export scan, `py_compile`, and `git diff --check`.
- [ ] Commit with `git commit -m "fix: consume producer-native governance evidence"` and obtain independent spec/code-quality review.

### Task 4: Requalify Task 6 on physical Windows

**Files:**
- Modify ignored SDD Task 6 report, final-review brief, dispatch, ledger, and Windows evidence directories.

**Interfaces:**
- Consumes: exact tracked head, verified released Windows assets, current fake fixtures built from that head, and Task 1 import map.
- Produces: one digest-bound focused/full/native terminal result and cleanup proof.

- [ ] Build one fresh allowlisted qualification archive; record source, archive, allowlist, every member, released archive, and extracted executable SHA-256.
- [ ] Independently extract and compare every member before launch.
- [ ] Launch one detached scheduled task and release SSH; run focused, full, and real-producer witness-to-execute native smoke sequentially.
- [ ] Retrieve and hash every stdout/stderr/cmd/result file before cleanup.
- [ ] Require expected test counts, native smoke pass, NTFS identity tests, zero bound/named AO/Cargo/Rust processes, then remove only the exact scheduled task and scratch.
- [ ] Update the Task 6 final review package and require `Spec compliance: PASS` plus `Code quality: APPROVED` before Task 7 dispatch.
