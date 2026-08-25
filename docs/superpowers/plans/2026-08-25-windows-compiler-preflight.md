# Windows Compiler Preflight Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace fixed Visual Studio paths with a truthful Windows compiler preflight and accept safe Git worktree checkouts.

**Architecture:** A small standard-library test helper owns compiler discovery and invocation. Existing fixture setup calls it, README makes it a hard qualification preflight, and the scanner special-cases only root Git metadata.

**Tech Stack:** Python 3 standard library, `unittest`, PowerShell 7, MSVC Build Tools.

---

### Task 1: Shared Windows compiler gate

**Files:**
- Create: `tests/windows_compiler.py`
- Create: `tests/test_windows_compiler.py`
- Modify: `tests/test_execution.py`
- Modify: `tests/test_governance_witness.py`

- [ ] Write tests that require active-`cl`, explicit-override, and `vswhere` discovery, a bounded missing-compiler error, and removal of fixed Build Tools paths.
- [ ] Run `python -m unittest tests.test_windows_compiler -v` and confirm the new tests fail because the helper does not exist.
- [ ] Implement discovery and compilation with `shutil.which`, `subprocess.run`, `Path`, and `unittest.SkipTest` only.
- [ ] Route both native fixture families through the helper.
- [ ] Run `python -m unittest tests.test_windows_compiler tests.test_execution tests.test_governance_witness -v` and require `OK` with only named platform or privilege skips.

### Task 2: Worktree-safe privacy scan

**Files:**
- Modify: `tests/test_scan_public_tree.py`
- Modify: `scripts/scan_public_tree.py`

- [ ] Add a failing test proving a regular root `.git` pointer is ignored and a linked root `.git` entry is reported when link creation is available.
- [ ] Run `python -m unittest tests.test_scan_public_tree -v` and confirm the pointer test fails on private absolute-path content.
- [ ] Prune only root Git metadata, recording links before pruning.
- [ ] Rerun the scanner tests and require `OK` with only the documented privilege skips.

### Task 3: Truthful fresh-clone documentation

**Files:**
- Modify: `tests/test_bootstrap_contract.py`
- Modify: `README.md`

- [ ] Add a failing contract assertion for `python -m tests.windows_compiler` and the rule that compiler-dependent skips do not qualify the checkout.
- [ ] Run the focused contract test and confirm it fails for the missing preflight text.
- [ ] Add the compiler requirement, command, stop behavior, and AI instructions to README.
- [ ] Rerun bootstrap tests and the bootstrap verifier; require 13 members and 5 documents.

### Task 4: Qualification and privacy verification

**Files:**
- Verify only.

- [ ] Run the complete documented unittest suite with bytecode writing disabled and require a final `OK`.
- [ ] Export tracked bytes to a temporary directory, run the public-tree scanner there, and require zero findings.
- [ ] Parse every tracked JSON schema and require zero parse failures.
- [ ] Run `git diff --check`, inspect the complete diff, and verify no tracked absolute developer paths or private material were added.
- [ ] Commit the verified repair, integrate it to private `main`, and push once. Keep the release on `HOLD` pending an independent clean-clone rerun.
