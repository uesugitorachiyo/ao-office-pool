# Windows-Private Months 7–12 Roadmap Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the obsolete public, cross-platform Months 7–12 program with a Windows-only private-stable roadmap and create an executable, automatically gated Month 7–8 handoff.

**Architecture:** Tracked files define durable scope and gates; the ignored handoff contains machine-local execution instructions and evidence locations. Roadmap authoring occurs in the isolated planning worktree, while native installation and qualification occur in a new Windows Codex task on a fixed local NTFS root. AO Mission records evidence and reconciliation but never grants execution or publication authority.

**Tech Stack:** Markdown, PowerShell 7, Python 3 `unittest`, Git, AO Mission 0.1.6, GitHub private releases, Windows NTFS

---

## Execution topology

- Author and commit tracked documentation in the isolated branch
  `codex/ao-office-pool-months-7-12-roadmap`.
- Store the private handoff under
  `.local/handoffs/AO_OFFICE_POOL_MONTHS_7_8_WINDOWS_PRIVATE_HANDOFF.md` in the
  repository's primary workspace. Do not add it to Git.
- Execute the handoff in a new Windows Codex task with the repository selected
  as its workspace.
- Create a separate execution worktree from the exact accepted source commit.
  Do not execute from the release-tag worktree or from the roadmap-authoring
  worktree.
- Keep candidates, AO Mission state, redownloads, and logs under ignored
  repository-local roots.
- Use a task-specific child of `C:\AOOfficePoolQualification` for native
  installs, disposable projects, and the five-office soak. Resolve it to an
  absolute path, require fixed local NTFS, reject reparse points, and never use
  the base directory itself as a recursive cleanup target.

### Task 1: Establish the stale-roadmap RED contract

**Files:**
- Inspect: `docs/ROADMAP_MONTHS_7_12.md`
- Inspect: `docs/ROADMAP.md`
- Reference: `docs/superpowers/specs/2026-08-23-windows-private-months-7-12-design.md`

- [ ] **Step 1: Verify the worktree and approved design identity**

Run:

```powershell
git status --short
git log -1 --oneline
Get-FileHash -Algorithm SHA256 docs/superpowers/specs/2026-08-23-windows-private-months-7-12-design.md
```

Expected: the worktree is clean, HEAD contains the approved design commit, and
the design file produces one SHA-256 digest for the evidence record.

- [ ] **Step 2: Run the stale-scope scan and preserve the RED output**

Run:

```powershell
rg -n 'public v1\.2\.0|public release|macOS|Linux|Pulse|RSI|skill package|component activation|72-hour' docs/ROADMAP_MONTHS_7_12.md docs/ROADMAP.md
```

Expected: matches demonstrate that the current tracked roadmap still contains
public-release, cross-platform, and speculative expansion scope. Save the
command and matched lines in the private execution evidence, not in tracked
documentation.

- [ ] **Step 3: Confirm the private release baseline**

Read `candidate-manifest.json` from the accepted private candidate and verify:

```text
source commit: 4bf8db6469a00dac69d2ddd7d103b501f797d7f6
candidate archive SHA-256: ebc61a5ae235815456831934e4e4a31352591c2dc71044de1b5a64b3186b4282
release tag: developer-preview-v02
visibility: private
architecture: windows-x86_64
```

Expected: every value matches. Stop with an exact identity blocker if any value
differs.

- [ ] **Step 4: Commit no changes for the RED contract**

This task is evidence-only. Confirm `git status --short` is unchanged before
starting the roadmap edits.

### Task 2: Replace the Months 7–12 roadmap

**Files:**
- Modify: `docs/ROADMAP_MONTHS_7_12.md`
- Reference: `docs/superpowers/specs/2026-08-23-windows-private-months-7-12-design.md`

- [ ] **Step 1: Replace the program statement and rules**

Write a Windows-only private-stable program statement with these exact
properties:

```text
Target: private stable AO Office Pool release
Supported platform: Windows x86-64 only
Repository and releases: private GitHub visibility
Delivery model: manual, evidence-gated releases; no complex CI/CD
Gate results: PASS, REPAIR, HOLD; Month 8 additionally returns ADVANCE
Progression: Month 7 PASS automatically starts Month 8
```

State that months are evidence gates, not mandatory calendar durations. Remove
all promises of a public `v1.2.0` release.

- [ ] **Step 2: Write the Month 7 gate**

Document these required inputs and outcomes:

```text
Input: exact authenticated developer-preview-v02 assets
Workload: all five offices on fixed local NTFS
Minimum volume: 100 successful claim/resume/release lifecycles across O1–O5
Minimum elapsed soak: 8 hours
Restart coverage: fresh-process restart and exact resume
Integrity: no duplicate ownership, cross-office access, unexplained resource growth, or accepted-state drift
Cleanup: zero candidate-owned residue; preserve and report unknown residue
Regression: full Windows suite passes against exact candidate source
Decision: PASS automatically advances; REPAIR reruns the entire gate; HOLD requires a genuine external blocker
```

- [ ] **Step 3: Write the Month 8 gate**

Document clean install, repeated verification, corruption rejection,
interrupted transaction recovery, repair/reinstall, uninstall/reinstall, all
eight component identities and help routes, support-output leak scanning, and
final cleanup. State explicitly:

```text
Native version-to-version update and rollback require two independently qualified candidates.
Do not fabricate a second release or weaken version checks to satisfy the test.
When only one candidate exists, keep deterministic update/rollback tests and move the native two-version exercise to Month 11.
```

Month 8 returns `ADVANCE`, `REPAIR`, or `HOLD` with AO Mission reconciliation.

- [ ] **Step 4: Write Months 9–12 as inactive future gates**

Use these bounded scopes:

```text
Month 9: Windows security and boundary audit
Month 10: 24-hour endurance and fault injection; extend to 72 hours only when evidence justifies it
Month 11: immutable stable candidate and two clean-host qualifications, one independent
Month 12: exact-byte private stable GitHub release and bounded stabilization
```

Keep Pulse/RSI expansion, unrelated skill redesign, unused component
activation, macOS/Linux, public distribution, schedulers, services, cloud
tenancy, public APIs, automatic updates, and complex CI/CD out of scope.

- [ ] **Step 5: Run the focused roadmap GREEN checks**

Run:

```powershell
rg -n 'Windows x86-64 only|private stable|100 successful|eight hours|ADVANCE|two independently qualified|24-hour|two clean-host' docs/ROADMAP_MONTHS_7_12.md
rg -n 'public v1\.2\.0|public release|macOS|Linux|Pulse|RSI|skill package|Complete AO component activation' docs/ROADMAP_MONTHS_7_12.md
```

Expected: the first command finds every required gate. The second command
returns no matches except explicit out-of-scope statements; inspect those
matches and require each to be a denial rather than a deliverable.

- [ ] **Step 6: Commit the roadmap replacement**

Run:

```powershell
git add docs/ROADMAP_MONTHS_7_12.md
git diff --cached --check
git commit -m "docs: make months 7-12 Windows-private gates"
```

Expected: one tracked roadmap file is committed with no whitespace errors.

### Task 3: Correct the Months 1–6 transition

**Files:**
- Modify: `docs/ROADMAP.md`
- Test: `tests/test_scan_public_tree.py`

- [ ] **Step 1: Mark Months 1–6 as the completed preview phase**

Update the introduction and closing transition without rewriting historical
technical requirements. Record that the accepted outcome is the private
Windows developer preview and that current execution is Windows-only.

- [ ] **Step 2: Replace the obsolete transition promise**

The closing paragraph must say:

```text
Months 7–12 advance the qualified private Windows developer preview through soak, lifecycle hardening, security, endurance, independent stable-candidate qualification, and an exact-byte private stable release. See ROADMAP_MONTHS_7_12.md.
```

Remove the promise of skill redesign, broad advanced-component activation, and
public `v1.2.0`.

- [ ] **Step 3: Verify transition consistency**

Run:

```powershell
rg -n 'private Windows developer preview|private stable release|ROADMAP_MONTHS_7_12' docs/ROADMAP.md
rg -n 'public v1\.2\.0|public release' docs/ROADMAP.md
python -m unittest tests.test_scan_public_tree
```

Expected: the new transition is present; obsolete public-release promises are
absent; scanner tests pass with only documented Windows-inapplicable skips.

- [ ] **Step 4: Remove only test-created cache files**

If the focused test creates untracked `__pycache__` files, resolve each exact
file below the worktree, verify it is a regular task-created `.pyc`, delete the
files, and remove only the now-empty cache directories. Do not run a recursive
delete against the repository or worktree root.

- [ ] **Step 5: Commit the transition correction**

Run:

```powershell
git add docs/ROADMAP.md
git diff --cached --check
git commit -m "docs: point preview to private stable program"
```

Expected: only `docs/ROADMAP.md` is included in this commit.

### Task 4: Create the private Month 7–8 execution handoff

**Files:**
- Create, ignored: `.local/handoffs/AO_OFFICE_POOL_MONTHS_7_8_WINDOWS_PRIVATE_HANDOFF.md`
- Reference: `docs/ROADMAP_MONTHS_7_12.md`
- Reference: `docs/superpowers/specs/2026-08-23-windows-private-months-7-12-design.md`

- [ ] **Step 1: Confirm the handoff root is ignored**

Run:

```powershell
git check-ignore -v .local/handoffs/AO_OFFICE_POOL_MONTHS_7_8_WINDOWS_PRIVATE_HANDOFF.md
```

Expected: a repository ignore rule covers the handoff. Stop before writing if
Git would track it.

- [ ] **Step 2: Write the activation and authority contract**

The handoff must begin with these instructions:

```text
Run only in a new Windows Codex task.
Create a Goal for completing Month 7 and, after PASS, Month 8.
Continue proactively through in-scope work without asking permission merely to continue.
Do not publish, promote, change visibility, install unrelated toolchains, or expand platform scope.
Use AO Mission for records and reconciliation only; it grants no execution or publication authority.
Preserve unrelated changes and reconcile only processes and paths proven to belong to this task.
```

- [ ] **Step 3: Write the preflight and execution topology**

Require the executor to:

1. resolve the repository root with Git rather than hardcoding a developer
   path;
2. verify the private release, source commit, tag target, eight asset names,
   sizes, and hashes;
3. create a clean execution worktree at the accepted source commit;
4. create fresh ignored AO Mission, log, and redownload roots;
5. allocate one task-specific fixed-local-NTFS qualification root under
   `C:\AOOfficePoolQualification`;
6. verify that root is neither a reparse point nor the base directory; and
7. inspect running processes by executable path and command line before ending
   only a process proven to belong to this handoff.

- [ ] **Step 4: Write the exact Month 7 control loop**

The handoff must implement:

```text
PRECHECK -> authenticated redownload -> exact hash comparison -> clean install/verify
-> 100+ O1-O5 lifecycle cycles -> 8+ elapsed hours -> restart/resume coverage
-> resource/state/residue audit -> full Windows suite -> AO Mission checkpoint/reconcile
```

Decision rules:

```text
PASS: every gate passes against one exact candidate; start Month 8 automatically.
REPAIR: create a failing test, apply the smallest correction, build a new immutable candidate, and restart Month 7 from precheck.
HOLD: stop only for a genuine external blocker; record exact evidence and next action.
```

- [ ] **Step 5: Write the exact Month 8 control loop**

Require the native lifecycle matrix from the approved design, deterministic
update/rollback regressions, the two-qualified-candidate rule, operator guide
verification, support-output leak scanning, full suite, uninstall, zero
candidate-owned residue, and AO Mission reconciliation.

Decision rules:

```text
ADVANCE: Month 8 complete and Months 9-12 remain inactive.
REPAIR: repair from one demonstrated RED and rerun every invalidated Month 7-8 gate.
HOLD: genuine external blocker with exact next action.
```

- [ ] **Step 6: Define the required handback**

Require the executor to create ignored
`.local/handoffs/AO_OFFICE_POOL_MONTHS_7_8_HANDBACK.md` containing:

```text
Goal and AO Mission identities
source commit, clean-tree state, release URL, tag target, candidate hash
all eight redownloaded asset names, sizes, and hashes
Month 7 workload counts, elapsed time, restart coverage, resource trends, and decision
Month 8 lifecycle matrix and decision
tests with commands, counts, durations, skips, and exit status
repairs and candidate changes, or an explicit statement that none occurred
cleanup and residue disposition
AO Mission checkpoint and final reconciliation digests
recommendation: ADVANCE, REPAIR, or HOLD
exact next action
```

- [ ] **Step 7: Verify the handoff remains private and self-contained**

Run:

```powershell
git check-ignore -q .local/handoffs/AO_OFFICE_POOL_MONTHS_7_8_WINDOWS_PRIVATE_HANDOFF.md
git status --short
rg -n 'public v1\.2\.0|macOS|Linux|Pulse|RSI|automatic publish|automatic promotion' .local/handoffs/AO_OFFICE_POOL_MONTHS_7_8_WINDOWS_PRIVATE_HANDOFF.md
```

Expected: the handoff is ignored, absent from Git status, and any scope terms
appear only as explicit denials.

### Task 5: Final documentation verification and branch handoff

**Files:**
- Verify: `docs/ROADMAP.md`
- Verify: `docs/ROADMAP_MONTHS_7_12.md`
- Verify: `docs/superpowers/specs/2026-08-23-windows-private-months-7-12-design.md`
- Verify: `docs/superpowers/plans/2026-08-23-windows-private-months-7-12-roadmap.md`
- Verify, ignored: `.local/handoffs/AO_OFFICE_POOL_MONTHS_7_8_WINDOWS_PRIVATE_HANDOFF.md`

- [ ] **Step 1: Run the tracked privacy and consistency checks**

Run:

```powershell
python scripts/scan_public_tree.py .
python -m unittest tests.test_scan_public_tree
git diff --check
rg -n 'public v1\.2\.0 release|public GitHub release|macOS qualification|Linux qualification' docs/ROADMAP.md docs/ROADMAP_MONTHS_7_12.md
```

Expected: scanner exit `0`; focused tests pass; diff check is clean; stale
scope scan has no positive deliverable claim.

- [ ] **Step 2: Inspect every changed tracked line**

Run:

```powershell
git status --short
git diff --stat 4bf8db6469a00dac69d2ddd7d103b501f797d7f6..HEAD
git diff 4bf8db6469a00dac69d2ddd7d103b501f797d7f6..HEAD -- docs/ROADMAP.md docs/ROADMAP_MONTHS_7_12.md docs/superpowers/specs docs/superpowers/plans
```

Expected: only the approved design, roadmap, transition, and implementation
plan are changed. No private handoff, candidate, receipt, log, or live state is
tracked.

- [ ] **Step 3: Commit the implementation plan if it is not already committed**

Run:

```powershell
git add docs/superpowers/plans/2026-08-23-windows-private-months-7-12-roadmap.md
git diff --cached --check
git commit -m "docs: plan Windows-private months 7-8 handoff"
```

Expected: the plan receives its own documentation commit.

- [ ] **Step 4: Record the execution recommendation**

Return the roadmap branch and commit identities, the ignored handoff path and
SHA-256, and this exact recommendation:

```text
Execute Months 7-8 in a new Windows Codex task. Keep source and evidence under the private repository workspace, but run native installation and soak workloads under a fresh task-specific fixed-local-NTFS C: qualification root. Do not run the soak in the planning worktree, release-tag worktree, macOS, Linux, WSL, a network share, or a removable qualification root.
```

- [ ] **Step 5: Dispatch only after the tracked roadmap branch is integrated**

After the roadmap commits are integrated into the private repository's main
branch, create the new Windows Codex task with the ignored Month 7–8 handoff as
its prompt. Wait for an initial readback proving the Goal, AO Mission,
candidate, worktree, NTFS root, and orphan-process audit before leaving it to
run the bounded soak.
