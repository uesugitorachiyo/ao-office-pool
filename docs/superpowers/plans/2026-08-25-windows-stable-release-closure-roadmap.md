# Windows Stable Release Closure Roadmap Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the obsolete Month 7–8 preview-soak entry point with a resumable Windows-only G0–G6 release-closure roadmap and a self-contained private Codex handoff that stops at an independently auditable release-ready candidate.

**Architecture:** Tracked documentation defines durable scope, gates, estimates, and acceptance rules. An ignored repository-local handoff carries machine-local execution instructions and returns an ignored private handback. One Windows Codex task owns investigation, repair, source qualification, candidate assembly, installed-product testing, and endurance while publication remains a separate authorized action.

**Tech Stack:** Markdown, PowerShell 7, Python 3.12 `unittest`, Git, Windows x86-64, fixed local NTFS, Visual Studio Build Tools C++ workload, GitHub private releases, AO Mission

---

## File map

- Modify `docs/ROADMAP_MONTHS_7_12.md`: durable G0–G6 release-closure roadmap and retained Months 9–12 hardening gates.
- Reference `docs/superpowers/specs/2026-08-25-windows-stable-release-closure-design.md`: approved authority and acceptance design.
- Create `docs/superpowers/plans/2026-08-25-windows-stable-release-closure-roadmap.md`: this implementation plan.
- Create ignored `.local/handoffs/AO_OFFICE_POOL_WINDOWS_STABLE_RELEASE_HANDOFF.md`: executable Windows Codex prompt.
- Require ignored `.local/handoffs/AO_OFFICE_POOL_WINDOWS_STABLE_RELEASE_HANDBACK.md`: executor’s evidence-backed result.

## Execution topology

- Author and verify tracked documentation on branch
  `codex/windows-stable-release-closure-roadmap` in an isolated worktree.
- Write the ignored handoff in the primary repository’s `.local/handoffs/`
  directory so it survives disposal of the documentation worktree.
- Execute the handoff later in one capable Windows Codex task with the private
  repository selected as its workspace.
- Keep mutable qualification installs on a unique child of an operator-selected
  fixed local NTFS root. Do not put mutable installed state in the source tree,
  release tree, removable storage, a network share, WSL, or a Git worktree.
- Store raw evidence, AO Mission state, downloads, logs, receipts, and support
  bundles only under ignored repository-local or task-local private paths.

### Task 1: Establish the obsolete-roadmap RED

**Files:**
- Inspect: `docs/ROADMAP_MONTHS_7_12.md`
- Reference: `docs/superpowers/specs/2026-08-25-windows-stable-release-closure-design.md`

- [ ] **Step 1: Prove that the durable roadmap still names the obsolete candidate**

Run:

```powershell
rg -n 'developer-preview-v02|4bf8db6469a00dac69d2ddd7d103b501f797d7f6|Month 7: Private preview soak' docs/ROADMAP_MONTHS_7_12.md
```

Expected: matches identify the obsolete baseline and Month 7 entry point.

- [ ] **Step 2: Prove that the new release-closure gates are absent**

Run:

```powershell
$required = 'Gate G0','Gate G1','Gate G2','Gate G3','Gate G4','Gate G5','Gate G6','RELEASE_READY'
$text = Get-Content -Raw docs/ROADMAP_MONTHS_7_12.md
$missing = $required | Where-Object { -not $text.Contains($_) }
if ($missing.Count -ne $required.Count) { throw 'Roadmap RED is not clean: some new gates already exist.' }
```

Expected: exit `0`; all eight required markers are absent.

- [ ] **Step 3: Record the clean starting identity**

Run:

```powershell
git status --short
git rev-parse HEAD
git branch --show-current
```

Expected: clean status, the branch contains design commit `ee1bbf5`, and the
branch is `codex/windows-stable-release-closure-roadmap`.

### Task 2: Replace the immediate roadmap with G0–G6 release closure

**Files:**
- Modify: `docs/ROADMAP_MONTHS_7_12.md`
- Reference: `docs/superpowers/specs/2026-08-25-windows-stable-release-closure-design.md`

- [ ] **Step 1: Replace the accepted starting point and program framing**

Set the accepted source starting point to
`892538bb05a9578db62bd7d46f1f8c2ce8427fd4`, with an explicit rule that a later
commit is accepted only after its exact identity and clean-tree state are
recorded. Remove the obsolete `developer-preview-v02` archive as the active
candidate. State that the program produces a private release-ready candidate
and does not publish it.

- [ ] **Step 2: Add gates G0–G2**

Write observable entrance and exit requirements for:

```text
G0 identity/environment preflight
G1 instrumented cumulative-suite reproduction and repair
G2 compiler-complete Windows source qualification
```

G1 must bind the observed test-251 anomaly, require per-test duration and
timeout diagnostics, and distinguish harness correction from product repair.
G2 must require `windows-c-compiler=ready`, zero compiler-dependent skips,
classified remaining skips, schema/PowerShell parsing, scanner zero, bootstrap
verification, full suite success, and a clean tree.

- [ ] **Step 3: Add gates G3–G6**

Write observable entrance and exit requirements for:

```text
G3 checksum-bound real-stack candidate
G4 installed five-office product qualification
G5 eight-hour installed endurance campaign
G6 final audit and private handback
```

G3 must bind real AO2, AO Mission, AO Blueprint, skills, accessories, manifests,
provenance, SBOM, inventory, licenses, and checksums. G4 must reject fake or
source-substituted binaries. G5 requires 100 successful lifecycles, at least 20
per office, distributed work over eight elapsed hours, five-minute samples,
resource baselines, cleanup, and post-soak regression. G6 returns
`RELEASE_READY`, `REPAIR`, or `HOLD` and forbids publication.

- [ ] **Step 4: Retain Months 9–12 as later hardening**

Keep the existing Windows security, extended endurance, stable-candidate, and
private-publication themes, but state that they remain inactive until G6
returns `RELEASE_READY` and an independent audit accepts the handback. Remove
claims that the obsolete preview is their current accepted input.

- [ ] **Step 5: Add the approved effort estimate**

Include the eight-row active-effort/calendar-time table and these ranges:

```text
Optimistic: 4–6 working days
Likely: 1–2 weeks
Defect or binary blocker: 2–4 weeks
Planning commitment: two weeks with evidence-backed extension
```

- [ ] **Step 6: Verify roadmap content**

Run:

```powershell
$required = 'Gate G0','Gate G1','Gate G2','Gate G3','Gate G4','Gate G5','Gate G6','RELEASE_READY','eight elapsed hours','892538bb05a9578db62bd7d46f1f8c2ce8427fd4'
$text = Get-Content -Raw docs/ROADMAP_MONTHS_7_12.md
$missing = $required | Where-Object { -not $text.Contains($_) }
if ($missing) { throw "Roadmap missing: $($missing -join ', ')" }
if ($text -match 'accepted starting point is `developer-preview-v02`') { throw 'Obsolete active baseline remains.' }
```

Expected: exit `0`.

- [ ] **Step 7: Commit the durable roadmap**

Run:

```powershell
git add docs/ROADMAP_MONTHS_7_12.md
git diff --cached --check
git commit -m "docs: define Windows stable release closure"
```

Expected: one commit containing only the roadmap replacement.

### Task 3: Create the executable private Windows handoff

**Files:**
- Create, ignored: `.local/handoffs/AO_OFFICE_POOL_WINDOWS_STABLE_RELEASE_HANDOFF.md`
- Require, ignored: `.local/handoffs/AO_OFFICE_POOL_WINDOWS_STABLE_RELEASE_HANDBACK.md`
- Reference: `docs/ROADMAP_MONTHS_7_12.md`
- Reference: `docs/superpowers/specs/2026-08-25-windows-stable-release-closure-design.md`

- [ ] **Step 1: Define task authority and terminal objective**

The handoff must tell one Windows Codex task to create a Goal and continue
proactively through G0–G6. It authorizes documented compiler installation on
the designated engineering host, task-local process cleanup, focused RED/GREEN
repairs, commits on a task branch, candidate construction, private-release
read-only acquisition using existing credentials, installed-product testing,
and private evidence writes.

It must forbid publication, repository-visibility changes, direct mutation of
`main`, secret disclosure, invented replacement binaries, unrelated AO work,
and platform expansion.

- [ ] **Step 2: Define discovery and read order**

Require the executor to resolve the repository root with Git and read:

```text
AGENTS.md and applicable descendants
approved stable-release-closure design
durable Months 7–12 roadmap
this implementation plan
README.md and README-FIRST.md
AI operator runbook, operator guide, and pilot qualification
component lock, release manifest, public-tree manifest, schemas
this handoff
```

Require read-only reconciliation of `origin/main`, release metadata, existing
ignored candidates, source component checkouts, credentials presence, running
processes, filesystem health, and prior reports before accepting any input.

- [ ] **Step 3: Encode G0–G2 as closed control loops**

For each gate, define inputs, commands or discovery rules, evidence fields,
exit conditions, invalidation rules, and `PASS`/`REPAIR`/`HOLD` decisions.
Require the G1 reproduction ladder and actionable timeout behavior. Require G2
to execute compiler-dependent cases rather than accepting skips.

- [ ] **Step 4: Encode G3–G5 as closed control loops**

Require authoritative acquisition of every real component, deterministic
candidate construction, two-tree comparison, clean installed-product testing,
and the eight-hour mixed endurance workload. The handoff must never hardcode a
new candidate hash before G3 creates and verifies it.

For long-running work, prohibit blocking waits longer than 60 seconds. Require
a persistent runner, bounded polling, hourly progress summaries, crash-safe
checkpoints, and resume without resetting elapsed evidence.

- [ ] **Step 5: Encode repair, candidate invalidation, and blocker handling**

Use one behavior-focused RED for each demonstrated defect, the smallest GREEN,
focused regression, and the complete affected suite. Product-byte changes
create a new immutable candidate and rerun dependent gates. Harness-only changes
rerun affected evidence without relabeling product bytes. `HOLD` requires an
external prerequisite, exhausted safe alternatives, and an exact next action.

- [ ] **Step 6: Define G6 and the required handback**

Require `.local/handoffs/AO_OFFICE_POOL_WINDOWS_STABLE_RELEASE_HANDBACK.md` to
contain:

```text
Goal and AO Mission identities and final status
accepted source commit, task branch, and clean-tree state
host, volume, toolchain, compiler, privilege, and credential preflight
G1 reproduction matrix, per-test timings, timeout evidence, cause, and repairs
G2 commands, test counts, skips by class, durations, exits, and parse/scan results
all component source/release identities, names, sizes, and SHA-256 values
candidate archive, manifest, inventory, provenance, SBOM, license, and checksum identities
G4 installed lifecycle matrix for five offices, components, skills, and accessories
G5 start/end/elapsed time, per-office counts, failures, latency/throughput, resources, and residue
all repair commits and candidate invalidations, or an explicit none statement
cleanup and unknown-residue disposition
AO Mission checkpoint and reconciliation digests
terminal RELEASE_READY, REPAIR, or HOLD recommendation
exact next action and explicit statement that publication did not occur
```

- [ ] **Step 7: Verify the private handoff**

Run from the primary repository:

```powershell
git check-ignore -q .local/handoffs/AO_OFFICE_POOL_WINDOWS_STABLE_RELEASE_HANDOFF.md
$text = Get-Content -Raw .local/handoffs/AO_OFFICE_POOL_WINDOWS_STABLE_RELEASE_HANDOFF.md
$required = 'Create a Goal','Gate G0','Gate G1','Gate G2','Gate G3','Gate G4','Gate G5','Gate G6','eight elapsed hours','RELEASE_READY','Do not publish','AO_OFFICE_POOL_WINDOWS_STABLE_RELEASE_HANDBACK.md'
$missing = $required | Where-Object { -not $text.Contains($_) }
if ($missing) { throw "Handoff missing: $($missing -join ', ')" }
git status --short
```

Expected: handoff is ignored, all markers exist, and it does not appear in Git
status.

### Task 4: Verify privacy, consistency, and execution readiness

**Files:**
- Verify: `docs/ROADMAP_MONTHS_7_12.md`
- Verify: `docs/superpowers/specs/2026-08-25-windows-stable-release-closure-design.md`
- Verify: `docs/superpowers/plans/2026-08-25-windows-stable-release-closure-roadmap.md`
- Verify, ignored: `.local/handoffs/AO_OFFICE_POOL_WINDOWS_STABLE_RELEASE_HANDOFF.md`

- [ ] **Step 1: Run tracked privacy and bootstrap checks**

Run:

```powershell
$env:PYTHONDONTWRITEBYTECODE = '1'
python -B scripts/scan_public_tree.py .
python -B scripts/verify_bootstrap_contract.py .
python -B -m unittest tests.test_scan_public_tree tests.test_bootstrap_contract -v
Remove-Item Env:PYTHONDONTWRITEBYTECODE
```

Expected: scanner zero findings, bootstrap 13 members and 5 documents, focused
tests `OK` with only privilege-dependent skips.

- [ ] **Step 2: Parse and inspect the documentation**

Run:

```powershell
$tokens = @('T' + 'BD', 'T' + 'ODO', 'implement ' + 'later', 'fill in ' + 'details')
$files = @('docs/ROADMAP_MONTHS_7_12.md', 'docs/superpowers/specs/2026-08-25-windows-stable-release-closure-design.md', 'docs/superpowers/plans/2026-08-25-windows-stable-release-closure-roadmap.md')
foreach ($token in $tokens) { rg -n -F $token $files }
rg -n 'automatic publish|change visibility|macOS qualification|Linux qualification|accepted starting point is `developer-preview-v02`' docs/ROADMAP_MONTHS_7_12.md docs/superpowers/specs/2026-08-25-windows-stable-release-closure-design.md
git diff --check
```

Expected: no placeholder or stale-positive-scope matches; any platform or
publication term appears only as an explicit denial; diff check is clean.

- [ ] **Step 3: Inspect every tracked change and private boundary**

Run:

```powershell
git status --short
git diff main...HEAD -- docs/ROADMAP_MONTHS_7_12.md docs/superpowers/specs docs/superpowers/plans
git check-ignore -v .local/handoffs/AO_OFFICE_POOL_WINDOWS_STABLE_RELEASE_HANDOFF.md
```

Expected: tracked changes are limited to the approved design, plan, and roadmap;
the handoff is ignored; no receipt, credential, log, live state, absolute
developer path, or private model output is tracked.

- [ ] **Step 4: Verify the implementation-plan commit**

Run:

```powershell
git log -1 --format='%H %s' -- docs/superpowers/plans/2026-08-25-windows-stable-release-closure-roadmap.md
git status --short
```

Expected: the plan is owned by commit `docs: plan Windows stable release
closure` and tracked status is clean.

### Task 5: Produce the execution package

**Files:**
- Read: `.local/handoffs/AO_OFFICE_POOL_WINDOWS_STABLE_RELEASE_HANDOFF.md`
- Read: `docs/ROADMAP_MONTHS_7_12.md`

- [ ] **Step 1: Calculate the handoff identity**

Run from the primary repository:

```powershell
$handoff = Resolve-Path .local/handoffs/AO_OFFICE_POOL_WINDOWS_STABLE_RELEASE_HANDOFF.md
$hash = (Get-FileHash -LiteralPath $handoff -Algorithm SHA256).Hash.ToLowerInvariant()
Get-Item -LiteralPath $handoff | Select-Object FullName,Length,LastWriteTime
$hash
```

Expected: one resolved ignored file and one 64-character SHA-256 value.

- [ ] **Step 2: Record the branch and commit chain**

Run:

```powershell
git log --oneline --decorate main..HEAD
git status --short
```

Expected: design, roadmap, and plan commits are present; tracked status is
clean.

- [ ] **Step 3: Return the execution recommendation**

Return the roadmap branch, commit identities, handoff path, length, SHA-256,
and this recommendation:

```text
Execute the handoff in one new capable Windows Codex task after integrating the tracked roadmap branch. Use a compiler-ready engineering environment for source qualification and a clean customer-like NTFS installation root for runtime qualification. Continue through G0–G6, but stop at RELEASE_READY and return the private handback for independent final audit. Do not publish from the execution task.
```
