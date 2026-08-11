# AO Office Pool v1.2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and independently qualify a public Windows v1.2.0 release with five isolated AO offices, governed AO Mission intake, receipt-bound AO2 execution, and a lean portable skill package.

**Architecture:** A small coordination layer owns O1–O5 state, receipts, Windows identity, runtime activation, and public-safe readback. Shared immutable AO packages sit outside offices; each office has an independent equal AO2 runtime. Durable mission and evidence state stays in the connected project's `.ao/` tree.

**Tech Stack:** Python 3 standard library for portable coordination and release tooling, PowerShell 7-compatible packaging commands, native Windows file APIs for NTFS identity and locks, upstream AO executables, JSON schemas, and GitHub Actions Windows/macOS runners.

## Global Constraints

- macOS and external-drive paths are staging surfaces only.
- Production qualification runs from a fixed path on a local Windows NTFS volume.
- Public files contain no prompts, receipts, recovery data, owner identifiers, absolute local paths, office state, or private support data.
- AO Mission records and routes; it does not execute, approve policy, call providers, publish, deploy, or mutate repositories.
- AO2 is the receipt-bound execution runtime.
- The product has exactly five offices, O1 through O5, and no automatic queue.
- Component readiness distinguishes source-present, asset-verified, patched, executable-tested, accepted, activated, and routed.
- Runtime activation requires all offices free and rolls back on partial failure.
- Every `SKILL.md` has at most 200 physical lines and only `name` and `description` in frontmatter.
- Reimplement predecessor behavior through contracts and tests; do not copy predecessor code, state, private paths, or acceptance claims.
- Months 1–6 end at a private developer preview. Public v1.2.0 qualification occurs in months 11–12.
- Use standard-library and native platform features before adding a dependency.

---

### Task 0: Materialized repository and AO stack layout

**Files:**
- Create: `docs/STACK_LAYOUT.md`
- Create: `manifests/stack-layout.json`
- Create: `manifests/public-tree.json`
- Create: `.github/workflows/.gitkeep`
- Create: `cmd/.gitkeep`
- Create: `internal/.gitkeep`
- Create: `schemas/.gitkeep`
- Create: `skills/.gitkeep`
- Create: `scripts/.gitkeep`
- Create: `tests/.gitkeep`
- Create: `packaging/windows/.gitkeep`
- Modify: `.gitignore`
- Modify: `.local/handoffs/AO_MISSION_HANDOFF.md`

**Interfaces:**
- AO Mission working directory: repository root `.`.
- AO Mission component checkout: `.local/sources/ao-mission`; never the mission working directory.
- Durable project mission state: `.ao/mission`.
- Local AO source root: `.local/sources`.
- Windows package staging root: `.local/staging/windows-x86_64`.
- Public GitHub boundary: `manifests/public-tree.json`.

- [x] Materialize all tracked roots, fourteen ignored AO source directories, thirteen shared component staging directories, O1–O5 runtime/history/work directories, and connected-project `.ao/` state roots.
- [x] Confirm `manifests/stack-layout.json` contains exactly fourteen source components, thirteen shared Windows components, O1–O5, and `ao2` as the office-local runtime component.
- [x] Confirm every excluded root, name, and pattern in `manifests/public-tree.json` has a matching `.gitignore` rule or an ignored parent.
- [x] Run `git check-ignore` against `.local/sources/ao-mission`, `.local/staging/windows-x86_64/offices/O1/work`, `.ao/mission`, `offices/O1`, and `operator-secrets`; every path must report ignored.
- [x] Run a tracked-file root audit; every candidate public file must be a listed root file or live under a listed tracked root.
- [x] Commit with `git commit -m "build: materialize repository and AO stack layout"` before executing Task 1.

### Task 1: Requirement inheritance and source locks

**Files:**
- Create: `manifests/components.lock.json`
- Create: `manifests/requirements.json`
- Create: `scripts/verify_components.py`
- Create: `scripts/verify_requirements.py`
- Create: `tests/test_verify_components.py`
- Create: `tests/test_verify_requirements.py`

**Interfaces:**
- Produces: `verify_lock(path: Path, component_root: Path) -> dict[str, str]`.
- Produces: `verify_requirements(path: Path) -> dict[str, Requirement]`.
- Requires: one row for every V1.1 inheritance invariant and B01–B19, each with a unique test id and release phase.

- [ ] Write failing tests for duplicate component names, malformed commits, non-HTTPS repositories, missing licenses, wrong SHA-256 values, unknown fields, duplicate requirement ids, missing test ids, and missing B01–B19 rows.
- [ ] Run `python -m unittest tests.test_verify_components tests.test_verify_requirements -v`; confirm both modules fail because the verifiers do not exist.
- [ ] Implement strict JSON field sets, streaming SHA-256, repository validation, component-root containment, exact requirement-id sets, and nonempty test bindings with `json`, `hashlib`, `urllib.parse`, and `pathlib`.
- [ ] Pin AO Mission, AO2, Blueprint, Atlas, Foundry, Forge, Covenant, Command, Arena, Crucible, Sentinel, Promoter, Control Plane, and AO Architecture only after source, asset, license, and digest review.
- [ ] Run the focused tests on macOS and Windows and commit with `git commit -m "build: bind inherited requirements and sources"`.

### Task 2: Public boundary and deterministic release tree

**Files:**
- Create: `scripts/scan_public_tree.py`
- Create: `scripts/build_release.py`
- Create: `tests/test_scan_public_tree.py`
- Create: `tests/test_release_tree.py`
- Create: `.github/workflows/verify.yml`
- Modify: `.gitignore`

**Interfaces:**
- Produces: `scan_tree(root: Path) -> list[Finding]` where `Finding` has `path`, `rule`, and `detail`.
- Produces: `build_release(source: Path, output: Path, allowlist: Path) -> Path`.

- [ ] Write failing fixtures for `.env`, receipt JSON, recovery keys, owner fields, prompt text, macOS and Windows user paths, unsafe links, duplicate ZIP names, parent paths, and nondeterministic timestamps.
- [ ] Run `python -m unittest tests.test_scan_public_tree tests.test_release_tree -v`; confirm the scanner and builder are missing.
- [ ] Implement one non-link-following tree walk, explicit forbidden basenames, conservative secret/path patterns, exact release allowlisting, normalized ZIP metadata, and deterministic ordering with standard-library modules.
- [ ] Add macOS and Windows CI jobs that run the scanner, requirement verifiers, and `python -m unittest discover -s tests -v`.
- [ ] Prove `.local/`, `.ao/`, offices, runtime state, receipts, and support data are ignored, then commit with `git commit -m "build: enforce the public repository boundary"`.

### Task 3: Windows path and file-identity boundary

**Files:**
- Create: `internal/windows_paths.py`
- Create: `internal/windows_identity.py`
- Create: `tests/test_windows_paths.py`
- Create: `tests/test_windows_identity.py`

**Interfaces:**
- Produces: `validate_segment(value: str) -> str`.
- Produces: `canonical_windows_path(value: str) -> PureWindowsPath`.
- Produces: `open_identity(path: Path) -> FileIdentity` and `require_within(child: FileIdentity, root: FileIdentity) -> None`.

- [ ] Write a table-driven lexical corpus for drive, UNC, extended, mixed-separator, case-folded, reserved-name, trailing-dot, 8.3, traversal, and long-path inputs.
- [ ] Write Windows-only physical tests for junction, reparse-point, hard-link, symlink, alias, and delete/recreate escapes.
- [ ] Run `python -m unittest tests.test_windows_paths tests.test_windows_identity -v`; confirm missing APIs fail and physical tests skip on macOS.
- [ ] Implement lexical checks with `PureWindowsPath` and physical checks through Windows handles; compare volume and file identity rather than string prefixes.
- [ ] Run the full corpus on Windows, confirm no physical test skips, and commit with `git commit -m "feat: enforce Windows path and file identity"`.

### Task 4: Five-office ownership, release, and recovery

**Files:**
- Create: `internal/pool.py`
- Create: `internal/transactions.py`
- Create: `schemas/pool.schema.json`
- Create: `schemas/office-state.schema.json`
- Create: `schemas/claim-receipt.schema.json`
- Create: `tests/test_pool.py`
- Create: `tests/test_pool_crash.py`

**Interfaces:**
- Produces: `Pool.initialize(count: int = 5)`, `Pool.claim(owner_id, task_id, project_root, mode)`, `Pool.resume(receipt_path)`, `Pool.release(receipt_path)`, `Pool.recover(key_path, office_id, generation)`, and `Pool.public_status()`.
- Persists: `pool.json`, O1–O5 state, private receipts, resume pointers, transaction journals, and sanitized recovery records.

- [ ] Write failing tests for atomic first-free claims, sixth-claim failure, required project binding, stale generation, wrong owner/task/project, missing pointer reconciliation, raw-key non-disclosure, dirty release, emergency recovery, and non-expiring pinning.
- [ ] Add crash injection after each office, receipt, pointer, and journal transition; assert restart reaches the prior accepted state or `recovery-required` without losing unknown bytes.
- [ ] Run `python -m unittest tests.test_pool tests.test_pool_crash -v`; confirm lifecycle APIs are absent.
- [ ] Implement one pool lock, monotonic generations, receipt-only output, an atomic owner registry, journaled closeout, explicit recovery state, and exact-field public constructors.
- [ ] Run repeated six-claim and release/recovery races on Windows, then commit with `git commit -m "feat: add crash-safe five-office ownership"`.

### Task 5: AO Mission intake and project-owned context

**Files:**
- Create: `internal/mission_bridge.py`
- Create: `internal/conversation_lifecycle.py`
- Create: `schemas/mission-record.schema.json`
- Create: `schemas/context-handoff.schema.json`
- Create: `templates/AO_OFFICE_POOL_TASK_TEMPLATE.txt`
- Create: `tests/test_mission_bridge.py`
- Create: `tests/test_conversation_lifecycle.py`

**Interfaces:**
- Produces: `start_or_resume(receipt: Path, objective: str) -> MissionReadback`.
- Produces: `transition(event: ConversationEvent, state: ConversationState) -> Transition`.
- Stores durable records only under `<connected-project>/.ao/`.

- [ ] Write failing tests for bounded conversation, explicit long-task pinning, same-task resume proof, cross-chat denial, no-file completion, Goal-state conflict, cancellation, replacement, compression recovery, and Mission authority escalation.
- [ ] Run `python -m unittest tests.test_mission_bridge tests.test_conversation_lifecycle -v`; confirm the bridge and lifecycle are missing.
- [ ] Implement exact executable-hash verification, argument-array launch, bounded output capture, digest-bound mission records, fixed transition rules, and compact handoff schemas.
- [ ] Checkpoint cancel or replacement before exact release; stop when platform Goal and local Mission state disagree.
- [ ] Run fake-executable tests and a native Windows Mission identity smoke test, then commit with `git commit -m "feat: route project conversations through AO Mission"`.

### Task 6: Planning routes and governed AO2 execution

**Files:**
- Create: `internal/planning_routes.py`
- Create: `internal/execution.py`
- Create: `schemas/route-decision.schema.json`
- Create: `schemas/execution-record.schema.json`
- Create: `tests/test_planning_routes.py`
- Create: `tests/test_execution.py`

**Interfaces:**
- Produces: `select_route(mission: MissionReadback) -> RouteDecision`.
- Produces: `execute(request: ExecutionRequest) -> ExecutionResult`.
- Requires: Blueprint authorization, Atlas workgraph validation when routed, Forge packet, Covenant decision, active receipt, and connected-project target.

- [ ] Write failing route tests for bounded, underspecified, oversized, mutation-class, long-running, blocked, and source-only capability cases.
- [ ] Write failing execution tests for wrong receipt/generation/project, pool and sibling targets, path-option escape, shell metacharacters, timeout, runtime tampering, and Covenant digest mismatch.
- [ ] Run `python -m unittest tests.test_planning_routes tests.test_execution -v`; confirm both APIs are absent.
- [ ] Implement a fixed rule table, strict evidence schemas, argument-array AO2 launch, timeout, executable-hash checks, Windows file-identity containment, and allowlisted diagnostics.
- [ ] Run deterministic fakes and native Windows AO2 smoke tests, then commit with `git commit -m "feat: add governed AO planning and execution"`.

### Task 7: Runtime activation, evidence binding, and safe exports

**Files:**
- Create: `internal/runtime_update.py`
- Create: `internal/qualification.py`
- Create: `internal/readback.py`
- Create: `internal/support_bundle.py`
- Create: `schemas/runtime-package.schema.json`
- Create: `schemas/qualification-record.schema.json`
- Create: `tests/test_runtime_update.py`
- Create: `tests/test_qualification.py`
- Create: `tests/test_readback.py`

**Interfaces:**
- Produces: `stage(candidate: Path)`, `activate(version: str)`, `rollback(version: str)`, and `promote(evidence_set: Path, state: str)`.
- Produces: exact-field public, protected, and support-bundle records.

- [ ] Write failing tests for unsafe versions, malformed manifests, occupied activation, substitution of executable plus manifest, interruption at O1–O5, semantic evidence omissions, nonexistent test bindings, non-durable promotion, and private export seeds.
- [ ] Run the three focused test modules and confirm failure.
- [ ] Implement independent trust-anchor checks, temporary sibling staging, all-office transaction journals, complete restoration, semantic-input fingerprints, exact assertion-set checks, and atomic hash-bound qualification records.
- [ ] Build public and support outputs from explicit schemas; never recursively sanitize arbitrary private dictionaries.
- [ ] Run Windows interruption injection and the leak scanner against every generated export, then commit with `git commit -m "feat: add transactional updates and evidence-bound qualification"`.

### Task 8: Months 1–6 Windows developer preview

**Files:**
- Create: `packaging/Install-AOOfficePool.ps1`
- Create: `packaging/Verify-AOOfficePool.ps1`
- Create: `packaging/Uninstall-AOOfficePool.ps1`
- Create: `tests/test_pilot_matrix.py`
- Create: `docs/OPERATOR_GUIDE.md`
- Create: `docs/PILOT_QUALIFICATION.md`

**Interfaces:**
- Produces: a private `developer-preview` archive, checksums, SBOM, provenance, B01–B19 ledger, and pilot qualification record.

- [ ] Bind every V1.1 invariant, B01–B19 row, and P01–P76-equivalent assertion to an existing test function.
- [ ] Run `python -m unittest tests.test_pilot_matrix -v`; confirm failure until the exact set and all evidence files exist.
- [ ] Implement PowerShell install, verify, update, rollback, and uninstall with checksum, manifest, NTFS, path, and all-free checks.
- [ ] Run two clean Windows installations, six-claim concurrency, five-office execution, interruption rollback, emergency recovery, support export, and uninstall against unchanged bytes.
- [ ] Record independent reproduction, label the archive `developer-preview`, and commit with `git commit -m "release: qualify private Windows developer preview"`.

### Task 9: Lean product skills and instruction surfaces

**Files:**
- Create: `skills/ao2-approval-policy/SKILL.md`
- Create: `skills/ao2-evidence-closure/SKILL.md`
- Create: `skills/ao2-pulse-operator/SKILL.md`
- Create: `skills/ao2-rsi-operator/SKILL.md`
- Create: `skills/thought-experiment/SKILL.md`
- Create: `skills/engineering-research/SKILL.md`
- Create: `skills/scope-to-deliverable-workflow/SKILL.md`
- Create: `scripts/validate_skills.py`
- Create: `tests/test_validate_skills.py`
- Create: `tests/test_skill_routing.py`
- Create: `AGENTS.md`

**Interfaces:**
- Produces: `validate_skill(path: Path) -> list[Finding]` and `route_skill(request: str) -> tuple[str, ...]`.
- Enforces: at most 200 physical lines, frontmatter keys exactly `name` and `description`, lowercase-hyphen name, one-level references, and no private or project-contaminated text.

- [ ] Inventory candidate responsibilities and record `KEEP`, `UPDATE`, `MERGE`, `REPLACE`, `DELETE`, or `ADD`; update an existing responsibility before adding a new skill.
- [ ] Write failing validator tests for 201 lines, extra frontmatter, bad names, broken/deep references, duplicate content, absolute paths, user identities, stale versions, README files, and untested scripts.
- [ ] Write trigger-positive, trigger-negative, overlap, ordinary-task, heavy-task, and context-handoff behavior tests.
- [ ] Implement the smallest seven-skill package with detailed rubrics and examples in one-level references and deterministic repeated work in tested scripts.
- [ ] Measure root instructions below about 200 lines and 2,000 tokens, run both skill test modules, and commit with `git commit -m "feat: add lean portable AO skills"`.

### Task 10: Advanced AO activation, Pulse, RSI, and evaluation

**Files:**
- Create: `internal/capabilities.py`
- Create: `internal/evaluation.py`
- Create: `schemas/capability-status.schema.json`
- Create: `schemas/evaluation-chain.schema.json`
- Create: `tests/test_capabilities.py`
- Create: `tests/test_evaluation_chain.py`

**Interfaces:**
- Produces: truthful readiness records and digest-bound transitions among Pulse, RSI, Arena, Crucible, Sentinel, Promoter, Command, and Mission.

- [ ] Write failing tests that prevent source-only execution claims, unavailable-toolchain activation, evaluator execution, Promoter bypass, stale evidence, duplicate retry side effects, and public readback mutation.
- [ ] Run `python -m unittest tests.test_capabilities tests.test_evaluation_chain -v`; confirm missing integration fails.
- [ ] Implement exact readiness transitions, native executable identity replay, authority-separated evaluation records, Sentinel holds, Covenant bindings, and read-only Command output.
- [ ] Run provider-free deterministic fixtures plus native Windows smoke tests for every routed executable.
- [ ] Commit with `git commit -m "feat: activate the governed AO evaluation stack"`.

### Task 11: Windows endurance, recovery, and release security

**Files:**
- Create: `tests/test_windows_adversarial.py`
- Create: `tests/test_crash_matrix.py`
- Create: `scripts/run_endurance.py`
- Create: `SECURITY.md`
- Create: `docs/THREAT_MODEL.md`
- Create: `docs/ENDURANCE_REPORT.md`

**Interfaces:**
- Produces: repeatable 72-hour workload records, crash/recovery results, and the public security boundary.

- [ ] Write adversarial tests for ACLs, handles, junctions, reparse points, hard links, symlinks, 8.3 aliases, UNC and extended paths, process kills, disk pressure, and delete/recreate races.
- [ ] Run focused adversarial and crash tests before endurance; fix every deterministic failure at the shared boundary.
- [ ] Run a 72-hour five-office mixed workload with process and update faults, recording only sanitized metrics and evidence digests.
- [ ] Complete security review, threat model, dependency/SBOM audit, recovery drills, and support-bundle inspection; obtain owner approval before promoting the private security draft to root `SECURITY.md`.
- [ ] Confirm no unresolved release blocker and commit with `git commit -m "test: complete Windows endurance and security qualification"`.

### Task 12: Independent release candidate and public v1.2.0

**Files:**
- Create: `tests/test_release_qualification.py`
- Create: `docs/RELEASE_QUALIFICATION.md`
- Create: `docs/MIGRATION_FROM_V1_1.md`
- Modify: `docs/OPERATOR_GUIDE.md`
- Modify: `manifests/components.lock.json`

**Interfaces:**
- Produces: `ao-office-pool-v1.2.0-windows-x86_64.zip`, checksums, SBOM, provenance, notices, migration guide, and hash-bound release qualification.

- [ ] Freeze source and component identities; build the release candidate from a clean checkout with the deterministic allowlist builder.
- [ ] Run `python -m unittest discover -s tests -v` on clean macOS and Windows hosts, then run every Windows-only native, endurance-smoke, install, update, rollback, recovery, support, and uninstall gate.
- [ ] Have an independent evaluator repeat the full qualification twice against unchanged bytes and verify O1–O5 end free with zero task-output residue.
- [ ] Run the public-tree scanner against source and archive, verify every checksum/SBOM/provenance link, and atomically record `release-qualified` against the exact archive digest.
- [ ] After owner approval, tag and publish only the qualified bytes; commit final records with `git commit -m "release: qualify AO Office Pool v1.2.0"`.

## Execution boundary

Start with Task 1. Do not scaffold later task files before their inputs and gates
exist. Use one reviewable commit per task, rerun the narrow focused tests before
the full suite, and invalidate downstream qualification whenever a bound input
changes.
