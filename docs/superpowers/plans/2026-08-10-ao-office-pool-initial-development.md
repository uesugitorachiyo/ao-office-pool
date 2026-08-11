# AO Office Pool Initial Development Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and qualify a Windows-native five-office coordination layer over a shared, version-pinned AO stack.

**Architecture:** AO Mission accepts objectives after an office claim and routes governed work through the existing AO components. The product shares immutable component packages, gives O1-O5 independent AO2 runtime copies, and stores durable mission state in each connected project's `.ao/` directory.

**Tech Stack:** Python 3.12 standard library for the initial control plane and tests, PowerShell 7 for Windows packaging, native AO component executables, JSON schemas, GitHub Actions Windows runners.

## Global Constraints

- macOS construction folders are staging surfaces only.
- Production qualification runs from a fixed path on a local Windows NTFS volume.
- Public files contain no prompts, receipts, recovery data, owner identifiers, or absolute local project paths.
- AO Mission records and routes; it does not execute, approve policy, call providers, or mutate repositories.
- AO2 is the bounded execution runtime.
- The product has exactly five offices, O1 through O5, and no automatic queue.
- Component and runtime identity uses exact version, digest, and provenance records.
- Runtime activation requires all offices to be free and rolls back on partial failure.
- Use Python and PowerShell standard features before adding a dependency.

---

### Task 1: Public repository boundary and leak scanner

**Files:**
- Create: `scripts/scan_public_tree.py`
- Create: `tests/test_scan_public_tree.py`
- Create: `.github/workflows/verify.yml`
- Modify: `.gitignore`

**Interfaces:**
- Consumes: repository root path.
- Produces: `scan_tree(root: Path) -> list[Finding]`, where `Finding` is a frozen dataclass with `path`, `rule`, and `detail` strings.

- [ ] **Step 1: Write tests that create a clean tree and trees containing `.env`, receipt JSON, recovery keys, macOS paths, Windows user paths, and token-shaped text.**
- [ ] **Step 2: Run `python -m unittest tests.test_scan_public_tree -v` and confirm the missing scanner fails the suite.**
- [ ] **Step 3: Implement a single filesystem walk with an allowlisted text decoder, explicit forbidden basenames, local-path patterns, and conservative secret patterns. Skip `.git` without following links.**
- [ ] **Step 4: Run `python -m unittest tests.test_scan_public_tree -v` and confirm every fixture passes.**
- [ ] **Step 5: Add a Windows and macOS GitHub Actions matrix that runs the scanner and `python -m unittest discover -s tests -v`.**
- [ ] **Step 6: Commit with `git commit -m "build: enforce public repository boundary"`.**

### Task 2: Component lock and source verification

**Files:**
- Create: `manifests/components.lock.json`
- Create: `scripts/verify_components.py`
- Create: `tests/test_verify_components.py`

**Interfaces:**
- Consumes: lock records with `name`, `repository`, `commit`, `release`, `asset`, and `sha256`.
- Produces: `verify_lock(path: Path, component_root: Path) -> dict[str, str]` mapping component names to verified commits.

- [ ] **Step 1: Write tests for duplicate names, malformed commits, non-HTTPS repositories, missing assets, wrong SHA-256 values, unknown fields, and a valid two-component fixture.**
- [ ] **Step 2: Run `python -m unittest tests.test_verify_components -v` and confirm failure because the verifier does not exist.**
- [ ] **Step 3: Implement strict JSON parsing, exact field sets, SHA-256 streaming, and component-root containment with `json`, `hashlib`, and `pathlib`.**
- [ ] **Step 4: Pin AO Mission, AO2, AO Blueprint, AO Atlas, AO Foundry, AO Forge, AO Covenant, AO Command, AO Arena, AO Crucible, AO Sentinel, AO Promoter, and AO2 Control Plane only after their release assets and licenses are verified.**
- [ ] **Step 5: Run the component verifier and complete unit suite on macOS and Windows.**
- [ ] **Step 6: Commit with `git commit -m "build: pin AO component identities"`.**

### Task 3: Windows-safe path and identity model

**Files:**
- Create: `internal/windows_paths.py`
- Create: `tests/test_windows_paths.py`

**Interfaces:**
- Produces: `validate_segment(value: str) -> str`, `canonical_windows_path(value: str) -> PureWindowsPath`, and `is_within(child: str, parent: str) -> bool`.
- Denies: reserved device names, control characters, trailing spaces or periods, traversal, ambiguous roots, and unsupported path forms.

- [ ] **Step 1: Write a table-driven test corpus covering drive paths, UNC paths, extended paths, mixed separators, case differences, `CON`, `NUL`, `COM1`, `LPT9`, trailing dots, 8.3 aliases, and parent traversal.**
- [ ] **Step 2: Run `python -m unittest tests.test_windows_paths -v` and confirm failure.**
- [ ] **Step 3: Implement lexical validation with `pathlib.PureWindowsPath`; keep physical identity checks in the Windows adapter because macOS cannot prove NTFS identity.**
- [ ] **Step 4: Add Windows-only tests that resolve final handles and reject junction, reparse-point, and hard-link escapes.**
- [ ] **Step 5: Run the path suite on Windows and macOS, with Windows-only tests explicitly skipped on macOS.**
- [ ] **Step 6: Commit with `git commit -m "feat: add Windows path safety model"`.**

### Task 4: Five-office ownership lifecycle

**Files:**
- Create: `internal/pool.py`
- Create: `schemas/pool.schema.json`
- Create: `schemas/office-state.schema.json`
- Create: `schemas/claim-receipt.schema.json`
- Create: `tests/test_pool.py`

**Interfaces:**
- Produces: `Pool.initialize(count: int = 5)`, `Pool.claim(owner_id, project_root, mode)`, `Pool.resume(owner_id, project_root)`, `Pool.release(receipt_path)`, and `Pool.public_status()`.
- Persists: `pool.json`, `offices/O1` through `offices/O5`, private receipts, and resume pointers.

- [ ] **Step 1: Write tests for exactly five offices, atomic first-free claim, sixth-claim failure, stale generation rejection, cross-owner rejection, cross-project rejection, and residue preservation.**
- [ ] **Step 2: Run `python -m unittest tests.test_pool -v` and confirm failure.**
- [ ] **Step 3: Implement atomic JSON replacement and one pool lock with standard-library file APIs plus the platform-specific lock primitive.**
- [ ] **Step 4: Store receipt secrets only under `operator-secrets`; return receipt paths rather than secret values from the normal CLI.**
- [ ] **Step 5: Run repeated concurrent claim and release tests on Windows. Confirm five unique winners and one clear full-capacity result.**
- [ ] **Step 6: Commit with `git commit -m "feat: add five-office lifecycle"`.**

### Task 5: Connected-project state and AO Mission bridge

**Files:**
- Create: `internal/mission_bridge.py`
- Create: `schemas/project-binding.schema.json`
- Create: `tests/test_mission_bridge.py`
- Create: `templates/AO_OFFICE_POOL_TASK_TEMPLATE.txt`

**Interfaces:**
- Consumes: an active receipt, objective text, AO Mission executable identity, and connected-project root.
- Produces: `start_or_resume(receipt: Path, objective: str) -> MissionReadback` with mission id, objective digest, status, route, and next action.
- Stores: durable records under `<connected-project>/.ao/mission/`.

- [ ] **Step 1: Write tests proving one objective creates one digest-bound mission, repeated same-owner intake resumes it, another project is rejected, and Mission cannot request execution authority.**
- [ ] **Step 2: Run `python -m unittest tests.test_mission_bridge -v` and confirm failure.**
- [ ] **Step 3: Implement argument-array process launch without a shell, exact executable hash verification, bounded output capture, and project-root containment.**
- [ ] **Step 4: Add cancellation and replacement transitions that checkpoint the mission before releasing the office.**
- [ ] **Step 5: Run the focused tests with a deterministic fake Mission executable, then run the native Windows Mission identity and smoke test.**
- [ ] **Step 6: Commit with `git commit -m "feat: route office work through AO Mission"`.**

### Task 6: Blueprint and Atlas planning routes

**Files:**
- Create: `internal/planning_routes.py`
- Create: `tests/test_planning_routes.py`
- Create: `schemas/route-policy.schema.json`

**Interfaces:**
- Produces: `select_route(mission: MissionReadback) -> RouteDecision`.
- Routes underspecified objectives to Blueprint and oversized, mutation-class, or long-running authorized objectives to Atlas.

- [ ] **Step 1: Write route tests for bounded work, missing requirements, oversized work, mutation-class work, long-running work, and blocked authorization.**
- [ ] **Step 2: Run `python -m unittest tests.test_planning_routes -v` and confirm failure.**
- [ ] **Step 3: Implement a fixed rule table. Do not create a plugin system or configurable expression language.**
- [ ] **Step 4: Validate Blueprint authorization digests and Atlas workgraph/context-pack references before returning build-ready status.**
- [ ] **Step 5: Run the route suite and native Windows identity smoke tests for Blueprint and Atlas.**
- [ ] **Step 6: Commit with `git commit -m "feat: add governed planning routes"`.**

### Task 7: Governed AO2 execution

**Files:**
- Create: `internal/execution.py`
- Create: `tests/test_execution.py`
- Create: `schemas/execution-record.schema.json`

**Interfaces:**
- Consumes: active receipt, Covenant decision, Forge packet, AO2 arguments, and connected-project target.
- Produces: `execute(request: ExecutionRequest) -> ExecutionResult` with exit code, artifact references, evidence digest, and sanitized diagnostics.

- [ ] **Step 1: Write tests for valid execution, wrong receipt, wrong generation, wrong project, pool target, sibling-project target, path-option escape, shell metacharacters, timeout, and runtime tampering.**
- [ ] **Step 2: Run `python -m unittest tests.test_execution -v` and confirm failure.**
- [ ] **Step 3: Implement receipt validation, Covenant digest checks, executable hash verification, argument-array launch, timeout, and bounded output capture.**
- [ ] **Step 4: Write private execution history under the office and export only allowlisted evidence references to the connected project.**
- [ ] **Step 5: Run the execution suite with a fake executable, followed by the native Windows AO2 smoke test.**
- [ ] **Step 6: Commit with `git commit -m "feat: execute receipt-bound AO2 work"`.**

### Task 8: Runtime stage, activation, and rollback

**Files:**
- Create: `internal/runtime_update.py`
- Create: `tests/test_runtime_update.py`
- Create: `schemas/runtime-package.schema.json`

**Interfaces:**
- Produces: `stage(candidate: Path) -> StagedRuntime`, `activate(version: str) -> ActivationResult`, and `rollback(version: str) -> ActivationResult`.

- [ ] **Step 1: Write tests for malformed manifests, wrong hashes, unsafe version segments, occupied-office activation, five equal independent copies, interruption at each office, and prior-version restoration.**
- [ ] **Step 2: Run `python -m unittest tests.test_runtime_update -v` and confirm failure.**
- [ ] **Step 3: Implement staging into a temporary sibling directory, full verification, atomic rename, and one all-office activation transaction under the pool lock.**
- [ ] **Step 4: On failure, restore every prior office state and remove partial hidden staging while retaining a sanitized attempt record.**
- [ ] **Step 5: Run interruption injection across O1-O5 on Windows and compare every runtime tree byte-for-byte.**
- [ ] **Step 6: Commit with `git commit -m "feat: add transactional runtime updates"`.**

### Task 9: Public readback, evaluation, and support exports

**Files:**
- Create: `internal/readback.py`
- Create: `internal/support_bundle.py`
- Create: `tests/test_readback.py`
- Create: `tests/test_support_bundle.py`

**Interfaces:**
- Produces: `public_status() -> PublicPoolStatus`, `protected_status(receipt: Path) -> ProtectedStatus`, and `build_support_bundle(output: Path) -> Path`.

- [ ] **Step 1: Write tests that seed owner ids, prompts, receipts, recovery keys, absolute paths, and private histories, then prove none appear in public status or support archives.**
- [ ] **Step 2: Run the focused test modules and confirm failure.**
- [ ] **Step 3: Implement explicit output allowlists. Do not sanitize arbitrary dictionaries recursively and assume the result is safe.**
- [ ] **Step 4: Bind Arena, Crucible, Sentinel, Promoter, Command, and Mission readbacks by exact evidence digest without granting execution authority.**
- [ ] **Step 5: Run the leak scanner against generated status, bundles, and evaluation fixtures.**
- [ ] **Step 6: Commit with `git commit -m "feat: add safe status and support exports"`.**

### Task 10: Windows packaging and final qualification

**Files:**
- Create: `packaging/Install-AOOfficePool.ps1`
- Create: `packaging/Verify-AOOfficePool.ps1`
- Create: `packaging/Uninstall-AOOfficePool.ps1`
- Create: `scripts/build_release.py`
- Create: `tests/test_release_package.py`
- Create: `docs/OPERATOR_GUIDE.md`

**Interfaces:**
- Produces: `ao-office-pool-v1.2.0-windows-x86_64.zip`, `SHA256SUMS`, SBOM, provenance, and qualification report.

- [ ] **Step 1: Write archive tests for exact allowlisted paths, normalized separators, deterministic metadata, forbidden private files, changed component hashes, and unsafe links.**
- [ ] **Step 2: Run `python -m unittest tests.test_release_package -v` and confirm failure.**
- [ ] **Step 3: Implement deterministic ZIP construction with Python's `zipfile`; PowerShell installs only after checksum, manifest, path, and NTFS checks pass.**
- [ ] **Step 4: Run clean-room install, five-office claim/execution/release, update, rollback, support export, and uninstall on a fresh Windows host.**
- [ ] **Step 5: Run the complete qualification twice against unchanged inputs and have an independent evaluator reproduce it.**
- [ ] **Step 6: Commit with `git commit -m "release: qualify AO Office Pool v1.2.0"` only after the owner approves the license and public release.**
