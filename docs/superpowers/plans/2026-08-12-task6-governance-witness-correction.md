# Task 6 Governance Witness Correction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace caller-forgeable Task 6 authority with one Pool-private, one-use governance witness and close every finding in the Task 6 independent review.

**Architecture:** Keep the existing fixed route table and retained-path primitives. Add one `governance_witness` module that verifies the locked Blueprint, Atlas, Forge, and Covenant binaries and their native candidate artifacts while the Pool authority lock is held, then seals a short-lived envelope. `execute()` accepts only the receipt path, envelope path, and bounded timeout; it consumes the envelope under the same authority lease and launches retained AO2, workflow, and project objects.

**Tech Stack:** Python 3.12 standard library, existing `internal.mission_bridge` retained-object helpers, JSON Schema draft 2020-12 files with the existing local validator, `unittest`, native POSIX process groups, Windows Job Objects through `ctypes`.

## Global Constraints

- Base implementation commit is `5af397240092f5b5f17f732fd6005e2e3e024035`; the approved design commit is `cd32e5c`.
- Do not repin `manifests/components.lock.json`; verify the exact locked Blueprint, Atlas, Forge, Covenant, and AO2 component entries already present.
- Do not use receipt bytes, recovery keys, or Mission HMAC material as the governance witness key.
- Do not expose raw witness-key bytes or a caller-selectable sealing function.
- Do not publish, deploy, call providers, mutate upstream repositories, claim Production/public v1.2.0, implement Task 7 or Task 8, or scaffold Months 7-12.
- Keep every artifact under the receipt-bound project `.ao` roots and every secret under the Pool `operator-secrets` root.
- Keep the Pool authority lock from witness verification through envelope consumption, AO2 completion, and final execution-record readback.
- Keep the execution timeout in the inclusive range 1-30 seconds and the combined live output bound at 64 KiB.
- Preserve B01-B19 and inherited-requirement evidence binding.
- Add no dependency; reuse the existing schema validator and retained object helpers.

---

### Task 1: Bind the authenticated Mission record to its route

**Files:**
- Modify: `schemas/mission-record.schema.json`
- Modify: `internal/mission_bridge.py`
- Modify: `internal/execution.py`
- Test: `tests/test_mission_bridge.py`
- Test: `tests/test_execution.py`

**Interfaces:**
- Consumes: the exact AO Mission JSON readback returned by `_run()`.
- Produces: authenticated Mission records with `current_route: str` and `_load_authenticated_record(receipt, objective) -> tuple[dict, dict, bytes, Path]` whose record includes that route.
- Preserves: `MissionReadback` and `select_route(mission)` public shapes.

- [ ] **Step 1: Add failing Mission-route persistence tests**

Add tests that assert a new record contains `current_route`, resume rejects a route changed only in the durable JSON, and execution rejects a caller `MissionReadback` whose route differs from the authenticated record:

```python
def test_authenticated_record_binds_current_route(self):
    readback = start_or_resume(self.receipt, self.objective)
    record = json.loads(readback.record.read_text(encoding="utf-8"))
    self.assertEqual(record["current_route"], "ao-blueprint")

def test_authenticated_route_tampering_is_rejected(self):
    readback = start_or_resume(self.receipt, self.objective)
    value = json.loads(readback.record.read_text(encoding="utf-8"))
    value["current_route"] = "ao-forge"
    readback.record.write_text(json.dumps(value), encoding="utf-8")
    with self.assertRaises(MissionBridgeError) as raised:
        start_or_resume(self.receipt, self.objective)
    self.assertEqual(raised.exception.code, "mission-record-mismatch")
```

- [ ] **Step 2: Run the focused tests and confirm the missing binding**

Run: `python -m unittest tests.test_mission_bridge tests.test_execution -v`

Expected: the new persistence assertion fails because `_expected_record()` omits `current_route`.

- [ ] **Step 3: Add `current_route` to the closed schema and authenticated record**

Add the required schema property:

```json
"current_route": {
  "type": "string",
  "pattern": "^[a-z][a-z0-9-]*$",
  "minLength": 1,
  "maxLength": 64
}
```

Update `_expected_record()` and `_load_record()`:

```python
"mission_status": readback["status"],
"current_route": readback["current_route"],
```

Execution must reconstruct `MissionReadback` from `_load_authenticated_record()` and must not compare authority against a caller-supplied Mission object.

- [ ] **Step 4: Run the focused tests**

Run: `python -m unittest tests.test_mission_bridge tests.test_planning_routes tests.test_execution -v`

Expected: PASS.

- [ ] **Step 5: Commit the route binding**

```bash
git add schemas/mission-record.schema.json internal/mission_bridge.py internal/execution.py tests/test_mission_bridge.py tests/test_execution.py
git commit -m "fix: bind governed execution to Mission route"
```

### Task 2: Add the Pool-private witness key and authority lease

**Files:**
- Modify: `internal/pool.py`
- Test: `tests/test_pool.py`
- Test: `tests/test_pool_crash.py`

**Interfaces:**
- Produces private: `Pool._read_witness_key() -> bytes`, called by governance code only while `Pool._locked()` is already held.
- Produces: `Pool.authority_lease(receipt_path: Path) -> Iterator[AuthorityLease]`.
- Produces: frozen `AuthorityLease(authority_path: Path, authority_bytes: bytes, authority: dict)`.
- Holds: the existing `_locked()` context for the entire lease body.

- [ ] **Step 1: Add failing key-lifecycle and lease tests**

Cover fresh 32-byte creation, non-overwrite on repeated initialization, missing/corrupt/link key failure, no key in `public_status()`, release blocking during a lease, and `_verify_runtime_containment()` translating Windows `ValueError` to `PoolError`:

```python
def test_authority_lease_holds_release_lock(self):
    started = threading.Event()
    finished = threading.Event()

    def release():
        started.set()
        self.pool.release(self.receipt)
        finished.set()

    with self.pool.authority_lease(self.receipt) as lease:
        thread = threading.Thread(target=release)
        thread.start()
        self.assertTrue(started.wait(1))
        self.assertFalse(finished.wait(0.1))
        self.assertEqual(lease.authority_path, self.receipt.resolve())
    thread.join(2)
    self.assertTrue(finished.is_set())
```

- [ ] **Step 2: Run the Pool tests and confirm the APIs are absent**

Run: `python -m unittest tests.test_pool tests.test_pool_crash -v`

Expected: FAIL with missing `authority_lease` or missing witness key.

- [ ] **Step 3: Create and validate one witness key during initialization**

Use the existing `atomic_write_bytes()` primitive and `secrets.token_bytes(32)`. Store exactly 32 bytes at `operator-secrets/governance-witness.key`, reject symlinks/reparse points and wrong length, and never rotate automatically:

```python
@property
def _witness_key_path(self) -> Path:
    return self.root / "operator-secrets" / "governance-witness.key"

def _read_witness_key(self) -> bytes:
    value = self._witness_key_path.read_bytes()
    if len(value) != 32:
        raise PoolError("recovery-required")
    return value
```

Extend protected-path validation to include the key. Do not add a public raw-key
getter or a caller-selectable seal method. Keep installer-grade Windows ACL
ownership out of this task.

- [ ] **Step 4: Add the context-managed authority lease**

Implement the lease on the existing global Pool lock:

```python
@dataclass(frozen=True)
class AuthorityLease:
    authority_path: Path
    authority_bytes: bytes
    authority: dict

@contextmanager
def authority_lease(self, receipt_path: Path):
    with self._locked():
        self._ensure_initialized()
        self._reconcile()
        path, raw, authority, state = self._authorize(receipt_path)
        if self._unknown_paths(authority["office_id"]):
            self._mark_recovery(authority["office_id"], state, "unknown-residue")
            raise PoolError("recovery-required")
        yield AuthorityLease(path, raw, authority)
```

Do not call `resume()` inside the lease; that would reacquire the same lock.

- [ ] **Step 5: Normalize Windows containment failures**

Change `_verify_runtime_containment()` to catch both `OSError` and `ValueError` and raise `PoolError("recovery-required")`.

- [ ] **Step 6: Run Pool and full tests**

Run: `python -m unittest tests.test_pool tests.test_pool_crash -v`

Run: `python -m unittest discover -s tests -v`

Expected: PASS with only the existing platform-specific skips.

- [ ] **Step 7: Commit the key and lease**

```bash
git add internal/pool.py tests/test_pool.py tests/test_pool_crash.py
git commit -m "fix: hold Pool authority through governed work"
```

### Task 3: Seal one-use governance envelopes from locked producer validation

**Files:**
- Create: `internal/governance_witness.py`
- Create: `schemas/governance-envelope.schema.json`
- Create: `tests/test_governance_witness.py`
- Modify: `internal/mission_bridge.py`
- Modify: `tests/test_mission_bridge.py`
- Modify: `tests/test_release_tree.py`
- Modify: `tests/test_scan_public_tree.py`

**Interfaces:**
- Produces: frozen `GovernanceArtifacts(blueprint_pack: Path, atlas_workgraph: Path | None, forge_goal_run: Path, covenant_evidence: Path, workflow: Path, target: Path, run_id: str, evidence_set: Path)`.
- Produces: `issue_witness(receipt: Path, objective: str, artifacts: GovernanceArtifacts, *, lifetime_seconds: int = 60) -> Path`.
- Produces: `revoke_witness(receipt: Path, envelope: Path) -> None`, which creates a receipt-bound private revocation marker and never rewrites the envelope.
- Produces private: `_consume_witness(lease: AuthorityLease, envelope_path: Path) -> GovernedExecution`.
- `GovernedExecution` carries only verified data needed by `execute()`: Mission/route records, retained target/workflow identities, run ID, workflow digest, producer/artifact identities, evidence-set digest, expected AO2 identity, and request digest.

- [ ] **Step 1: Add failing witness tests**

Use deterministic fake executables whose bytes are pinned in a temporary component lock and whose supported command vectors are:

```text
ao-blueprint pack inspect --pack <blueprint-pack> --json
ao-atlas workgraph validate --workgraph <atlas-workgraph>
forge goal validate --goal-run <forge-goal-run> --json
covenant verify --evidence <covenant-evidence> --json
```

The fake output must match the real command’s bounded success shape. Test exact component name/commit/asset/digest enforcement, missing and unexpected Atlas, producer failure, non-object JSON, artifact escape/link/reparse/hard-link, relationship mismatch, B01-B19 drift, HMAC tampering, relocation, expiry, replay, and key disclosure scans.

```python
def test_caller_cannot_seal_self_consistent_records(self):
    artifacts = self.valid_artifacts()
    envelope = issue_witness(self.receipt, self.objective, artifacts)
    value = json.loads(envelope.read_text(encoding="utf-8"))
    value["covenant"]["decision"] = "authorized"
    envelope.write_text(json.dumps(value), encoding="utf-8")
    with self.pool.authority_lease(self.receipt) as lease:
        with self.assertRaises(GovernanceError) as raised:
            _consume_witness(lease, envelope)
    self.assertEqual(raised.exception.code, "governance-envelope-mismatch")
```

- [ ] **Step 2: Run the new module tests and confirm the module is absent**

Run: `python -m unittest tests.test_governance_witness -v`

Expected: FAIL importing `internal.governance_witness`.

- [ ] **Step 3: Define the closed envelope schema**

The schema must set `additionalProperties: false` at every object level and require:

```json
{
  "schema_version": 1,
  "witness_id": "witness-<32 lowercase hex>",
  "state": "ready",
  "authority_digest": "<64 lowercase hex>",
  "office_id": "O1..O5",
  "generation": 1,
  "runtime_version": "<validated segment>",
  "project_path": "<canonical receipt path>",
  "project_volume": "<native identity value>",
  "project_file_id": "<native identity value>",
  "mission": {"mission_id": "...", "objective_digest": "sha256:...", "status": "...", "current_route": "..."},
  "route": {"decision_digest": "...", "route": "...", "atlas_required": false, "execution_candidate": true},
  "task_digest": "...",
  "request_digest": "...",
  "target": {"canonical_path": "...", "volume": "...", "file_id": "..."},
  "workflow_digest": "...",
  "run_id": "run-<16 lowercase hex>",
  "producer_artifacts": {},
  "covenant": {"decision": "authorized", "scope": "...", "expires_at": "<UTC RFC3339>", "revoked": false},
  "requirements_evidence_digest": "...",
  "ao2": {"name": "ao2", "commit": "<40 lowercase hex>", "asset": "ao2", "sha256": "<64 lowercase hex>"},
  "created_at": "<UTC RFC3339>",
  "expires_at": "<UTC RFC3339>",
  "payload_digest": "<64 lowercase hex>"
}
```

The `producer_artifacts` object has fixed keys `ao-blueprint`, `ao-atlas`, `ao-forge`, and `ao-covenant`; Atlas is `null` only when the fixed route says it is not required. Each non-null value contains exactly `commit`, `asset`, `binary_sha256`, `command_contract`, and `artifact_sha256`.

Store the HMAC as a detached sibling `<witness-id>.hmac`, not as an envelope
field. The closed envelope schema must never accept `hmac_sha256`.

- [ ] **Step 4: Complete the existing local schema validator**

Extend `_validate_schema()` only for constructs used by tracked schemas:
`boolean`, `null`, arrays with `items`, type unions, `minItems`, `maxItems`,
`oneOf`, `minProperties`, and `maxProperties`. Add direct tests for rejection of
booleans as integers, scalar/list values where objects are required, invalid
union members, and zero/multiple matching `oneOf` branches. Do not add a JSON
Schema dependency.

- [ ] **Step 5: Implement locked producer lookup and retained launch**

Load one exact component entry per producer from `manifests/components.lock.json`. Resolve its binary from `.local/bin/<asset>` and reuse the Task 5 `_open_verified_executable()` / `_run()` pattern by extracting a generic retained-executable helper only if direct reuse cannot preserve the loaded object.

Do not introduce a plugin registry or configurable commands. Keep one constant map:

```python
_PRODUCERS = {
    "ao-blueprint": ("pack", "inspect", "--pack", "{artifact}", "--json"),
    "ao-atlas": ("workgraph", "validate", "--workgraph", "{artifact}"),
    "ao-forge": ("goal", "validate", "--goal-run", "{artifact}", "--json"),
    "ao-covenant": ("verify", "--evidence", "{artifact}", "--json"),
}
```

Use closed stdin, a 10-second producer timeout, a 64 KiB combined output limit, the retained receipt project as cwd, and full process-tree cleanup from Task 5/Task 4 primitives.

- [ ] **Step 6: Validate native artifacts and Pool-owned relationships**

Open every candidate without following links and require physical containment under its fixed root:

```text
.ao/evidence/ao-blueprint/
.ao/evidence/ao-atlas/
.ao/evidence/ao-forge/
.ao/evidence/ao-covenant/
.ao/evidence/requirements/
```

Validate the producer’s native success output and artifact JSON. Never rewrite the candidate bytes; reopen them through the retained project object and confirm their digests after validation. Bind the active authenticated Mission and fixed route in the envelope. Where a native artifact carries a cross-reference, require exact equality; where the upstream contract has no Mission or receipt field, the envelope establishes that relationship from the active lease and verified artifact digest. Reject extra Atlas evidence on a non-Atlas route.

The requirements evidence must be a closed object with exactly `requirements_sha256`, `test_bindings_sha256`, and `requirement_ids`; require the set `B01` through `B19` and hash its canonical bytes.

- [ ] **Step 7: Implement create-only sealing and atomic one-use consumption**

Create `witness-<uuid.uuid4().hex>.json`, its detached `.hmac` sibling, and private consumed/revoked markers under `.ao/governance/office-pool`. While the authority lease holds the Pool lock, call the private `_read_witness_key()` and compute HMAC over the canonical envelope bytes. Use `O_CREAT | O_EXCL`; retry only ID collisions. `revoke_witness()` creates the revoked marker under an authority lease. On consumption, validate schema, payload digest, detached HMAC, receipt/project identity, route, expiry, Covenant scope/expiry/revocation, and absent consumed/revoked markers, then create the consumed marker with `O_CREAT | O_EXCL` before returning `GovernedExecution`.

Do not delete or overwrite the envelope. A second consume must return `governance-envelope-consumed`.

- [ ] **Step 8: Run witness and export tests**

Run: `python -m unittest tests.test_governance_witness tests.test_release_tree tests.test_scan_public_tree -v`

Expected: PASS; no witness key, HMAC input, prompt, owner ID, receipt bytes, or raw producer output appears in public/exported files.

- [ ] **Step 9: Commit the governance witness**

```bash
git add internal/governance_witness.py internal/mission_bridge.py schemas/governance-envelope.schema.json tests/test_governance_witness.py tests/test_mission_bridge.py tests/test_release_tree.py tests/test_scan_public_tree.py
git commit -m "fix: seal locked governance evidence"
```

### Task 4: Launch exact AO2, workflow, and project objects and kill full process trees

**Files:**
- Modify: `internal/execution.py`
- Modify: `internal/mission_bridge.py`
- Test: `tests/test_execution.py`
- Test: `tests/test_windows_identity.py`

**Interfaces:**
- Replaces: `execute(request: ExecutionRequest) -> ExecutionResult`.
- Produces: `execute(receipt: Path, envelope: Path, *, timeout_seconds: int = 30) -> ExecutionResult`.
- Consumes: `_consume_witness(lease, envelope) -> GovernedExecution` while the same lease remains active.

- [ ] **Step 1: Replace caller-authority tests with envelope-only tests**

Delete the caller-created `BlueprintAuthorization`, `AtlasWorkgraph`, `ForgePacket`, `CovenantDecision`, and `ExecutionRequest` setup. Build a witness through the Task 3 helper and call:

```python
result = execute(self.receipt, self.envelope, timeout_seconds=30)
```

Add mutation tests for AO2 pathname replacement after verification, project delete/recreate, target substitution, workflow substitution, child survival on timeout/output overflow, and envelope replay.

- [ ] **Step 2: Run execution tests and confirm the old API fails**

Run: `python -m unittest tests.test_execution -v`

Expected: FAIL because `execute()` still accepts `ExecutionRequest`.

- [ ] **Step 3: Reuse retained execution objects**

Open the receipt-bound project through `_receipt_project_root()` inside the authority lease. Open the workflow without following links, require one regular link, hash its descriptor, copy it to protected `.ao/governance/office-pool/staging`, then reopen and compare both descriptor hashes.

Pass retained objects through launch:

```text
Linux: /proc/self/fd/<ao2-fd>, /proc/self/fd/<workflow-fd>, cwd /proc/self/fd/<project-fd>
macOS: suspended AO2 child; verify loaded Mach-O vnode and cwd vnode; workflow uses /dev/fd/<workflow-fd>
Windows: keep no-write/no-delete-share AO2, workflow, target, and project handles until process creation completes
```

AO2 arguments remain an array and use `--target .`. Do not pass an absolute target pathname after verification.

- [ ] **Step 4: Add complete process-tree termination**

On POSIX set `start_new_session=True`; on timeout or overflow send `SIGKILL` to `os.killpg(process.pid, signal.SIGKILL)` and reap the leader.

On Windows create a Job Object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, start the child suspended, assign it to the job, resume it, and terminate/close the job on every error. Keep the `ctypes` declarations local to the Windows helper; do not add pywin32.

- [ ] **Step 5: Normalize malformed AO2 output**

Make `_diagnostics()` reject scalar/list JSON and wrong field types with `ExecutionError("invalid-execution-readback")`. Catch `TypeError`, `AttributeError`, `UnicodeError`, and JSON failures before attempting a failure record.

- [ ] **Step 6: Run execution tests on macOS**

Run: `python -m unittest tests.test_execution tests.test_windows_identity -v`

Expected: PASS; Windows-only cases skip on macOS.

- [ ] **Step 7: Commit exact launch and cleanup**

```bash
git add internal/execution.py internal/mission_bridge.py tests/test_execution.py tests/test_windows_identity.py
git commit -m "fix: retain governed execution identities"
```

### Task 5: Enforce closed create-only execution records

**Files:**
- Modify: `schemas/execution-record.schema.json`
- Modify: `internal/execution.py`
- Test: `tests/test_execution.py`

**Interfaces:**
- Produces private: `_write_record(project, governed, *, phase, diagnostics, failure_code, exit_code) -> Path`.
- Requires: schema validation before write and after retained-object readback.
- Guarantees: create-only record paths with a full 128-bit execution ID and preserved bytes on validation/readback failure.

- [ ] **Step 1: Add failing schema, collision, and readback tests**

Cover completed/failed phase constraints, malformed diagnostic types, forced UUID collision with pre-existing sentinel bytes, write/readback mutation, and record-digest mismatch:

```python
def test_execution_id_collision_never_overwrites(self):
    sentinel = self.evidence_root / ("execution-" + "a" * 32 + ".json")
    sentinel.write_bytes(b"preserve-me")
    with mock.patch.object(execution_module.uuid, "uuid4", side_effect=[FakeUUID("a" * 32), FakeUUID("b" * 32)]):
        result = execute(self.receipt, self.envelope)
    self.assertEqual(sentinel.read_bytes(), b"preserve-me")
    self.assertEqual(result.record.name, "execution-" + "b" * 32 + ".json")
```

- [ ] **Step 2: Run focused tests and confirm collision/schema failures**

Run: `python -m unittest tests.test_execution -v`

Expected: the new collision and phase-specific schema tests fail.

- [ ] **Step 3: Tighten the execution schema**

Change `execution_id` to `^execution-[0-9a-f]{32}$`. Add `oneOf` branches:

```text
completed: diagnostics has exactly status and run_id; exit_code is 0; failure_code is null
failed: diagnostics is empty; failure_code is a fixed allowlisted code; exit_code is integer or null
```

Keep `additionalProperties: false` at both record and diagnostics levels.

- [ ] **Step 4: Validate, create, read back, and verify**

Before write, validate the record without `record_digest`, compute the digest, validate the complete record, create with `O_CREAT | O_EXCL`, write/fsync, reopen through the retained project directory, parse and validate again, and compare canonical bytes and digest.

Retry only an existing filename collision. If readback fails, preserve the bytes and raise `ExecutionError("recovery-required", record_path)`.

- [ ] **Step 5: Run execution and full suites**

Run: `python -m unittest tests.test_execution -v`

Run: `python -m unittest discover -s tests -v`

Expected: PASS with only expected platform skips.

- [ ] **Step 6: Commit record enforcement**

```bash
git add schemas/execution-record.schema.json internal/execution.py tests/test_execution.py
git commit -m "fix: enforce durable execution records"
```

### Task 6: Qualify the correction on macOS and physical Windows

**Files:**
- Modify: `.superpowers/sdd/2026-08-10-ao-office-pool-initial-development/task-6-report.md`
- Modify: `.superpowers/sdd/2026-08-10-ao-office-pool-initial-development/progress.md`
- Create only if required by the existing evidence pattern: `.superpowers/sdd/2026-08-10-ao-office-pool-initial-development/task-6-fix-1-report.md`

**Interfaces:**
- Consumes: the exact tracked source tree and the already locked component binaries.
- Produces: digest-bound macOS and Windows evidence for the Task 6 correction.
- Does not produce: tags, releases, uploads, deployments, provider calls, credential changes, or publications.

- [ ] **Step 1: Run clean local verification**

Run:

```bash
python -m unittest tests.test_planning_routes tests.test_governance_witness tests.test_execution -v
python -m unittest discover -s tests -v
python scripts/scan_public_tree.py .
git diff --check
git status --short
```

Expected: every focused/full test passes, only documented platform skips remain, the scan is clean, and no unplanned file is present.

- [ ] **Step 2: Build a clean allowlisted Windows qualification package**

Copy only tracked files required by the Task 6 tests plus the exact locked Windows binaries into a new digest-named `%TEMP%` directory. Record the source commit, archive SHA-256, component commits/assets/SHA-256 values, and the file allowlist before transfer.

- [ ] **Step 3: Run the physical-Windows focused and full suites**

Run in the unpacked NTFS directory:

```powershell
py -3.12 -m unittest tests.test_planning_routes tests.test_governance_witness tests.test_execution -v
py -3.12 -m unittest discover -s tests -v
```

Also run the native locked-binary smoke through the witness and `execute()` path. Require the junction/reparse/hard-link/delete-recreate tests, Job Object descendant cleanup, exact binary hashes, and zero remaining `ao2.exe`, producer, Python qualification, or Cargo/Rust processes.

- [ ] **Step 4: Retrieve and independently verify evidence**

Retrieve the durable result JSON and logs. Verify their SHA-256 digests locally, confirm package/result binding, and record counts, skips, binary identities, timestamps, and cleanup state.

- [ ] **Step 5: Update the Task 6 report and SDD ledger**

Record fix round 1/5, commit range, exact commands, macOS/Windows counts, archive/result digests, native smoke outcome, cleanup state, and the statement that Task 7 remains held pending independent review.

- [ ] **Step 6: Commit qualification evidence**

```bash
git add .superpowers/sdd/2026-08-10-ao-office-pool-initial-development/task-6-report.md .superpowers/sdd/2026-08-10-ao-office-pool-initial-development/progress.md
git add .superpowers/sdd/2026-08-10-ao-office-pool-initial-development/task-6-fix-1-report.md 2>/dev/null || true
git commit -m "test: qualify Task 6 governance witness"
```

### Task 7: Run the independent Task 6 review gate

**Files:**
- Modify: `.superpowers/sdd/2026-08-10-ao-office-pool-initial-development/task-6-review.md`
- Modify: `.superpowers/sdd/2026-08-10-ao-office-pool-initial-development/progress.md`

**Interfaces:**
- Consumes: the Task 6 fix commit range and macOS/Windows evidence.
- Produces: independent spec-compliance and code-quality verdicts.
- Gates: Task 7 may start only after both verdicts approve Task 6.

- [ ] **Step 1: Request spec-compliance review**

Give the reviewer the handoff, original plan Task 6 section, approved governance-witness design, this correction plan, initial review, fix commit range, and qualification report. Require explicit disposition of all ten original findings.

- [ ] **Step 2: Request code-quality and mutation review**

Require review of authority/key separation, producer identity, envelope replay, route binding, retained launch objects, process-tree cleanup, create-only records, schema readback, controlled errors, Windows containment, and export leakage.

- [ ] **Step 3: Record the verdict**

If either review finds a Critical or Important defect, keep Task 7 held and return the bounded finding set to the same implementer for fix round 2/5. If both reviews approve, mark Task 6 complete and allow Task 7 to begin.

- [ ] **Step 4: Commit the review record**

```bash
git add .superpowers/sdd/2026-08-10-ao-office-pool-initial-development/task-6-review.md .superpowers/sdd/2026-08-10-ao-office-pool-initial-development/progress.md
git commit -m "docs: record Task 6 governance review"
```
