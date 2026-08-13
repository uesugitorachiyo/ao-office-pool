# Task 3: Consume producer-native governance evidence

## Scope and result

- Base: `513079fba08660d8fadb38293c22fa79de59df41`
- Required commit message: `fix: consume producer-native governance evidence`
- The witness now consumes the released Blueprint, Atlas, Forge, Covenant, and AO2 identities from the tracked component lock.
- Covenant input is a native `covenant.evidence-pack.v1` plus its native event ledger. Pool supplies the Mission, project, workflow, AO2, lease, and witness-expiry bindings that Covenant does not produce.
- The released Mission continuation `ao-foundry` routes to Forge with Blueprint and Atlas required, and remains subject to all existing execution gates.
- No dependency, upstream repository, provider, publication, Task 7, or Task 8 work was performed.

## Root cause confirmation

The old witness treated Covenant output as a custom Pool authority object named `covenant.governance-evidence.v1`. It expected Covenant to carry `decision`, Mission, project, workflow, AO2, and expiry fields. Released Covenant v0.1.1 does not emit or verify that object. Its native contract is `covenant.evidence-pack.v1` plus a hash-chained `covenant.event.v1` ledger, and `covenant verify` returns `covenant.verify-result.v1` metadata.

The unit fixtures and qualification runner also used fake-producer shapes. Real Atlas rejected the old workgraph, and real Covenant could not accept the custom evidence object. After replacing those fixtures, a second real-producer failure exposed a separate launch bug: producers received shared `/dev/fd` offsets. Atlas observed an empty descriptor, and Forge reopened the descriptor and reported `JSON: EOF`. Producers now receive the retained private staged pathname. Pool keeps the descriptor open and retains its parent/file identity, digest, reread, and post-run checks, while native tools can open an artifact more than once.

Released Mission v0.1.4 emits `ao-foundry` after Atlas. The fixed Pool route table had no executable route that also required Atlas, so real Atlas-through-execute qualification stopped with `PlanningRouteError("unsupported-route")`. The new fixed mapping is `ao-foundry -> ao-forge`, with Blueprint required, Atlas required, and execution candidate true.

## RED evidence

The first focused RED run established four contract breaks:

```text
ao-foundry route: PlanningRouteError("unsupported-route")
native Covenant pack: rejected by the old custom relationship checks
legacy covenant.governance-evidence.v1 object: accepted by the old witness
synthetic one-line ledger: accepted by the old witness
released component lock identities: governance-producer-identity-mismatch
```

The real released-producer RED then established the launch-path break:

```text
Atlas: empty /dev/fd artifact read
Forge: JSON: EOF when reopening the GoalRun artifact
```

The fake Atlas, Forge, and Covenant producers were strengthened to read the supplied artifacts. Forge and Covenant read their inputs twice, which keeps the unit path contract covered.

## Producer CLI and schema contracts

| Producer | Locked release | Command executed by Pool | Accepted artifact and bounded readback |
| --- | --- | --- | --- |
| Blueprint | `git-a581a22af7d0` / `a581a22af7d06483287a1b7590709e4c4d3739b8` | `ao-blueprint authorize --pack <pack> --out <output>` | `ao.blueprint.build-authorization.v0.1`; ready, user-approved, no blocking assumptions, bounded project and next-action fields |
| Atlas | `v0.2.0` / `2bf243ce8d8c71d845754398238b14d1ab77d0e6` | `ao-atlas workgraph validate --workgraph <workgraph>` | `ao.atlas.workgraph.v0.1` with at least one node; `status=valid\n` is the entire native readback |
| Forge | `v0.1.4` / `e104b47c2e14b6c0927b885e137907ad227aeb5c` | `forge goal validate --goal-run <goal-run> --json` | `ao.forge.goal-run.v0.1`; JSON readback has matching schema and goal ID, `status=passed`, and `errors=[]` |
| Covenant | `v0.1.1` / `2fd72a0426a747868826581612fa1dc9727b53b9` | `covenant verify --ledger <ledger> --evidence <pack> --json` | `covenant.evidence-pack.v1` plus native `covenant.event.v1` ledger; readback is verified `covenant.verify-result.v1` |
| AO2 | `v0.5.11` / `8307795b3434af920f6cef088e56ca8fcc76775b` | existing governed execution launch | Executable digest remains bound through the tracked lock and sealed witness |

Atlas validates the released Workgraph schema and its embedded `ao.atlas.factory-task.v0.1` objects. Pool still binds optional Mission and objective digests when Atlas supplies them, requires an allowed target instance, and binds the staged artifact digest.

Forge validates against `docs/contracts/goal-run-v0.1.schema.json`. The packaged file and the exact released file are byte-identical:

```text
SHA-256 68a0fb154124fb4c219cc68eeffcc432e2c5c445765e9dbe24b19718fb98d74c
size 3869 bytes
```

No Forge schema change was needed. Pool also requires the native GoalRun `repo` and objective to match the active project and request.

Covenant verification must report success, one or more ledger events, zero failures, nonnegative artifact/input counts, and valid ledger and terminal-event digests. Pool then requires:

- pack, readback, and requested run IDs to agree;
- pack, readback, and staged ledger SHA-256 values to agree;
- successful run status with no failures;
- every policy decision and explanation to be `allow`, with equal counts;
- manifest and input-snapshot counts to match the native readback;
- an accepted `covenant.closure-matrix.v1` for the same run and contract;
- at least one required closure row, with every required row closed.

Pool derives scope from the active authority lease and expiry from the witness creation time plus its bounded lifetime. It does not recover Mission, project, AO2, workflow, or expiry authority from Covenant.

## GREEN evidence

Focused suite after the contract correction:

```text
$ python3.12 -m unittest tests.test_planning_routes tests.test_governance_witness tests.test_execution -v
Ran 90 tests

OK
```

Fresh full suite during final review:

```text
$ python3.12 -m unittest discover -s tests
Ran 280 tests in 72.966s

OK (skipped=11)
```

The 11 skips are the existing platform-specific skips.

Fresh released macOS producer-to-AO2 smoke:

```json
{"ao2_sha256":"6cba9a1ded758506bb0a4b6d6377687e29b9d35950c799c2a0b4efb51c6f1bd7","producer_sha256":{"ao-atlas":"e6968aeeb11bc19eb77fe3f87ca71414697dc92736556e726abe89c74f874bea","ao-blueprint":"f86f221351069bbece0bd2afacdf964c812081018d71a94286bb0103927cafec","ao-covenant":"9a5ca7c6920c44b6e120d6c5bd8baf190b66e188d43485639c6fc5355190868e","ao-forge":"823ee61771608c7893287532c00929710ee1ff1149e06c13d40ff7296e937ba1"},"record_phase":"completed","record_sha256":"90b35aeb10cd17a1f03da9eeca0231ede62adf51701a42a0336e48fb05e85fc3","request_digest":"7b5d1dd332ce2092a4a516ee1d421378451a9bb8538dc0dadaa80ebe894dad0b","run_id":"run-0123456789abcdef","status":"accepted"}
```

This smoke selected the exact platform binaries by SHA-256, used the `ao-foundry` route with real Atlas required, ran all four locked producers through `issue_witness()`, and passed the resulting one-use envelope to `execute()`.

Additional checks:

```text
$ python3.12 -m py_compile <six changed Python files>
exit 0

$ git diff --check
exit 0

$ cmp <packaged Forge schema> <released Forge schema>
exit 0; byte-identical
```

## Files changed

- `internal/governance_witness.py`: exact released pins, native Covenant/readback validation, Pool-derived scope and expiry, and reread-safe private staged producer paths.
- `internal/planning_routes.py`: fixed `ao-foundry` continuation mapping.
- `tests/test_governance_witness.py`: producer-native Atlas/Forge/Covenant fixtures, a five-event Covenant hash chain, contract rejection tests, exact lock tests, and producers that read supplied files.
- `tests/test_planning_routes.py`: `ao-foundry` route contract.
- `tests/test_execution.py`: removed the synthetic Covenant `ao2_sha256` injection.
- `.superpowers/sdd/2026-08-12-task6-governance-witness-correction/qualification-support/native-smoke-current.py`: exact macOS/Windows binary selection and real producer-to-execute qualification.
- This report.

## Independent continuation review

- Compared every product change against Task 3's listed inputs and outputs. The added route is needed to qualify Mission's released `ao-foundry` continuation and does not bypass Blueprint, Atlas, Forge, Covenant, lease, requirements, HMAC, AO2, or one-use checks.
- Rechecked the producer path change against the retained descriptor lifecycle. The staged path stays inside Pool's private directory; open descriptor identity, link count, parent identity, ctime, digest, source reread, and post-producer checks remain active.
- Checked native Covenant pack/readback/ledger relationships for success, run identity, counts, digests, decisions, failures, and required closure. The locked native verifier remains the schema and ledger-chain authority.
- Confirmed no custom Covenant object, synthetic ledger authority, Covenant-supplied AO2 identity, dependency, new trust subsystem, or Forge schema edit remains in the change.

## Clean-export concern

The clean tracked export has one scanner finding:

```text
docs/superpowers/plans/2026-08-13-coherent-release-rebaseline.md  content  private
```

An export of base `513079fba08660d8fadb38293c22fa79de59df41` reports the same path, rule, and detail. Task 3 introduced no new clean-export finding. The pre-existing plan contains a private campaign-path literal and remains unchanged to preserve scope and provenance. This concern is deferred to avoid editing an approved plan outside Task 3.
