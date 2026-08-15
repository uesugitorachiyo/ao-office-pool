# Private developer-preview qualification procedure

This file defines the Month 6 gate. It is not campaign evidence and records no
pass result. The archive, checksums, SBOM, provenance, B01–B19 ledger, and
pilot qualification record are generated privately and remain untracked. Keep raw
receipts, operator material, host details, paths, transcripts, and test logs out
of the repository and public exports.

## Frozen inputs

Record the exact source commit, Windows x86-64 archive SHA-256, checksum sidecar
SHA-256, manifest SHA-256, SBOM SHA-256, provenance SHA-256, qualification
harness SHA-256, and test command. Label every generated artifact
`developer-preview`. Reject an artifact labeled Production, GA, or v1.2.0.

The preview manifest must list the exact installed file set. Recompute every
member digest and size before installation and after each install, update,
rollback, support export, and uninstall step. Source-present capability does
not establish executable, tested, accepted, activated, or routed capability.

## Callable assertion bindings

`tests/test_pilot_matrix.py` defines P01 through P76 as 76 unique dotted test
targets. Its tests import every target and require the resolved class method to
be callable. The first 31 assertions contain the exact 12 V1.1 and 19 blocker
targets from `manifests/requirements.json`; there are no duplicate filler rows.
Run:

```text
python -m unittest tests.test_pilot_matrix -v
```

The B01–B19 ledger uses these authoritative bindings:

| ID | Callable test |
| --- | --- |
| B01 | `tests.test_conversation_lifecycle.ConversationLifecycleTests.test_continuation_is_not_pinned` |
| B02 | `tests.test_conversation_lifecycle.ConversationLifecycleTests.test_conversation_completion_needs_no_file` |
| B03 | `tests.test_conversation_lifecycle.ConversationLifecycleTests.test_goal_state_conflict_stops` |
| B04 | `tests.test_pool.PoolTests.test_runtime_version_is_contained` |
| B05 | `tests.test_pool.PoolTests.test_corrupt_pointer_cannot_duplicate_claim` |
| B06 | `tests.test_pool.PoolTests.test_claim_hides_owner_key` |
| B07 | `tests.test_conversation_lifecycle.ConversationLifecycleTests.test_resume_proves_all_identities` |
| B08 | `tests.test_conversation_lifecycle.ConversationLifecycleTests.test_cancel_checkpoints_before_release` |
| B09 | `tests.test_pool_crash.PoolCrashTests.test_release_retires_receipt_and_pointer_atomically` |
| B10 | `tests.test_pool.PoolTests.test_dirty_release_requires_recovery` |
| B11 | `tests.test_qualification.QualificationTests.test_fingerprint_binds_semantic_inputs` |
| B12 | `tests.test_qualification.QualificationTests.test_promotion_state_is_hash_bound` |
| B13 | `tests.test_qualification.QualificationTests.test_critical_matrix_is_exact` |
| B14 | `tests.test_qualification.QualificationTests.test_readability_gates_preserve_semantics` |
| B15 | `tests.test_qualification.QualificationTests.test_root_authority_order` |
| B16 | `tests.test_qualification.QualificationTests.test_specifications_bind_real_code_and_tests` |
| B17 | `tests.test_qualification.QualificationTests.test_acceptance_rows_bind_existing_modules` |
| B18 | `tests.test_qualification.QualificationTests.test_lifecycle_authorities_agree` |
| B19 | `tests.test_pool.PoolTests.test_public_claim_requires_project_binding` |

Each private blocker row records the original RED command and failure, bounded
correction commit, GREEN command and result, authoritative requirement row,
and evidence digests. Historical P01–P75, 152/152, 171-pass, or independent
scores cannot replace this ledger.

## Required physical-Windows sequence

Use two clean Windows x86-64 environments on local NTFS volumes. Use unchanged
archive, sidecar, scripts, and qualification harness bytes for both runs.

1. Prove the target path is local NTFS and contains no pre-existing install,
   staging tree, task-bound process, or preview state.
2. Install and verify the exact private archive.
3. Start six simultaneous claims. Require five unique winners for O1 through
   O5 and one clear full-capacity result. No claimant may queue or steal.
4. Execute one governed, receipt-bound smoke task in each office. Require five
   independent equal AO2 runtime trees, connected-project containment, and no
   cross-office read, execute, inspect, or release.
5. Complete all work. Require all five offices are free and no task-output
   residue remains in any office.
6. Inject update interruption at every staged O1–O5, pool, decision, and
   cleanup boundary. Require exact accepted bytes and state after recovery.
7. Exercise dirty release and exact-authority emergency recovery. Require
   unknown bytes preserved and a distinct recovery state before reuse.
8. Create the allowlisted support export. Scan it and all other generated
   outputs for private fields and paths.
9. Update, verify, roll back to the prior accepted archive, and verify again.
   Every activation, update, and rollback requires all five offices free.
10. Uninstall against unchanged manifest-bound bytes. Confirm the active root
    is absent, the recoverable preserved tree is byte-exact, and no process or
    task residue remains.
11. Repeat steps 1–10 in the second clean environment.
12. Give the frozen inputs and procedure to an independent reviewer. Require
    an independent reproduction before a PASS disposition.

## Disposition

Use `NOT RUN`, `FAIL CLOSED`, or `PASS` for each gate. Any missing evidence,
digest mismatch, skipped load-bearing NTFS check, occupied office, unknown
byte, unrecovered transaction, capability-state inflation, or changed input
makes the overall result `FAIL CLOSED`.

A `PASS` disposition requires both clean installations, the complete callable
matrix, exact B01–B19 red/correction/green/traceability rows, all recovery and
uninstall checks, clean privacy scans, and independent reproduction. It remains
a private `developer-preview` result and grants no publication or deployment
authority. Months 7–12 remain out of scope.
