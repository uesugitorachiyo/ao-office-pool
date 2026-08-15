import importlib
import hashlib
import json
import os
import re
import shutil
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[1]

PILOT_ASSERTIONS = (
    ("P01", "tests.test_pool.PoolTests.test_atomic_first_free_claims"),
    ("P02", "tests.test_pool.PoolTests.test_exact_authorization"),
    ("P03", "tests.test_pool.PoolTests.test_private_same_task_resume"),
    ("P04", "tests.test_pool.PoolTests.test_public_status_is_secret_free_and_nonmutating"),
    ("P05", "tests.test_pool.PoolTests.test_pinned_work_does_not_expire"),
    ("P06", "tests.test_execution.ExecutionTests.test_project_delete_recreate_never_redirects_child_cwd"),
    ("P07", "tests.test_pool_crash.PoolCrashTests.test_unknown_residue_requires_recovery"),
    ("P08", "tests.test_pool.PoolTests.test_emergency_release_requires_exact_authority"),
    ("P09", "tests.test_runtime_update.RuntimeUpdateTests.test_activation_rolls_back_all_offices"),
    ("P10", "tests.test_runtime_update.RuntimeUpdateTests.test_independent_trust_anchor_detects_substitution"),
    ("P11", "tests.test_qualification.QualificationTests.test_capability_states_are_truthful"),
    ("P12", "tests.test_pool.PoolTests.test_no_automatic_office_lifecycle"),
    ("P13", "tests.test_conversation_lifecycle.ConversationLifecycleTests.test_continuation_is_not_pinned"),
    ("P14", "tests.test_conversation_lifecycle.ConversationLifecycleTests.test_conversation_completion_needs_no_file"),
    ("P15", "tests.test_conversation_lifecycle.ConversationLifecycleTests.test_goal_state_conflict_stops"),
    ("P16", "tests.test_pool.PoolTests.test_runtime_version_is_contained"),
    ("P17", "tests.test_pool.PoolTests.test_corrupt_pointer_cannot_duplicate_claim"),
    ("P18", "tests.test_pool.PoolTests.test_claim_hides_owner_key"),
    ("P19", "tests.test_conversation_lifecycle.ConversationLifecycleTests.test_resume_proves_all_identities"),
    ("P20", "tests.test_conversation_lifecycle.ConversationLifecycleTests.test_cancel_checkpoints_before_release"),
    ("P21", "tests.test_pool_crash.PoolCrashTests.test_release_retires_receipt_and_pointer_atomically"),
    ("P22", "tests.test_pool.PoolTests.test_dirty_release_requires_recovery"),
    ("P23", "tests.test_qualification.QualificationTests.test_fingerprint_binds_semantic_inputs"),
    ("P24", "tests.test_qualification.QualificationTests.test_promotion_state_is_hash_bound"),
    ("P25", "tests.test_qualification.QualificationTests.test_critical_matrix_is_exact"),
    ("P26", "tests.test_qualification.QualificationTests.test_readability_gates_preserve_semantics"),
    ("P27", "tests.test_qualification.QualificationTests.test_root_authority_order"),
    ("P28", "tests.test_qualification.QualificationTests.test_specifications_bind_real_code_and_tests"),
    ("P29", "tests.test_qualification.QualificationTests.test_acceptance_rows_bind_existing_modules"),
    ("P30", "tests.test_qualification.QualificationTests.test_lifecycle_authorities_agree"),
    ("P31", "tests.test_pool.PoolTests.test_public_claim_requires_project_binding"),
    ("P32", "tests.test_pool.PoolTests.test_initialize_requires_exactly_five_offices"),
    ("P33", "tests.test_pool_crash.PoolCrashTests.test_unknown_state_fields_are_preserved_before_reuse"),
    ("P34", "tests.test_pool_crash.PoolCrashTests.test_claim_transitions_are_restart_safe"),
    ("P35", "tests.test_pool_crash.PoolCrashTests.test_unknown_journal_bytes_are_quarantined_without_overwrite"),
    ("P36", "tests.test_pool_crash.PoolCrashTests.test_every_unexpected_runtime_member_stops_before_reuse"),
    ("P37", "tests.test_pool_crash.PoolCrashTests.test_recovery_transitions_preserve_every_unknown_byte"),
    ("P38", "tests.test_runtime_update.RuntimeUpdateTests.test_valid_update_stages_and_activates_five_independent_equal_copies"),
    ("P39", "tests.test_runtime_update.RuntimeUpdateTests.test_rejects_unsafe_versions_and_malformed_manifests_before_staging"),
    ("P40", "tests.test_runtime_update.RuntimeUpdateTests.test_incompatible_or_tampered_package_fails_closed"),
    ("P41", "tests.test_runtime_update.RuntimeUpdateTests.test_occupied_activation_is_rejected_without_runtime_mutation"),
    ("P42", "tests.test_runtime_update.RuntimeUpdateTests.test_rollback_reactivates_a_previously_anchored_version"),
    ("P43", "tests.test_runtime_update.RuntimeUpdateTests.test_abrupt_partial_activation_is_recovered_before_any_pool_caller"),
    ("P44", "tests.test_runtime_update.RuntimeUpdateTests.test_transaction_cleanup_failure_is_recovery_required"),
    ("P45", "tests.test_planning_routes.PlanningRouteTests.test_bounded_work_routes_to_forge_without_atlas"),
    ("P46", "tests.test_planning_routes.PlanningRouteTests.test_oversized_mutation_and_long_work_require_atlas"),
    ("P47", "tests.test_planning_routes.PlanningRouteTests.test_blocked_mission_cannot_become_execution_candidate"),
    ("P48", "tests.test_planning_routes.PlanningRouteTests.test_source_only_capability_fails_closed"),
    ("P49", "tests.test_mission_bridge.MissionBridgeTests.test_starts_verified_mission_with_argument_array_and_project_owned_state"),
    ("P50", "tests.test_mission_bridge.MissionBridgeTests.test_authenticated_route_tampering_is_rejected"),
    ("P51", "tests.test_mission_bridge.MissionBridgeTests.test_verified_open_executable_survives_path_substitution"),
    ("P52", "tests.test_mission_bridge.MissionBridgeTests.test_rejects_wrong_objective_or_receipt_before_launch"),
    ("P53", "tests.test_mission_bridge.MissionBridgeTests.test_mission_record_schema_has_exact_persisted_shape"),
    ("P54", "tests.test_governance_witness.GovernanceWitnessTests.test_issues_closed_detached_authenticated_envelope_from_native_producers"),
    ("P55", "tests.test_governance_witness.GovernanceWitnessTests.test_native_covenant_pack_and_ledger_are_bound_after_locked_verification"),
    ("P56", "tests.test_governance_witness.GovernanceWitnessTests.test_only_pool_issued_witness_pairs_are_consumed"),
    ("P57", "tests.test_governance_witness.GovernanceWitnessTests.test_non_executable_atlas_route_cannot_mint_authority"),
    ("P58", "tests.test_governance_witness.GovernanceWitnessTests.test_requirements_evidence_requires_exact_closed_B01_through_B19"),
    ("P59", "tests.test_governance_witness.GovernanceWitnessTests.test_private_key_receipt_prompt_and_raw_outputs_are_not_disclosed"),
    ("P60", "tests.test_execution.ExecutionTests.test_executes_only_envelope_bound_objects_and_relative_target"),
    ("P61", "tests.test_execution.ExecutionTests.test_verified_ao2_path_replacement_never_runs_substituted_bytes"),
    ("P62", "tests.test_execution.ExecutionTests.test_timeout_kills_complete_process_tree"),
    ("P63", "tests.test_execution.ExecutionTests.test_envelope_is_one_use"),
    ("P64", "tests.test_execution.ExecutionTests.test_runtime_tampering_fails_before_launch"),
    ("P65", "tests.test_qualification.QualificationTests.test_exact_qualification_binding_promotes_candidate"),
    ("P66", "tests.test_qualification.QualificationTests.test_missing_pool_governance_issuance_cannot_qualify"),
    ("P67", "tests.test_qualification.QualificationTests.test_nonreleased_producer_identity_cannot_qualify"),
    ("P68", "tests.test_qualification.QualificationTests.test_semantic_evidence_omissions_and_extra_files_fail_closed"),
    ("P69", "tests.test_readback.ReadbackTests.test_public_and_protected_records_are_exact_field_constructors"),
    ("P70", "tests.test_readback.ReadbackTests.test_support_record_redacts_private_seeds_and_allowlists_actionable_codes"),
    ("P71", "tests.test_readback.ReadbackTests.test_support_bundle_is_create_only_canonical_allowlisted_json"),
    ("P72", "tests.test_readback.ActiveReadbackTests.test_activation_invalidates_detached_qualification_exports"),
    ("P73", "tests.test_release_tree.BuildReleaseTests.test_archives_exact_allowlist_and_unique_names"),
    ("P74", "tests.test_release_tree.BuildReleaseTests.test_rejects_private_selected_members_before_output"),
    ("P75", "tests.test_scan_public_tree.ScanPublicTreeTests.test_reports_existing_public_boundary_leaks"),
    ("P76", "tests.test_verify_components.VerifyLockTests.test_returns_component_digests_for_the_exact_component_set"),
)


def resolve_test(test_id):
    module_name, class_name, method_name = test_id.rsplit(".", 2)
    test_class = getattr(importlib.import_module(module_name), class_name)
    method = getattr(test_class, method_name)
    if not isinstance(test_class, type) or not callable(method):
        raise TypeError(test_id)
    return method


def function_body(source, name):
    match = re.search(
        rf"(?ms)^function\s+{re.escape(name)}\s*\{{(?P<body>.*?)(?=^function\s+|^\[CmdletBinding\(\)|\Z)",
        source,
    )
    if not match:
        raise AssertionError(f"missing PowerShell function: {name}")
    return match.group("body")


class PilotMatrixTests(unittest.TestCase):
    def test_inherited_and_blocker_rows_resolve_to_real_pilot_tests(self):
        requirements = json.loads((ROOT / "manifests" / "requirements.json").read_text(encoding="utf-8"))["requirements"]
        self.assertEqual(
            [row["id"] for row in requirements],
            [f"V11-{number:02d}" for number in range(1, 13)]
            + [f"B{number:02d}" for number in range(1, 20)],
        )
        pilot_targets = dict(PILOT_ASSERTIONS).values()
        for row in requirements:
            with self.subTest(requirement=row["id"]):
                self.assertIn(row["test_id"], pilot_targets)
                self.assertTrue(callable(resolve_test(row["test_id"])))

    def test_p01_through_p76_are_unique_callable_assertions(self):
        self.assertEqual([item[0] for item in PILOT_ASSERTIONS], [f"P{number:02d}" for number in range(1, 77)])
        targets = [item[1] for item in PILOT_ASSERTIONS]
        self.assertEqual(len(targets), len(set(targets)))
        self.assertTrue(all(callable(resolve_test(target)) for target in targets))

    def test_powershell_lifecycle_has_fail_closed_operation_order(self):
        install = (ROOT / "packaging" / "Install-AOOfficePool.ps1").read_text(encoding="utf-8")
        verify = (ROOT / "packaging" / "Verify-AOOfficePool.ps1").read_text(encoding="utf-8")
        uninstall = (ROOT / "packaging" / "Uninstall-AOOfficePool.ps1").read_text(encoding="utf-8")

        for source in (install, verify, uninstall):
            self.assertIn("Set-StrictMode -Version Latest", source)
            self.assertIn("$ErrorActionPreference = 'Stop'", source)
            self.assertIn("Assert-NtfsPath", source)
            self.assertIn("Assert-AllFree", source)

        self.assertRegex(install, r"ValidateSet\('Install', 'Update', 'Rollback'\)")
        for name in ("Assert-SafeRoot", "Assert-ArchiveChecksum", "Read-PreviewManifest", "Expand-VerifiedArchive", "Assert-InstalledTree", "Invoke-AtomicInstall"):
            function_body(install, name)
        operation = function_body(install, "Invoke-AtomicInstall")
        self.assertLess(operation.index("Assert-InstalledTree"), operation.index("Assert-AllFree"))
        self.assertLess(operation.index("Assert-AllFree"), operation.index("Move-Item"))
        self.assertIn("Restore-PreviousInstall", operation)

        for name in ("Assert-SafeRoot", "Assert-NtfsPath", "Assert-AllFree", "Assert-InstalledTree", "Invoke-Verification"):
            function_body(verify, name)
        verification = function_body(verify, "Invoke-Verification")
        self.assertLess(verification.index("Assert-InstalledTree"), verification.index("Assert-AllFree"))

        removal = function_body(uninstall, "Invoke-AtomicUninstall")
        self.assertLess(removal.index("Assert-InstalledTree"), removal.index("Assert-AllFree"))
        self.assertLess(removal.index("Assert-AllFree"), removal.index("Move-Item"))
        self.assertIn("Restore-PreviousInstall", removal)

    def test_powershell_rejects_alias_reparse_and_hard_link_paths(self):
        sources = [
            (ROOT / "packaging" / name).read_text(encoding="utf-8")
            for name in (
                "Install-AOOfficePool.ps1",
                "Verify-AOOfficePool.ps1",
                "Uninstall-AOOfficePool.ps1",
            )
        ]
        for source in sources:
            with self.subTest(script=source[:40]):
                safe_path = function_body(source, "Assert-SafeRelativePath")
                self.assertIn("short-name aliases are not accepted", safe_path)
                self.assertIn("reserved device name", safe_path)
                self.assertIn("ReparsePoint", source)
                self.assertIn("HardLink", source)
                installed_tree = function_body(source, "Assert-InstalledTree")
                self.assertNotIn("-File -Recurse", installed_tree)
                self.assertIn("-not $item.PSIsContainer", installed_tree)
        archive_check = function_body(sources[0], "Assert-ArchiveChecksum")
        self.assertIn("ReparsePoint", archive_check)
        self.assertIn("Test-HardLink", archive_check)

    def test_powershell_preview_lifecycle_preserves_state_and_binds_trusted_bytes(self):
        install = (ROOT / "packaging" / "Install-AOOfficePool.ps1").read_text(encoding="utf-8")
        verify = (ROOT / "packaging" / "Verify-AOOfficePool.ps1").read_text(encoding="utf-8")
        uninstall = (ROOT / "packaging" / "Uninstall-AOOfficePool.ps1").read_text(encoding="utf-8")

        for source in (install, verify, uninstall):
            self.assertIn("DriveType -ne [System.IO.DriveType]::Fixed", source)
            self.assertIn("Test-MutableStatePath", source)
            self.assertIn("manifest_sha256", source)
            self.assertIn("Assert-ArchiveManifest", source)
            tree = function_body(source, "Assert-InstalledTree")
            self.assertIn("Test-MutableStatePath", tree)
            self.assertIn("ExpectedManifestSha256", tree)

        self.assertIn("[string]$Archive", verify)
        self.assertIn("[string]$ChecksumFile", verify)
        self.assertIn("[string]$Archive", uninstall)
        self.assertIn("[string]$ChecksumFile", uninstall)

        expansion = function_body(install, "Expand-VerifiedArchive")
        self.assertIn("[System.IO.Compression.ZipArchive]::new($ArchiveStream", expansion)
        self.assertNotIn("ExtractToDirectory", expansion)
        self.assertIn("[System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $target, $false)", expansion)
        self.assertNotIn("$entry.ExtractToFile", expansion)

        activation = function_body(install, "Invoke-AtomicInstall")
        self.assertIn("Enter-PoolLock", activation)
        self.assertLess(activation.index("Enter-PoolLock"), activation.index("Assert-AllFree $safeRoot"))
        self.assertIn("Write-ActivationTransaction", activation)
        self.assertIn("Recover-PendingActivation", install)
        restore = function_body(install, "Restore-PreviousInstall")
        self.assertIn("Test-Path -LiteralPath $Backup", restore)

    def test_powershell_activation_prefixes_keep_the_lock_and_runtime_binding(self):
        install = (ROOT / "packaging" / "Install-AOOfficePool.ps1").read_text(encoding="utf-8")
        verify = (ROOT / "packaging" / "Verify-AOOfficePool.ps1").read_text(encoding="utf-8")
        uninstall = (ROOT / "packaging" / "Uninstall-AOOfficePool.ps1").read_text(encoding="utf-8")
        normalized = ".Replace('" + chr(92) + "', '/')"
        doubled = ".Replace('" + chr(92) * 2 + "', '/')"

        for source in (verify, uninstall):
            self.assertIn(normalized, source)
            self.assertNotIn(doubled, source)

        def powershell_array(source, name):
            match = re.search(
                rf"(?ms)^\${re.escape(name)}\s*=\s*@\((?P<body>.*?)^\)",
                source,
            )
            if not match:
                self.fail(f"missing PowerShell array: {name}")
            return re.findall(r"'([^']+)'", match.group("body"))

        state_files = [
            "pool.json",
            ".pool.lock",
            *(f"offices/O{number}/office-state.json" for number in range(1, 6)),
        ]
        state_directories = [
            "runtime",
            "operator-secrets",
            "updates",
            *(path for number in range(1, 6) for path in (
                f"offices/O{number}/history",
                f"offices/O{number}/work",
            )),
        ]
        required_state_files = [
            "runtime/generations.json",
            "runtime/recovery-authority.json",
            "runtime/runtime-update-state.json",
            "operator-secrets/governance-witness.key",
            *(f"operator-secrets/recovery-key-O{number}" for number in range(1, 6)),
        ]
        required_state_directories = [
            "runtime/governance",
            *(f"runtime/governance/{name}" for name in ("consumed", "issued", "revoked")),
            *(f"runtime/{name}" for name in ("pointers", "receipts", "recovery", "transactions")),
        ]
        for source in (install, verify, uninstall):
            self.assertEqual(powershell_array(source, "MutableStateFiles"), state_files)
            self.assertEqual(powershell_array(source, "MutableStateDirectories"), state_directories)

        for source in (install, verify, uninstall):
            state_shape = function_body(source, "Assert-MutableStateShape")
            regular_state_file = function_body(source, "Assert-RegularStateFile")
            governance_markers = function_body(source, "Assert-GovernanceMarkerDirectory")
            for check in ("PSIsContainer", "ReparsePoint", "Test-HardLink"):
                self.assertIn(check, regular_state_file)
            self.assertIn("Assert-SafeStateTree $Path", governance_markers)
            self.assertIn("^[0-9a-f]{64}-witness-[0-9a-f]{32}$", governance_markers)
            self.assertIn("Assert-RegularStateFile", governance_markers)
            self.assertIn("Assert-RegularStateFile", state_shape)
            self.assertGreaterEqual(state_shape.count("Assert-SafeStateTree"), 2)
            self.assertIn("Assert-GovernanceMarkerDirectory", state_shape)
            for relative in required_state_files + required_state_directories:
                self.assertIn("'" + relative.replace("/", chr(92)) + "'", state_shape)

        verification = function_body(verify, "Invoke-Verification")
        self.assertLess(
            verification.index("Assert-MutableStateShape $safeRoot"),
            verification.index("[pscustomobject]"),
        )
        removal = function_body(uninstall, "Invoke-AtomicUninstall")
        self.assertGreaterEqual(removal.count("Assert-MutableStateShape"), 2)
        self.assertLess(
            removal.index("Assert-MutableStateShape $safeRoot"),
            removal.index("Move-Item -LiteralPath $safeRoot"),
        )

        activation = function_body(install, "Invoke-AtomicInstall")
        self.assertRegex(activation, r"(?s)try \{.*\}\s*finally \{\s*\$archiveStream\.Dispose\(\)\s*\}")
        for operation in (
            "Save-CandidateMutableState",
            "Copy-AcceptedMutableState",
            "Assert-MutableStateEquivalent",
            "Assert-MatchingRuntimeVersion",
        ):
            self.assertIn(operation, activation)
        self.assertLess(
            activation.index("Assert-AllFree $safeRoot"),
            activation.index("Assert-MatchingRuntimeVersion"),
        )
        self.assertLess(
            activation.index("Assert-MatchingRuntimeVersion"),
            activation.index("Write-ActivationTransaction"),
        )
        self.assertLess(
            activation.index("Move-Item -LiteralPath (Join-Path $backup '.pool.lock') -Destination (Join-Path $staging '.pool.lock')"),
            activation.index("Move-Item -LiteralPath $staging -Destination $safeRoot"),
        )
        recovery = function_body(install, "Recover-PendingActivation")
        for phase in ("prepared", "candidate-saved", "state-copied", "backup", "staging-locked", "active", "committed"):
            self.assertIn("'" + phase + "'", recovery)
        writer = function_body(install, "Write-ActivationTransaction")
        self.assertNotIn("WriteAllText", writer)
        for primitive in ("FileOptions]::WriteThrough", "Flush($true)"):
            self.assertIn(primitive, writer)
        self.assertIn("Publish-ActivationTransaction $temporary $path", writer)
        self.assertNotIn("[System.IO.File]::Replace", writer)
        self.assertNotIn("[System.IO.File]::Move", writer)
        publisher = function_body(install, "Publish-ActivationTransaction")
        self.assertIn("MoveFileExW", publisher)
        self.assertIn("[uint32]9", publisher)
        self.assertIn("GetLastWin32Error()", publisher)
        for shape in ("$hasRoot", "$hasBackup", "$backupLock", "$stagedLock", "$transaction.candidate_state"):
            self.assertIn(shape, recovery)
        lock_selection = recovery[
            recovery.index("if (-not $LockHeld)") : recovery.index("$hasRoot =")
        ]
        self.assertNotIn("$lockRoots", lock_selection)
        lock_checks = (
            "if (Test-Path -LiteralPath $rootLock)",
            "elseif (Test-Path -LiteralPath $backupLock)",
            "elseif (Test-Path -LiteralPath $stagedLock)",
        )
        lock_check_offsets = [lock_selection.index(check) for check in lock_checks]
        self.assertEqual(lock_check_offsets, sorted(lock_check_offsets))
        active_recovery = recovery[recovery.index("if ($hasRoot -and $hasBackup)") :]
        source_recovery_moves = (
            "Move-Item -LiteralPath $Root -Destination $transaction.staging",
            "Move-Item -LiteralPath $stagedLock -Destination $backupLock",
            "Move-Item -LiteralPath $transaction.backup -Destination $Root",
        )
        self.assertNotIn("NewGuid", recovery)
        source_move_offsets = [active_recovery.index(operation) for operation in source_recovery_moves]
        self.assertEqual(source_move_offsets, sorted(source_move_offsets))

        for source in (install, verify, uninstall):
            all_free = function_body(source, "Assert-AllFree")
            self.assertIn("ExpectedRuntimeVersion", all_free)
            self.assertIn("runtime version differs", all_free)

        roots = state_files + state_directories

        def present(path):
            return path.exists() or path.is_symlink()

        def remove(path):
            if not present(path):
                return
            if path.is_symlink() or path.is_file():
                path.unlink()
            else:
                shutil.rmtree(path)

        def copy_path(source, destination):
            destination.parent.mkdir(parents=True, exist_ok=True)
            if source.is_dir():
                shutil.copytree(source, destination)
            else:
                shutil.copy2(source, destination)

        def copy_roots(source, destination, selected=roots):
            for relative in selected:
                candidate = source / relative
                if present(candidate):
                    copy_path(candidate, destination / relative)

        def clear_roots(base):
            for relative in roots:
                remove(base / relative)

        def mutable(relative):
            return relative in state_files or any(
                relative == directory or relative.startswith(directory + "/")
                for directory in state_directories
            )

        def snapshot(base, mutable_only=False):
            result = {}
            for path in sorted(base.rglob("*")):
                relative = path.relative_to(base).as_posix()
                if mutable_only and not mutable(relative):
                    continue
                information = path.lstat()
                if path.is_symlink():
                    value = ("link", os.readlink(path))
                elif path.is_dir():
                    value = ("directory",)
                else:
                    value = ("file", information.st_size, hashlib.sha256(path.read_bytes()).hexdigest())
                result[relative] = value
            return result

        def write_json(path, value):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")

        def build_archive(path, immutable, runtime_version="v1"):
            path.mkdir()
            (path / ".pool.lock").write_bytes(b"candidate-lock")
            write_json(path / "pool.json", {
                "schema_version": 1,
                "office_count": 5,
                "offices": [f"O{number}" for number in range(1, 6)],
                "runtime_version": runtime_version,
            })
            for name in ("receipts", "pointers", "transactions", "recovery"):
                (path / "runtime" / name).mkdir(parents=True)
            for name in ("consumed", "issued", "revoked"):
                (path / "runtime" / "governance" / name).mkdir(parents=True)
            write_json(path / "runtime" / "generations.json", {
                "schema_version": 1,
                "generations": {f"O{number}": 0 for number in range(1, 6)},
            })
            write_json(path / "runtime" / "recovery-authority.json", {"schema_version": 1, "digests": {}})
            write_json(path / "runtime" / "runtime-update-state.json", {"schema_version": 1, "completed": {}, "state_tag": "0" * 64})
            (path / "operator-secrets").mkdir()
            (path / "operator-secrets" / "governance-witness.key").write_bytes(b"g" * 32)
            for number in range(1, 6):
                (path / "operator-secrets" / f"recovery-key-O{number}").write_bytes(f"key-O{number}\n".encode())
            (path / "updates" / "runtime-transactions").mkdir(parents=True)
            for number in range(1, 6):
                office = path / "offices" / f"O{number}"
                (office / "history").mkdir(parents=True)
                (office / "work").mkdir()
                write_json(office / "office-state.json", {
                    "schema_version": 1,
                    "office_id": f"O{number}",
                    "generation": 0,
                    "status": "free",
                })
                executable = office / "runtime" / "versions" / runtime_version / "ao2.exe"
                executable.parent.mkdir(parents=True)
                executable.write_bytes(("runtime-" + runtime_version).encode())
            (path / "immutable.bin").write_bytes(immutable)

        immutable_files = {"immutable.bin", *(f"offices/O{number}/runtime/versions/v1/ao2.exe" for number in range(1, 6))}

        def validate(base):
            for relative in state_files:
                item = base / relative
                if not item.is_file() or item.is_symlink() or item.stat().st_nlink != 1:
                    raise ValueError("unsafe mutable file")
            for relative in state_directories:
                item = base / relative
                if relative == "updates" and not present(item):
                    continue
                if not item.is_dir() or item.is_symlink():
                    raise ValueError("unsafe mutable directory")
            for relative in required_state_files:
                item = base / relative
                if not item.is_file() or item.is_symlink() or item.stat().st_nlink != 1:
                    raise ValueError("unsafe mutable file")
            for relative in required_state_directories:
                item = base / relative
                if not item.is_dir() or item.is_symlink():
                    raise ValueError("unsafe mutable directory")
            for name in ("consumed", "issued", "revoked"):
                for item in (base / "runtime" / "governance" / name).iterdir():
                    information = item.lstat()
                    if (
                        item.is_symlink()
                        or not item.is_file()
                        or information.st_nlink != 1
                        or re.fullmatch(r"[0-9a-f]{64}-witness-[0-9a-f]{32}", item.name) is None
                    ):
                        raise ValueError("unsafe governance marker")
            for number in range(1, 6):
                if any((base / "offices" / f"O{number}" / "work").iterdir()):
                    raise ValueError("unsafe office work residue")
            for path in base.rglob("*"):
                relative = path.relative_to(base).as_posix()
                information = path.lstat()
                if path.is_symlink() or (path.is_file() and information.st_nlink != 1):
                    raise ValueError("unsafe state member")
                if path.is_file() and not mutable(relative) and relative not in immutable_files:
                    raise ValueError("unknown state member")

        def advance_generations(root):
            write_json(root / "runtime" / "generations.json", {
                "schema_version": 1,
                "generations": {f"O{number}": number + 10 for number in range(1, 6)},
            })
            marker = "a" * 64 + "-witness-" + "b" * 32
            (root / "runtime" / "governance" / "issued" / marker).write_bytes(b"authenticated-governance-history\n")
            (root / "runtime" / "runtime-update-state.json").write_bytes(b"authenticated-runtime-update-history\n")
            (root / "operator-secrets" / "governance-witness.key").write_bytes(b"accepted-secret".ljust(32, b"!"))
            for number in range(1, 6):
                write_json(root / "offices" / f"O{number}" / "office-state.json", {
                    "schema_version": 1,
                    "office_id": f"O{number}",
                    "generation": number + 10,
                    "status": "free",
                })
                evidence = root / "offices" / f"O{number}" / "history" / ("recovery-g1-" + f"{number:032x}") / "recovery.json"
                evidence.parent.mkdir()
                evidence.write_bytes(f"history-O{number}\n".encode())

        def activate(root, archive, suffix):
            active_version = json.loads((root / "pool.json").read_bytes())["runtime_version"]
            archive_version = json.loads((archive / "pool.json").read_bytes())["runtime_version"]
            if active_version != archive_version:
                raise ValueError("unsupported runtime drift")
            validate(root)
            validate(archive)
            staging = root.with_name(root.name + ".staging." + suffix)
            backup = root.with_name(root.name + ".previous." + suffix)
            candidate_state = staging.with_name(staging.name + ".mutable")
            shutil.copytree(archive, staging)
            candidate_state.mkdir()
            copy_roots(staging, candidate_state)
            clear_roots(staging)
            copy_roots(root, staging, [path for path in roots if path != ".pool.lock"])
            self.assertEqual(
                {key: value for key, value in snapshot(root, True).items() if key != ".pool.lock"},
                snapshot(staging, True),
            )
            os.replace(root, backup)
            os.replace(backup / ".pool.lock", staging / ".pool.lock")
            os.replace(staging, root)
            remove(candidate_state)
            return backup

        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            original = base / "original"
            update = base / "update"
            root = base / "active"
            build_archive(original, b"original-package")
            build_archive(update, b"updated-package")
            shutil.copytree(original, root)
            advance_generations(root)
            accepted_state = snapshot(root, True)
            lock_identity = root.joinpath(".pool.lock").stat().st_ino

            activate(root, update, "1" * 32)
            self.assertEqual(snapshot(root, True), accepted_state)
            self.assertEqual(root.joinpath(".pool.lock").stat().st_ino, lock_identity)
            self.assertEqual((root / "immutable.bin").read_bytes(), b"updated-package")

            before_rollback = snapshot(root, True)
            activate(root, original, "2" * 32)
            self.assertEqual(snapshot(root, True), before_rollback)
            self.assertEqual(root.joinpath(".pool.lock").stat().st_ino, lock_identity)
            self.assertEqual((root / "immutable.bin").read_bytes(), b"original-package")

            unknown = base / "unknown"
            shutil.copytree(root, unknown)
            (unknown / "offices" / "O1" / "cache.bin").write_bytes(b"not governed")
            with self.assertRaisesRegex(ValueError, "unknown"):
                validate(unknown)

            unsafe = base / "unsafe"
            shutil.copytree(root, unsafe)
            (unsafe / "offices" / "O1" / "history" / "link").symlink_to(unsafe / "pool.json")
            with self.assertRaisesRegex(ValueError, "unsafe"):
                validate(unsafe)

            wrong_kinds = (
                ("runtime/generations.json", "directory"),
                ("runtime/pointers", "file"),
                ("runtime/governance/issued", "file"),
                ("operator-secrets/recovery-key-O1", "directory"),
            )
            for number, (relative, replacement) in enumerate(wrong_kinds):
                with self.subTest(wrong_kind=relative):
                    invalid = base / f"wrong-kind-{number}"
                    shutil.copytree(root, invalid)
                    target = invalid / relative
                    remove(target)
                    if replacement == "directory":
                        target.mkdir()
                    else:
                        target.write_bytes(b"wrong kind")
                    with self.assertRaisesRegex(ValueError, "unsafe mutable"):
                        validate(invalid)

            validate(root)
            alternate_marker = "c" * 64 + "-witness-" + "d" * 32
            for number, marker_case in enumerate(("wrong-name", "nested", "directory", "symlink", "hardlink")):
                with self.subTest(governance_marker=marker_case):
                    invalid = base / f"governance-{number}"
                    shutil.copytree(root, invalid)
                    issued = invalid / "runtime" / "governance" / "issued"
                    if marker_case == "wrong-name":
                        (issued / "unknown.bin").write_bytes(b"unknown governance bytes")
                    elif marker_case == "nested":
                        nested = issued / "nested"
                        nested.mkdir()
                        (nested / alternate_marker).write_bytes(b"nested governance bytes")
                    elif marker_case == "directory":
                        (issued / alternate_marker).mkdir()
                    elif marker_case == "symlink":
                        (issued / alternate_marker).symlink_to(invalid / "pool.json")
                    else:
                        source = base / f"governance-hardlink-source-{number}"
                        source.write_bytes(b"hard-linked governance bytes")
                        os.link(source, issued / alternate_marker)
                    with self.assertRaisesRegex(ValueError, "unsafe governance marker"):
                        validate(invalid)

            def verify_state(candidate):
                validate(candidate)
                return "verified-all-free"

            def uninstall_state(candidate, quarantine):
                validate(candidate)
                os.replace(candidate, quarantine)

            for residue_kind in ("work", "history-link"):
                for operation in ("verify", "uninstall"):
                    with self.subTest(residue=residue_kind, operation=operation):
                        invalid = base / f"{operation}-{residue_kind}"
                        shutil.copytree(root, invalid)
                        if residue_kind == "work":
                            (invalid / "offices" / "O1" / "work" / "residue.bin").write_bytes(b"live task residue")
                        else:
                            (invalid / "offices" / "O1" / "history" / "residue").symlink_to(invalid / "pool.json")
                        before = snapshot(invalid)
                        quarantine = invalid.with_name(invalid.name + ".quarantine")
                        with self.assertRaisesRegex(ValueError, "unsafe"):
                            if operation == "verify":
                                verify_state(invalid)
                            else:
                                uninstall_state(invalid, quarantine)
                        self.assertEqual(snapshot(invalid), before)
                        self.assertFalse(quarantine.exists())

            drift = base / "drift"
            build_archive(drift, b"future-package", "v2")
            before_drift = snapshot(root)
            with self.assertRaisesRegex(ValueError, "runtime drift"):
                activate(root, drift, "3" * 32)
            self.assertEqual(snapshot(root), before_drift)
            self.assertFalse(root.with_name(root.name + ".staging." + "3" * 32).exists())

        # Exercise real directories and bytes at every state-copy and rename
        # prefix. Recovery itself is also restartable after each individual
        # move because the journal and candidate-state copy remain durable.
        def interrupted_case(base, stop):
            base.mkdir()
            accepted_archive = base / "accepted-archive"
            archive = base / "archive"
            root = base / "root"
            staging = base / "root.staging"
            backup = base / "root.previous"
            candidate_state = base / "root.staging.mutable"
            journal = base / "root.activation.json"
            build_archive(accepted_archive, b"accepted-package")
            build_archive(archive, b"candidate-package")
            shutil.copytree(accepted_archive, root)
            advance_generations(root)
            accepted = snapshot(root)
            candidate = snapshot(archive)
            activated = dict(candidate)
            activated.update({key: value for key, value in accepted.items() if mutable(key)})
            accepted_lock = (root / ".pool.lock").stat().st_ino
            shutil.copytree(archive, staging)

            def phase(value):
                write_json(journal, {"phase": value})

            operations = [("prepared", lambda: phase("prepared"))]
            for relative in roots:
                operations.append(("save-" + relative, lambda relative=relative: (
                    candidate_state.mkdir(exist_ok=True),
                    copy_path(staging / relative, candidate_state / relative),
                )))
            operations.append(("candidate-saved", lambda: phase("candidate-saved")))
            for relative in roots:
                operations.append(("clear-" + relative, lambda relative=relative: remove(staging / relative)))
                if relative != ".pool.lock":
                    operations.append(("copy-" + relative, lambda relative=relative: copy_path(root / relative, staging / relative)))
            operations.extend((
                ("state-copied", lambda: phase("state-copied")),
                ("root-to-backup", lambda: os.replace(root, backup)),
                ("backup", lambda: phase("backup")),
                ("lock-to-staging", lambda: os.replace(backup / ".pool.lock", staging / ".pool.lock")),
                ("staging-locked", lambda: phase("staging-locked")),
                ("staging-to-root", lambda: os.replace(staging, root)),
                ("active", lambda: phase("active")),
                ("committed", lambda: phase("committed")),
                ("partial-commit-cleanup", lambda: remove(candidate_state / "runtime" / "generations.json")),
                ("candidate-state-cleaned", lambda: remove(candidate_state)),
                ("journal-cleaned", lambda: journal.unlink()),
            ))
            committed_stop = next(
                number for number, (name, _) in enumerate(operations, 1)
                if name == "committed"
            )
            for _, operation in operations[:stop]:
                operation()

            def recover_once():
                if not journal.exists():
                    return None
                current = json.loads(journal.read_bytes())["phase"]
                if current == "committed":
                    if candidate_state.exists():
                        remove(candidate_state)
                        return "finish-commit-cleanup"
                    journal.unlink()
                    return "delete-committed-journal"
                if current not in {"prepared", "candidate-saved", "state-copied", "backup", "staging-locked", "active"}:
                    raise ValueError("invalid transaction")
                if root.exists() and backup.exists():
                    os.replace(root, staging)
                    return "root-to-staging"
                if not root.exists() and backup.exists():
                    if not (backup / ".pool.lock").exists():
                        os.replace(staging / ".pool.lock", backup / ".pool.lock")
                        return "staging-lock-to-backup"
                    os.replace(backup, root)
                    return "backup-to-root"
                if root.exists() and not backup.exists():
                    if current != "prepared":
                        clear_roots(staging)
                        copy_roots(candidate_state, staging)
                        phase("prepared")
                        return "restore-candidate-state"
                    if candidate_state.exists():
                        remove(candidate_state)
                        return "discard-candidate-state-copy"
                    journal.unlink()
                    return "delete-journal"
                raise ValueError("unrecoverable transaction shape")

            moves = []
            for _ in range(10):
                operation = recover_once()
                if operation is None:
                    break
                moves.append(operation)
            else:
                self.fail("recovery did not converge")
            if stop >= committed_stop:
                self.assertEqual(snapshot(root), activated)
                self.assertFalse(staging.exists())
                self.assertTrue(backup.exists())
            else:
                self.assertEqual(snapshot(root), accepted)
                self.assertEqual(snapshot(staging), candidate)
                self.assertFalse(backup.exists())
            self.assertEqual((root / ".pool.lock").stat().st_ino, accepted_lock)
            self.assertFalse(candidate_state.exists())
            return operations, moves

        with tempfile.TemporaryDirectory() as temporary:
            template = Path(temporary)
            operation_names = None
            recovery_moves = set()
            probe_operations, _ = interrupted_case(template / "probe", 0)
            operation_names = [name for name, _ in probe_operations]
            remove(template / "probe")
            for stop, prefix in enumerate(operation_names, 1):
                with self.subTest(prefix=prefix):
                    _, moves = interrupted_case(template / f"case-{stop}", stop)
                    recovery_moves.update(moves)
            self.assertTrue({"root-to-staging", "staging-lock-to-backup", "backup-to-root", "restore-candidate-state"} <= recovery_moves)

    def test_operator_docs_keep_preview_outputs_private_and_claims_truthful(self):
        guide = (ROOT / "docs" / "OPERATOR_GUIDE.md").read_text(encoding="utf-8")
        qualification = (ROOT / "docs" / "PILOT_QUALIFICATION.md").read_text(encoding="utf-8")
        combined = guide + qualification
        self.assertIn("developer-preview", combined)
        self.assertIn("O1, O2, O3, O4, and O5", combined)
        self.assertIn("source-present", combined)
        self.assertIn("does not establish executable", combined)
        self.assertIn("all five offices are free", combined)
        for output in ("archive", "checksums", "SBOM", "provenance", "B01–B19 ledger", "pilot qualification record"):
            with self.subTest(output=output):
                self.assertIn(output, qualification)
        self.assertIn("generated privately and remain untracked", qualification)
        self.assertNotIn("public v1.2.0 release", qualification)


if __name__ == "__main__":
    unittest.main()
