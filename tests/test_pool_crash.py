import base64
import hashlib
import json
import multiprocessing
import tempfile
import unittest
from pathlib import Path

from internal.pool import InjectedCrash, Pool, PoolError
from tests.process_control import stop_process, wait_for_expected_exit


def _crash_claim(root, project, stage):
    Pool(Path(root), crash_after=stage, abrupt_crash=True).claim(
        "holder", "task", Path(project), "pinned"
    )


def _crash_release(root, authority, stage):
    Pool(Path(root), crash_after=stage, abrupt_crash=True).release(Path(authority))


def _crash_recover(root, stage, generation):
    root = Path(root)
    Pool(root, crash_after=stage, abrupt_crash=True).recover(
        root / "operator-secrets" / "recovery-key-O1", "O1", generation
    )


def _crash_initialize(root, stage):
    Pool(Path(root), crash_after=stage, abrupt_crash=True).initialize()


class PoolCrashTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory(
            dir=Path(tempfile.gettempdir()).resolve()
        )
        self.base = Path(self.temporary_directory.name).resolve()
        self.project = self.base / "project"
        self.project.mkdir()

    def tearDown(self):
        self.temporary_directory.cleanup()

    def _pool(self, name):
        root = self.base / name
        pool = Pool(root)
        pool.initialize()
        return root, pool

    def _abrupt(self, target, *arguments):
        process = multiprocessing.get_context("spawn").Process(target=target, args=arguments)
        process.start()
        self.addCleanup(stop_process, process)
        wait_for_expected_exit(process, expected_exit=97, timeout_seconds=180)

    def test_unknown_residue_requires_recovery(self):
        # MUTATION: a free-office scan ignores unknown bytes and reuses the office.
        root, pool = self._pool("unknown")
        residue = root / "offices" / "O1" / "work" / "orphan.bin"
        residue.write_bytes(b"orphan\x00bytes")
        authority = pool.claim("holder", "task", self.project, "pinned")
        self.assertEqual(authority.parent.parent.parent, root)
        status = pool.public_status()["offices"]
        self.assertEqual(status[0]["status"], "recovery-required")
        self.assertEqual(status[1]["status"], "occupied")
        self.assertEqual(residue.read_bytes(), b"orphan\x00bytes")

    def test_unknown_state_fields_are_preserved_before_reuse(self):
        # MUTATION: permissive state parsing overwrites bytes with unknown semantics.
        root, pool = self._pool("unknown-state")
        state_path = root / "offices" / "O1" / "office-state.json"
        original = state_path.read_bytes().rstrip()[:-1] + b',"future":"unknown"}\n'
        state_path.write_bytes(original)
        pool.claim("holder", "task", self.project, "pinned")
        status = pool.public_status()["offices"]
        self.assertEqual(status[0]["status"], "recovery-required")
        self.assertEqual(status[1]["status"], "occupied")
        self.assertEqual(state_path.read_bytes(), original)

    def test_claim_transitions_are_restart_safe(self):
        # MUTATION: exception unwinding hides abandoned-lock and stage-state defects.
        stages = (
            "claim:journal-prepared",
            "claim:generation",
            "claim:office",
            "claim:authority",
            "claim:pointer",
            "claim:journal-committed",
        )
        for stage in stages:
            with self.subTest(stage=stage):
                root, _ = self._pool(stage.replace(":", "-"))
                self._abrupt(_crash_claim, str(root), str(self.project), stage)
                restarted = Pool(root)
                if stage == "claim:journal-committed":
                    with self.assertRaises(PoolError) as raised:
                        restarted.claim("holder", "task", self.project, "pinned")
                    self.assertEqual(raised.exception.code, "already-claimed")
                    authority = next((root / "runtime" / "receipts").iterdir())
                    self.assertEqual(restarted.resume(authority), authority)
                    generation = 1
                else:
                    authority = restarted.claim("holder", "task", self.project, "pinned")
                    generation = 1 if stage == "claim:journal-prepared" else 2
                self.assertEqual(
                    restarted.public_status()["offices"][0],
                    {"office_id": "O1", "status": "occupied", "generation": generation},
                )
                self.assertEqual(len(list((root / "runtime" / "receipts").iterdir())), 1)

    def test_initialization_abrupt_exit_is_restart_safe(self):
        # MUTATION: initialization relies on exception cleanup instead of lock abandonment.
        for office_id in ("O1", "O2", "O3", "O4", "O5"):
            with self.subTest(office_id=office_id):
                root = self.base / f"initialize-{office_id}"
                self._abrupt(_crash_initialize, str(root), f"initialize:office:{office_id}")
                Pool(root).initialize()
                self.assertEqual(
                    Pool(root).public_status()["offices"],
                    [
                        {"office_id": f"O{number}", "status": "free", "generation": 0}
                        for number in range(1, 6)
                    ],
                )

    def test_interrupted_initialization_preserves_witness_key(self):
        root = self.base / "initialize-witness"
        self._abrupt(_crash_initialize, str(root), "initialize:office:O1")
        key_path = root / "operator-secrets" / "governance-witness.key"
        original = key_path.read_bytes()

        Pool(root).initialize()

        self.assertEqual(len(original), 32)
        self.assertEqual(key_path.read_bytes(), original)

    def test_unknown_journal_bytes_are_quarantined_without_overwrite(self):
        # MUTATION: rollback unlinks a foreign replacement at an expected path.
        root, _ = self._pool("foreign-journal-bytes")
        with self.assertRaises(InjectedCrash):
            Pool(root, crash_after="claim:authority").claim(
                "holder", "task", self.project, "pinned"
            )
        authority = next((root / "runtime" / "receipts").iterdir())
        authority.write_bytes(b"foreign\x00bytes")
        with self.assertRaises(PoolError) as raised:
            Pool(root).claim("next", "next-task", self.project, "pinned")
        self.assertEqual(raised.exception.code, "recovery-required")
        self.assertEqual(authority.read_bytes(), b"foreign\x00bytes")
        self.assertEqual(Pool(root).public_status()["offices"][0]["status"], "recovery-required")

    def test_journal_quarantine_preserves_existing_recovery_marker(self):
        # MUTATION: quarantine overwrites a marker whose bytes have unknown semantics.
        root, _ = self._pool("existing-recovery-marker")
        with self.assertRaises(InjectedCrash):
            Pool(root, crash_after="claim:journal-prepared").claim(
                "holder", "task", self.project, "pinned"
            )
        journal = next((root / "runtime" / "transactions").iterdir())
        value = json.loads(journal.read_text())
        value["phase"] = "impossible"
        journal.write_text(json.dumps(value), encoding="utf-8")
        marker = root / "runtime" / "recovery" / "O1.json"
        original = b"future-marker\x00bytes"
        marker.write_bytes(original)

        with self.assertRaises(PoolError) as raised:
            Pool(root).claim("next", "next-task", self.project, "pinned")
        self.assertEqual(raised.exception.code, "recovery-required")
        self.assertEqual(marker.read_bytes(), original)
        self.assertTrue(journal.exists())

    def test_unexpected_transaction_members_stop_before_reuse(self):
        # MUTATION: globbing only JSON journals ignores foreign protected bytes.
        for relative, directory in (("future.bin", False), ("nested", True)):
            with self.subTest(relative=relative):
                root, _ = self._pool(f"unexpected-transaction-{relative.replace('.', '-')}")
                unexpected = root / "runtime" / "transactions" / relative
                if directory:
                    unexpected.mkdir()
                    payload = unexpected / "payload.bin"
                else:
                    payload = unexpected
                payload.write_bytes(b"unknown-transaction\x00bytes")
                before = {
                    path.relative_to(root).as_posix(): path.read_bytes()
                    for path in root.rglob("*")
                    if path.is_file() and path.name != ".pool.lock"
                }

                with self.assertRaises(PoolError) as raised:
                    Pool(root).claim("holder", "task", self.project, "pinned")
                self.assertEqual(raised.exception.code, "recovery-required")
                after = {
                    path.relative_to(root).as_posix(): path.read_bytes()
                    for path in root.rglob("*")
                    if path.is_file() and path.name != ".pool.lock"
                }
                self.assertEqual(after, before)

    def test_every_unexpected_runtime_member_stops_before_reuse(self):
        # MUTATION: checking only transactions leaves other protected registries open.
        relatives = (
            "future.bin",
            "receipts/future.bin",
            "pointers/future.bin",
            "transactions/future.bin",
            "recovery/future.bin",
        )
        for number, relative in enumerate(relatives):
            with self.subTest(relative=relative):
                root, _ = self._pool(f"unexpected-runtime-{number}")
                unexpected = root / "runtime" / relative
                unexpected.write_bytes(b"unknown-runtime\x00bytes")
                before = {
                    path.relative_to(root).as_posix(): path.read_bytes()
                    for path in root.rglob("*")
                    if path.is_file() and path.name != ".pool.lock"
                }

                with self.assertRaises(PoolError) as raised:
                    Pool(root).claim("holder", "task", self.project, "pinned")
                self.assertEqual(raised.exception.code, "recovery-required")
                after = {
                    path.relative_to(root).as_posix(): path.read_bytes()
                    for path in root.rglob("*")
                    if path.is_file() and path.name != ".pool.lock"
                }
                self.assertEqual(after, before)

    def test_exact_shaped_orphan_receipts_and_pointers_stop_before_reuse(self):
        # MUTATION: filename-only checks accept unowned protected registry bytes.
        relatives = (
            f"receipts/{'a' * 64}.receipt.json",
            f"pointers/{'b' * 64}.json",
        )
        for number, relative in enumerate(relatives):
            with self.subTest(relative=relative):
                root, pool = self._pool(f"orphan-runtime-{number}")
                orphan = root / "runtime" / relative
                orphan.write_bytes(b"exact-shaped-orphan\x00bytes")
                before = {
                    path.relative_to(root).as_posix(): path.read_bytes()
                    for path in root.rglob("*")
                    if path.is_file() and path.name != ".pool.lock"
                }

                with self.assertRaises(PoolError) as raised:
                    pool.claim("holder", "task", self.project, "pinned")

                self.assertEqual(raised.exception.code, "recovery-required")
                after = {
                    path.relative_to(root).as_posix(): path.read_bytes()
                    for path in root.rglob("*")
                    if path.is_file() and path.name != ".pool.lock"
                }
                self.assertEqual(after, before)

    def test_untrusted_journal_paths_stop_before_mutation(self):
        # MUTATION: replaying unvalidated journal member paths deletes an unrelated file.
        root, _ = self._pool("journal-path")
        victim = self.base / "victim.bin"
        victim.write_bytes(b"preserve-me")
        operation_id = "a" * 32
        state = json.loads((root / "offices" / "O1" / "office-state.json").read_text())
        value = {
            "schema_version": 1,
            "operation_id": operation_id,
            "kind": "claim",
            "phase": "prepared",
            "office_id": "O1",
            "before_state": state,
            "after_state": state,
            "authority_name": "../../../victim.bin",
            "authority_bytes": base64.b64encode(victim.read_bytes()).decode("ascii"),
            "pointer_name": "safe.json",
            "pointer": {},
        }
        journal = root / "runtime" / "transactions" / f"{operation_id}.json"
        journal.write_text(json.dumps(value), encoding="utf-8")
        with self.assertRaises(PoolError) as raised:
            Pool(root).claim("holder", "task", self.project, "pinned")
        self.assertEqual(raised.exception.code, "recovery-required")
        self.assertEqual(victim.read_bytes(), b"preserve-me")
        self.assertTrue(journal.exists())

    def test_unauthorized_calls_do_not_replay_pending_journal(self):
        # MUTATION: replay before credential checks mutates state for an unauthorized call.
        root, _ = self._pool("unauthorized-replay")
        with self.assertRaises(InjectedCrash):
            Pool(root, crash_after="claim:office").claim(
                "holder", "task", self.project, "pinned"
            )
        journal = next((root / "runtime" / "transactions").iterdir())
        before = {
            path.relative_to(root).as_posix(): path.read_bytes()
            for path in root.rglob("*")
            if path.is_file()
        }
        wrong = self.base / "wrong.bin"
        wrong.write_bytes(b"wrong")
        calls = (
            lambda: Pool(root).resume(wrong),
            lambda: Pool(root).release(wrong),
            lambda: Pool(root).recover(wrong, "O1", 1),
        )
        for call in calls:
            with self.subTest(call=call):
                with self.assertRaises(PoolError) as raised:
                    call()
                self.assertEqual(raised.exception.code, "unauthorized")
                after = {
                    path.relative_to(root).as_posix(): path.read_bytes()
                    for path in root.rglob("*")
                    if path.is_file()
                }
                self.assertEqual(after, before)
                self.assertTrue(journal.exists())

    def test_forged_claim_journal_is_preserved_without_replay(self):
        # MUTATION: outer-key validation accepts incoherent authority/pointer/state.
        root, _ = self._pool("forged-journal")
        operation_id = "b" * 32
        before = json.loads((root / "offices" / "O1" / "office-state.json").read_text())
        value = {
            "schema_version": 1,
            "operation_id": operation_id,
            "kind": "claim",
            "phase": "committed",
            "office_id": "O1",
            "before_state": before,
            "after_state": before,
            "authority_name": f"{'a' * 64}.receipt.json",
            "authority_bytes": base64.b64encode(b"not-json").decode("ascii"),
            "pointer_name": f"{'c' * 64}.json",
            "pointer": [],
        }
        journal = root / "runtime" / "transactions" / f"{operation_id}.json"
        journal.write_text(json.dumps(value), encoding="utf-8")
        original = journal.read_bytes()
        with self.assertRaises(PoolError) as raised:
            Pool(root).claim("holder", "task", self.project, "pinned")
        self.assertEqual(raised.exception.code, "recovery-required")
        self.assertEqual(journal.read_bytes(), original)
        self.assertEqual(list((root / "runtime" / "receipts").iterdir()), [])

    def test_coherent_looking_forged_claim_journals_are_preserved(self):
        # MUTATION: individually valid claim fields conceal cross-field forgery.
        for mutation in ("pointer-name", "generation-jump"):
            with self.subTest(mutation=mutation):
                root, _ = self._pool(f"forged-{mutation}")
                with self.assertRaises(InjectedCrash):
                    Pool(root, crash_after="claim:journal-prepared").claim(
                        "holder", "task", self.project, "pinned"
                    )
                journal = next((root / "runtime" / "transactions").iterdir())
                value = json.loads(journal.read_text())
                if mutation == "pointer-name":
                    value["pointer_name"] = f"{'d' * 64}.json"
                else:
                    authority = json.loads(base64.b64decode(value["authority_bytes"]))
                    authority["generation"] = 99
                    authority_bytes = (
                        json.dumps(authority, sort_keys=True, separators=(",", ":")) + "\n"
                    ).encode()
                    value["authority_bytes"] = base64.b64encode(authority_bytes).decode()
                    value["after_state"]["generation"] = 99
                    value["after_state"]["authority_digest"] = hashlib.sha256(
                        authority_bytes
                    ).hexdigest()
                    value["pointer"]["generation"] = 99
                journal.write_text(json.dumps(value), encoding="utf-8")
                original = journal.read_bytes()

                with self.assertRaises(PoolError) as raised:
                    Pool(root).claim("next", "next-task", self.project, "pinned")
                self.assertEqual(raised.exception.code, "recovery-required")
                self.assertEqual(journal.read_bytes(), original)

    def test_committed_phase_requires_fully_durable_post_state(self):
        # MUTATION: phase alone rolls an authentic but incomplete transition forward.
        cases = []

        claim_root, _ = self._pool("phase-prefix-claim")
        with self.assertRaises(InjectedCrash):
            Pool(claim_root, crash_after="claim:journal-prepared").claim(
                "holder", "task", self.project, "pinned"
            )
        cases.append(claim_root)

        release_root, release_pool = self._pool("phase-prefix-release")
        authority = release_pool.claim("holder", "task", self.project, "pinned")
        with self.assertRaises(InjectedCrash):
            Pool(release_root, crash_after="release:journal-prepared").release(authority)
        cases.append(release_root)

        recover_root, recover_pool = self._pool("phase-prefix-recover")
        recovery_authority = recover_pool.claim("holder", "task", self.project, "pinned")
        (recover_root / "offices" / "O1" / "work" / "partial.bin").write_bytes(
            b"partial"
        )
        with self.assertRaises(PoolError):
            recover_pool.release(recovery_authority)
        with self.assertRaises(InjectedCrash):
            Pool(recover_root, crash_after="recover:journal-prepared").recover(
                recover_root / "operator-secrets" / "recovery-key-O1", "O1", 1
            )
        cases.append(recover_root)

        for root in cases:
            with self.subTest(kind=root.name):
                journal = next((root / "runtime" / "transactions").iterdir())
                value = json.loads(journal.read_text())
                value["phase"] = "committed"
                journal.write_text(json.dumps(value), encoding="utf-8")
                original = journal.read_bytes()
                before = {
                    path.relative_to(root).as_posix(): path.read_bytes()
                    for path in root.rglob("*")
                    if path.is_file() and path.name != ".pool.lock"
                }

                with self.assertRaises(PoolError) as raised:
                    Pool(root).claim("next", "next-task", self.project, "pinned")
                self.assertEqual(raised.exception.code, "recovery-required")
                self.assertEqual(journal.read_bytes(), original)
                after = {
                    path.relative_to(root).as_posix(): path.read_bytes()
                    for path in root.rglob("*")
                    if path.is_file() and path.name != ".pool.lock"
                }
                marker_name = f"runtime/recovery/{value['office_id']}.json"
                after.pop(marker_name, None)
                before.pop(marker_name, None)
                self.assertEqual(after, before)

    def test_generation_registry_survives_unknown_state(self):
        # MUTATION: corrupt state resets generation to zero and reuses generation one.
        root, pool = self._pool("generation-registry")
        authority = pool.claim("holder", "task", self.project, "pinned")
        pool.release(authority)
        state = root / "offices" / "O1" / "office-state.json"
        unknown = b'{"schema_version":1,"office_id":"O1","status":"free"}\n'
        state.write_bytes(unknown)
        pool.claim("other", "other-task", self.project, "pinned")
        status = pool.public_status()["offices"]
        self.assertEqual(status[0], {"office_id": "O1", "status": "recovery-required", "generation": 1})
        self.assertEqual(status[1]["status"], "occupied")
        pool.recover(root / "operator-secrets" / "recovery-key-O1", "O1", 1)
        next_authority = pool.claim("next", "next-task", self.project, "pinned")
        record = json.loads(next_authority.read_text())
        self.assertEqual(record["office_id"], "O1")
        self.assertEqual(record["generation"], 2)
        self.assertEqual(next((root / "offices" / "O1" / "history").rglob("unknown-office-state.json")).read_bytes(), unknown)

    def test_repeated_aborted_claims_preserve_generation_progress(self):
        # MUTATION: claim-journal validation assumes office state and registry never diverge.
        root, _ = self._pool("repeated-aborted-claims")
        with self.assertRaises(InjectedCrash):
            Pool(root, crash_after="claim:generation").claim(
                "holder-1", "task-1", self.project, "pinned"
            )
        with self.assertRaises(InjectedCrash):
            Pool(root, crash_after="claim:journal-prepared").claim(
                "holder-2", "task-2", self.project, "pinned"
            )

        authority = Pool(root).claim("holder-3", "task-3", self.project, "pinned")
        record = json.loads(authority.read_text())
        self.assertEqual(record["office_id"], "O1")
        self.assertEqual(record["generation"], 2)

    def test_prepared_recovery_preserves_source_destination_collision(self):
        # MUTATION: recursive rollback cleanup deletes an unknown archive copy.
        root, pool = self._pool("recovery-collision")
        authority = pool.claim("holder", "task", self.project, "pinned")
        (root / "offices" / "O1" / "work" / "partial.bin").write_bytes(b"partial")
        with self.assertRaises(PoolError):
            pool.release(authority)
        with self.assertRaises(InjectedCrash):
            Pool(root, crash_after="recover:authority").recover(
                root / "operator-secrets" / "recovery-key-O1", "O1", 1
            )
        archive_copy = next((root / "offices" / "O1" / "history").rglob("authority.json"))
        original = archive_copy.read_bytes()
        authority.write_bytes(b"foreign-source\x00")
        journal = next((root / "runtime" / "transactions").iterdir())
        with self.assertRaises(PoolError) as raised:
            Pool(root).claim("next", "next-task", self.project, "pinned")
        self.assertEqual(raised.exception.code, "recovery-required")
        self.assertEqual(authority.read_bytes(), b"foreign-source\x00")
        self.assertEqual(archive_copy.read_bytes(), original)
        self.assertTrue(journal.exists())

    def test_forged_recovery_journal_requires_exact_move_map(self):
        # MUTATION: kind-only recovery validation accepts substituted sources/destinations.
        for mutation in ("destination", "authority-source"):
            with self.subTest(mutation=mutation):
                root, pool = self._pool(f"forged-recovery-{mutation}")
                authority = pool.claim("holder", "task", self.project, "pinned")
                (root / "offices" / "O1" / "work" / "partial.bin").write_bytes(
                    b"partial"
                )
                with self.assertRaises(PoolError):
                    pool.release(authority)
                with self.assertRaises(InjectedCrash):
                    Pool(root, crash_after="recover:journal-prepared").recover(
                        root / "operator-secrets" / "recovery-key-O1", "O1", 1
                    )
                journal = next((root / "runtime" / "transactions").iterdir())
                value = json.loads(journal.read_text())
                if mutation == "destination":
                    value["moves"][0]["destination"] = str(
                        Path(value["archive"]) / "recovery.json"
                    )
                else:
                    move = next(item for item in value["moves"] if item["kind"] == "authority")
                    substitute = root / "runtime" / "receipts" / "substitute.receipt.json"
                    substitute.write_bytes(authority.read_bytes())
                    move["source"] = str(substitute)
                journal.write_text(json.dumps(value), encoding="utf-8")
                original = journal.read_bytes()

                with self.assertRaises(PoolError) as raised:
                    Pool(root).claim("next", "next-task", self.project, "pinned")
                self.assertEqual(raised.exception.code, "recovery-required")
                self.assertEqual(journal.read_bytes(), original)

    def test_release_retires_receipt_and_pointer_atomically(self):
        # MUTATION: deleting authority and pointer without a journal strands ownership.
        stages = (
            "release:journal-prepared",
            "release:authority",
            "release:pointer",
            "release:office",
            "release:journal-committed",
        )
        for stage in stages:
            with self.subTest(stage=stage):
                root, pool = self._pool(stage.replace(":", "-"))
                authority = pool.claim("holder", "task", self.project, "pinned")
                self._abrupt(_crash_release, str(root), str(authority), stage)
                restarted = Pool(root)
                if stage == "release:journal-committed":
                    replacement = restarted.claim("next", "next-task", self.project, "pinned")
                    self.assertEqual(restarted.public_status()["offices"][0]["status"], "occupied")
                    self.assertTrue(replacement.exists())
                    self.assertFalse(authority.exists())
                else:
                    with self.assertRaises(PoolError) as raised:
                        restarted.claim("holder", "task", self.project, "pinned")
                    self.assertEqual(raised.exception.code, "already-claimed")
                    self.assertEqual(restarted.resume(authority), authority)
                    self.assertTrue(authority.exists())
                    self.assertEqual(len(list((root / "runtime" / "pointers").iterdir())), 1)

    def test_interrupted_release_retries_directly_with_original_receipt_path(self):
        # MUTATION: retry requires a receipt already deleted by the interrupted release.
        stages = (
            "release:journal-prepared",
            "release:authority",
            "release:pointer",
            "release:office",
            "release:journal-committed",
        )
        for stage in stages:
            with self.subTest(stage=stage):
                root, pool = self._pool(f"direct-{stage.replace(':', '-')}")
                authority = pool.claim("holder", "task", self.project, "pinned")
                self._abrupt(_crash_release, str(root), str(authority), stage)

                Pool(root).release(authority)

                self.assertEqual(
                    Pool(root).public_status()["offices"][0],
                    {"office_id": "O1", "status": "free", "generation": 1},
                )
                self.assertFalse(authority.exists())
                self.assertEqual(list((root / "runtime" / "transactions").iterdir()), [])

    def test_recovery_transitions_preserve_every_unknown_byte(self):
        # MUTATION: interrupted recovery deletes residue instead of preserving it.
        stages = (
            "recover:journal-prepared",
            "recover:authority",
            "recover:pointer",
            "recover:office",
            "recover:journal-committed",
        )
        payload = b"crash-residue\x00\xff"
        for stage in stages:
            with self.subTest(stage=stage):
                root, pool = self._pool(stage.replace(":", "-"))
                authority = pool.claim("holder", "task", self.project, "pinned")
                residue = root / "offices" / "O1" / "work" / "partial.bin"
                residue.write_bytes(payload)
                with self.assertRaises(PoolError):
                    pool.release(authority)
                generation = pool.public_status()["offices"][0]["generation"]
                self._abrupt(_crash_recover, str(root), stage, generation)
                restarted = Pool(root)
                if stage == "recover:journal-committed":
                    next_authority = restarted.claim("next", "next-task", self.project, "pinned")
                    self.assertEqual(json.loads(next_authority.read_text())["generation"], 2)
                else:
                    with self.assertRaises(PoolError) as raised:
                        restarted.claim("holder", "task", self.project, "pinned")
                    self.assertEqual(raised.exception.code, "already-claimed")
                    self.assertEqual(
                        restarted.public_status()["offices"][0],
                        {"office_id": "O1", "status": "recovery-required", "generation": 1},
                    )
                copies = [path.read_bytes() for path in root.rglob("partial.bin")]
                self.assertEqual(copies, [payload])
                self.assertEqual(hashlib.sha256(copies[0]).hexdigest(), hashlib.sha256(payload).hexdigest())

    def test_corrupt_state_recovery_reconciles_every_durable_prefix(self):
        # MUTATION: parsing opaque state before its preserved move blocks reconciliation.
        stages = (
            "recover:journal-prepared",
            "recover:state",
            "recover:office",
            "recover:journal-committed",
        )
        original = b"corrupt-office-state\x00bytes"
        for stage in stages:
            with self.subTest(stage=stage):
                root, _ = self._pool(f"corrupt-{stage.replace(':', '-')}")
                state_path = root / "offices" / "O1" / "office-state.json"
                state_path.write_bytes(original)
                self._abrupt(_crash_recover, str(root), stage, 0)
                journal_path = next((root / "runtime" / "transactions").iterdir())
                journal = json.loads(journal_path.read_text())
                state_move = next(item for item in journal["moves"] if item["kind"] == "state")
                archived_state = Path(state_move["destination"])

                if stage == "recover:journal-prepared":
                    self.assertEqual(state_path.read_bytes(), original)
                    self.assertFalse(archived_state.exists())
                elif stage == "recover:state":
                    self.assertFalse(state_path.exists())
                    self.assertEqual(archived_state.read_bytes(), original)
                else:
                    self.assertEqual(json.loads(state_path.read_text()), journal["after_state"])
                    self.assertEqual(archived_state.read_bytes(), original)

                Pool(root).recover(
                    root / "operator-secrets" / "recovery-key-O1", "O1", 0
                )

                self.assertEqual(
                    Pool(root).public_status()["offices"][0],
                    {"office_id": "O1", "status": "free", "generation": 0},
                )
                self.assertEqual(list((root / "runtime" / "transactions").iterdir()), [])
                preserved = list(
                    (root / "offices" / "O1" / "history").rglob(
                        "unknown-office-state.json"
                    )
                )
                self.assertEqual([path.read_bytes() for path in preserved], [original])

    def test_interrupted_recovery_retries_directly_with_exact_key(self):
        # MUTATION: retry rejects the free post-state before replaying its pending journal.
        stages = (
            "recover:journal-prepared",
            "recover:authority",
            "recover:pointer",
            "recover:office",
            "recover:journal-committed",
        )
        for stage in stages:
            with self.subTest(stage=stage):
                root, pool = self._pool(f"direct-{stage.replace(':', '-')}")
                authority = pool.claim("holder", "task", self.project, "pinned")
                (root / "offices" / "O1" / "work" / "partial.bin").write_bytes(
                    b"direct-recovery"
                )
                with self.assertRaises(PoolError):
                    pool.release(authority)
                key = root / "operator-secrets" / "recovery-key-O1"
                self._abrupt(_crash_recover, str(root), stage, 1)

                Pool(root).recover(key, "O1", 1)

                self.assertEqual(
                    Pool(root).public_status()["offices"][0],
                    {"office_id": "O1", "status": "free", "generation": 1},
                )
                self.assertEqual(list((root / "runtime" / "transactions").iterdir()), [])
                preserved = list((root / "offices" / "O1" / "history").rglob("partial.bin"))
                self.assertEqual([path.read_bytes() for path in preserved], [b"direct-recovery"])


if __name__ == "__main__":
    unittest.main()
