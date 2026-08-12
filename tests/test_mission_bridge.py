import hashlib
import hmac
import json
import os
import stat
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import internal.mission_bridge as mission_bridge
from internal.mission_bridge import MissionBridgeError, start_or_resume
from internal.pool import Pool
from internal.windows_paths import canonical_windows_path


FAKE = r'''#!/usr/bin/env python3
import json, os, pathlib, sys, time
mode = os.environ.get("AO_TEST_FAKE_MODE")
if mode == "slow-large":
    sys.stdout.write("x" * 70000)
    sys.stdout.flush()
    time.sleep(10)
    raise SystemExit(0)
home = pathlib.Path(sys.argv[sys.argv.index("--home") + 1])
home.mkdir(parents=True, exist_ok=True)
log = home / "fake-arguments.jsonl"
with log.open("a", encoding="utf-8") as stream:
    stream.write(json.dumps(sys.argv[1:]) + "\n")
(home / "fake-cwd").write_text(str(pathlib.Path.cwd()))
if "inspect" in sys.argv:
    mission_id = sys.argv[sys.argv.index("--mission") + 1]
    if mode == "inspect-mismatch":
        mission_id = "mission-fedcba9876543210"
    objective_digest = (home / "objective-digest").read_text()
else:
    task_text = sys.argv[-1]
    import hashlib
    objective_digest = "sha256:" + hashlib.sha256(task_text.encode()).hexdigest()
    (home / "objective-digest").write_text(objective_digest)
    mission_id = "mission-0123456789abcdef"
if mode == "invalid-id":
    mission_id = "mission-not-valid"
print(json.dumps({
    "schema": "ao.mission.record.v0.1",
    "mission_id": mission_id,
    "objective_digest": objective_digest,
    "status": "active",
    "current_route": "ao-blueprint"
}))
'''


class MissionBridgeTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory(
            dir=Path(tempfile.gettempdir()).resolve()
        )
        self.base = Path(self.temporary_directory.name).resolve()
        self.project = self.base / "project"
        self.pool_root = self.base / "pool"
        self.project.mkdir()
        self.pool = Pool(self.pool_root)
        self.pool.initialize()
        self.task_text = "Explain bounded status; do not execute a shell"
        self.claim_path = self.pool.claim(
            "chat-a", self.task_text, self.project, "conversation"
        )
        supplied_fake = os.environ.get("AO_TEST_FAKE_MISSION")
        if os.name == "nt" and supplied_fake:
            self.executable = self.base / "ao-mission.exe"
            shutil.copy2(supplied_fake, self.executable)
        else:
            self.executable = self.base / "ao-mission"
            self.executable.write_text(FAKE, encoding="utf-8")
            self.executable.chmod(self.executable.stat().st_mode | stat.S_IXUSR)
        digest = hashlib.sha256(self.executable.read_bytes()).hexdigest()
        self.lock = self.base / "components.lock.json"
        self.lock.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "components": [
                        {
                            "name": "ao-mission",
                            "asset": self.executable.name,
                            "sha256": digest,
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        self.configuration = mock.patch.multiple(
            "internal.mission_bridge",
            MISSION_EXECUTABLE=self.executable,
            COMPONENT_LOCK=self.lock,
        )
        self.configuration.start()

    def tearDown(self):
        self.configuration.stop()
        self.temporary_directory.cleanup()

    def _replace_executable(self, body):
        replacement = self.executable.with_name("replacement-ao-mission")
        replacement.write_text(body, encoding="utf-8")
        replacement.chmod(replacement.stat().st_mode | stat.S_IXUSR)
        os.replace(replacement, self.executable)

    def _link_directory(self, link, target):
        if os.name == "nt":
            subprocess.run(
                ["cmd.exe", "/d", "/c", "mklink", "/J", str(link), str(target)],
                check=True,
                capture_output=True,
            )
        else:
            link.symlink_to(target, target_is_directory=True)

    def _swap_directory(self, directory, outside):
        parked = directory.with_name(directory.name + "-parked")
        try:
            os.replace(directory, parked)
        except OSError:
            if os.name != "nt":
                raise
            return None
        self._link_directory(directory, outside)
        return parked

    def test_starts_verified_mission_with_argument_array_and_project_owned_state(self):
        # MUTATION: shell=True would interpret the punctuation in the objective.
        before = {path.relative_to(self.project) for path in self.project.rglob("*")}
        readback = start_or_resume(self.claim_path, self.task_text)
        self.assertEqual(readback.mission_id, "mission-0123456789abcdef")
        self.assertEqual(readback.current_route, "ao-blueprint")
        self.assertFalse(readback.resumed)
        self.assertFalse(readback.executes_work)
        self.assertFalse(readback.approves_policy)
        self.assertFalse(readback.mutates_repositories)
        self.assertTrue(readback.record.is_relative_to(self.project / ".ao"))
        created = {path.relative_to(self.project) for path in self.project.rglob("*")} - before
        self.assertTrue(created)
        self.assertTrue(all(path.parts[0] == ".ao" for path in created))
        arguments = json.loads(
            (self.project / ".ao/mission/fake-arguments.jsonl")
            .read_text(encoding="utf-8")
            .splitlines()[0]
        )
        self.assertEqual(arguments[0], "--home")
        expected_home = str(self.project / ".ao/mission")
        if os.name == "nt":
            self.assertEqual(
                canonical_windows_path(arguments[1]),
                canonical_windows_path(expected_home),
            )
        else:
            self.assertEqual(arguments[1], expected_home)
        self.assertEqual(arguments[2:], ["start", self.task_text])
        recorded_cwd = (self.project / ".ao/mission/fake-cwd").read_text()
        if os.name == "nt":
            self.assertEqual(
                canonical_windows_path(recorded_cwd),
                canonical_windows_path(str(self.project)),
            )
        else:
            self.assertEqual(recorded_cwd, str(self.project))

    def test_rejects_linked_project_private_storage(self):
        # MUTATION: lexical `.ao` containment writes through a link outside project.
        outside = self.base / "outside"
        outside.mkdir()
        self._link_directory(self.project / ".ao", outside)
        with self.assertRaises(MissionBridgeError) as raised:
            start_or_resume(self.claim_path, self.task_text)
        self.assertEqual(raised.exception.code, "mission-storage-unsafe")
        self.assertEqual(list(outside.iterdir()), [])

    def test_record_write_retains_validated_storage_directory(self):
        # MUTATION: returning a checked path lets office-pool swap before record/HMAC writes.
        outside = self.base / "outside-record"
        outside.mkdir()
        real_private_file = mission_bridge._private_file
        parked = []

        def swap_after_open(project, directories, name):
            result = real_private_file(project, directories, name)
            if not parked:
                parked.append(
                    self._swap_directory(project.joinpath(*directories), outside)
                )
            return result

        with mock.patch.object(mission_bridge, "_private_file", swap_after_open):
            try:
                readback = start_or_resume(self.claim_path, self.task_text)
            except MissionBridgeError:
                readback = None
        self.assertEqual(list(outside.iterdir()), [])
        if readback is not None:
            self.assertEqual(readback.mission_id, "mission-0123456789abcdef")
        if os.name != "nt":
            self.assertIsNotNone(parked[0])

    def test_mission_home_retains_validated_directory_through_launch(self):
        # MUTATION: passing the checked Mission home pathname follows a swap at launch.
        outside = self.base / "outside-home"
        outside.mkdir()
        real_run = mission_bridge._run
        parked = []

        def swap_before_launch(*arguments, **keywords):
            if not parked:
                parked.append(
                    self._swap_directory(self.project / ".ao/mission", outside)
                )
            return real_run(*arguments, **keywords)

        with mock.patch.object(mission_bridge, "_run", swap_before_launch):
            try:
                readback = start_or_resume(self.claim_path, self.task_text)
            except MissionBridgeError:
                readback = None
        self.assertEqual(list(outside.iterdir()), [])
        if readback is not None:
            self.assertEqual(readback.mission_id, "mission-0123456789abcdef")
        if os.name != "nt":
            self.assertIsNotNone(parked[0])

    def test_verified_open_executable_survives_path_substitution(self):
        # MUTATION: hashing then reopening the executable launches substituted bytes.
        malicious = FAKE.replace(
            'mission_id = "mission-0123456789abcdef"',
            'mission_id = "mission-fedcba9876543210"',
        )
        with mission_bridge._open_verified_executable() as verified:
            if os.name == "nt":
                with self.assertRaises(OSError):
                    self._replace_executable(malicious)
            else:
                self._replace_executable(malicious)
            value = mission_bridge._run(
                ["--home", str(self.project / ".ao/mission"), "start", self.task_text],
                self.project,
                verified,
            )
        self.assertEqual(value["mission_id"], "mission-0123456789abcdef")

    @unittest.skipIf(os.name == "nt", "descriptor execution is POSIX-specific")
    def test_launch_uses_verified_descriptor_after_private_copy_substitution(self):
        # MUTATION: executing the verified copy pathname reopens attacker replacement bytes.
        malicious = FAKE.replace(
            'mission_id = "mission-0123456789abcdef"',
            'mission_id = "mission-fedcba9876543210"',
        )
        with mission_bridge._open_verified_executable() as verified:
            replacement = verified.path.with_name("replacement-verified-copy")
            replacement.write_text(malicious, encoding="utf-8")
            replacement.chmod(replacement.stat().st_mode | stat.S_IXUSR)
            os.replace(replacement, verified.path)
            try:
                value = mission_bridge._run(
                    ["--home", str(self.project / ".ao/mission"), "start", self.task_text],
                    self.project,
                    verified,
                )
            except MissionBridgeError as error:
                self.assertEqual(error.code, "mission-launch-failed")
            else:
                self.assertEqual(value["mission_id"], "mission-0123456789abcdef")

    def test_same_receipt_and_objective_resume_exact_mission(self):
        # MUTATION: always starting creates duplicate Mission records for one task.
        first = start_or_resume(self.claim_path, self.task_text)
        second = start_or_resume(self.claim_path, self.task_text)
        self.assertEqual(second.mission_id, first.mission_id)
        self.assertTrue(second.resumed)
        calls = [
            json.loads(line)
            for line in (self.project / ".ao/mission/fake-arguments.jsonl")
            .read_text(encoding="utf-8")
            .splitlines()
        ]
        self.assertEqual(calls[1][-5:], ["mission", "inspect", "--mission", first.mission_id, "--json"])

    def test_same_objective_different_chats_have_distinct_records(self):
        # MUTATION: task-digest-only names collide for independent chat authorities.
        other = self.pool.claim("chat-b", self.task_text, self.project, "conversation")
        first = start_or_resume(self.claim_path, self.task_text)
        second = start_or_resume(other, self.task_text)
        self.assertNotEqual(first.record, second.record)
        self.assertFalse(second.resumed)

    def test_resume_rejects_inspect_mission_identity_substitution(self):
        # MUTATION: trusting inspect readback permits a different Mission identity.
        first = start_or_resume(self.claim_path, self.task_text)
        with mock.patch.dict(os.environ, {"AO_TEST_FAKE_MODE": "inspect-mismatch"}):
            with self.assertRaises(MissionBridgeError) as raised:
                start_or_resume(self.claim_path, self.task_text)
        self.assertEqual(raised.exception.code, "mission-record-mismatch")
        self.assertEqual(
            json.loads(first.record.read_text(encoding="utf-8"))["mission_id"],
            first.mission_id,
        )

    def test_rejects_wrong_objective_or_receipt_before_launch(self):
        # MUTATION: trusting caller text permits cross-task Mission reuse.
        other = self.pool.claim("chat-b", "other objective", self.project, "conversation")
        for receipt, objective in (
            (self.claim_path, "changed objective"),
            (other, self.task_text),
        ):
            with self.subTest(authority_name=receipt.name, task_text=objective):
                with self.assertRaises(MissionBridgeError) as raised:
                    start_or_resume(receipt, objective)
                self.assertEqual(raised.exception.code, "task-mismatch")

    def test_rejects_executable_digest_mismatch_without_creating_mission_state(self):
        # MUTATION: checking only the executable name accepts substituted bytes.
        self.executable.write_text(FAKE + "# substitution\n", encoding="utf-8")
        with self.assertRaises(MissionBridgeError) as raised:
            start_or_resume(self.claim_path, self.task_text)
        self.assertEqual(raised.exception.code, "mission-identity-mismatch")
        self.assertFalse((self.project / ".ao").exists())

    def test_rejects_unbounded_or_authority_escalating_readback(self):
        # MUTATION: accepting arbitrary stdout or true authority flags widens Mission.
        escalation = FAKE.replace(
            '"current_route": "ao-blueprint"',
            '"current_route": "ao-blueprint", "executes_work": True',
        )
        for body, code in (
            (escalation, "mission-authority-escalation"),
            ('#!/usr/bin/env python3\nprint("x" * 70000)\n', "mission-output-too-large"),
        ):
            with self.subTest(code=code):
                mode = "escalation" if code.endswith("escalation") else "large"
                if os.name != "nt":
                    self.executable.write_text(body, encoding="utf-8")
                    self.executable.chmod(self.executable.stat().st_mode | stat.S_IXUSR)
                    digest = hashlib.sha256(self.executable.read_bytes()).hexdigest()
                    value = json.loads(self.lock.read_text(encoding="utf-8"))
                    value["components"][0]["sha256"] = digest
                    self.lock.write_text(json.dumps(value), encoding="utf-8")
                with mock.patch.dict(os.environ, {"AO_TEST_FAKE_MODE": mode}):
                    with self.assertRaises(MissionBridgeError) as raised:
                        start_or_resume(self.claim_path, self.task_text)
                self.assertEqual(raised.exception.code, code)

    def test_terminates_oversized_output_while_process_is_running(self):
        # MUTATION: checking temporary-file size after exit waits for an abusive child.
        if os.name != "nt":
            self.executable.write_text(FAKE, encoding="utf-8")
            self.executable.chmod(self.executable.stat().st_mode | stat.S_IXUSR)
            value = json.loads(self.lock.read_text(encoding="utf-8"))
            value["components"][0]["sha256"] = hashlib.sha256(
                self.executable.read_bytes()
            ).hexdigest()
            self.lock.write_text(json.dumps(value), encoding="utf-8")
        started = time.monotonic()
        with mock.patch.dict(os.environ, {"AO_TEST_FAKE_MODE": "slow-large"}):
            with self.assertRaises(MissionBridgeError) as raised:
                start_or_resume(self.claim_path, self.task_text)
        self.assertEqual(raised.exception.code, "mission-output-too-large")
        self.assertLess(time.monotonic() - started, 5)

    def test_record_digest_detects_private_state_tampering(self):
        # MUTATION: resuming without checking the wrapper record accepts field edits.
        readback = start_or_resume(self.claim_path, self.task_text)
        record = json.loads(readback.record.read_text(encoding="utf-8"))
        record["office_id"] = "O5"
        readback.record.write_text(json.dumps(record), encoding="utf-8")
        with self.assertRaises(MissionBridgeError) as raised:
            start_or_resume(self.claim_path, self.task_text)
        self.assertEqual(raised.exception.code, "mission-record-mismatch")

    def test_recomputable_digest_cannot_forge_record_authentication(self):
        # MUTATION: an unkeyed adjacent digest lets an editor reseal altered state.
        readback = start_or_resume(self.claim_path, self.task_text)
        value = json.loads(readback.record.read_text(encoding="utf-8"))
        value["mission_status"] = "complete"
        raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
        readback.record.write_bytes(raw)
        readback.record.with_suffix(".hmac").write_text(
            hashlib.sha256(raw).hexdigest() + "\n", encoding="ascii"
        )
        with self.assertRaises(MissionBridgeError) as raised:
            start_or_resume(self.claim_path, self.task_text)
        self.assertEqual(raised.exception.code, "mission-record-mismatch")

    def test_production_rejects_schema_invalid_record_even_with_valid_hmac(self):
        # MUTATION: treating the schema as documentation accepts invalid Mission IDs.
        readback = start_or_resume(self.claim_path, self.task_text)
        value = json.loads(readback.record.read_text(encoding="utf-8"))
        value["mission_id"] = "invalid"
        raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
        readback.record.write_bytes(raw)
        readback.record.with_suffix(".hmac").write_text(
            hmac.new(self.claim_path.read_bytes(), raw, hashlib.sha256).hexdigest() + "\n",
            encoding="ascii",
        )
        with self.assertRaises(MissionBridgeError) as raised:
            start_or_resume(self.claim_path, self.task_text)
        self.assertEqual(raised.exception.code, "mission-record-mismatch")

    def test_production_distinguishes_json_boolean_from_integer_const(self):
        # MUTATION: Python equality treats true as the schema_version integer 1.
        readback = start_or_resume(self.claim_path, self.task_text)
        value = json.loads(readback.record.read_text(encoding="utf-8"))
        value["schema_version"] = True
        raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
        readback.record.write_bytes(raw)
        readback.record.with_suffix(".hmac").write_text(
            hmac.new(self.claim_path.read_bytes(), raw, hashlib.sha256).hexdigest() + "\n",
            encoding="ascii",
        )
        with self.assertRaises(MissionBridgeError) as raised:
            start_or_resume(self.claim_path, self.task_text)
        self.assertEqual(raised.exception.code, "mission-record-mismatch")

    def test_rejects_schema_invalid_initial_mission_readback(self):
        # MUTATION: loose string checks persist an invalid Mission identifier.
        with mock.patch.dict(os.environ, {"AO_TEST_FAKE_MODE": "invalid-id"}):
            with self.assertRaises(MissionBridgeError) as raised:
                start_or_resume(self.claim_path, self.task_text)
        self.assertEqual(raised.exception.code, "invalid-mission-readback")

    def test_mission_record_schema_has_exact_persisted_shape(self):
        # MUTATION: an open schema permits unreviewed authority fields in durable state.
        record = start_or_resume(self.claim_path, self.task_text).record
        value = json.loads(record.read_text(encoding="utf-8"))
        schema = json.loads(
            (Path(__file__).parents[1] / "schemas/mission-record.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(set(value), set(schema["required"]))
        self.assertEqual(set(value), set(schema["properties"]))


if __name__ == "__main__":
    unittest.main()
