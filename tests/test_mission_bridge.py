import hashlib
import json
import os
import stat
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from internal.mission_bridge import MissionBridgeError, start_or_resume
from internal.pool import Pool
from internal.windows_paths import canonical_windows_path


FAKE = r'''#!/usr/bin/env python3
import json, pathlib, sys
home = pathlib.Path(sys.argv[sys.argv.index("--home") + 1])
home.mkdir(parents=True, exist_ok=True)
log = home / "fake-arguments.jsonl"
with log.open("a", encoding="utf-8") as stream:
    stream.write(json.dumps(sys.argv[1:]) + "\n")
if "inspect" in sys.argv:
    mission_id = sys.argv[sys.argv.index("--mission") + 1]
    objective_digest = (home / "objective-digest").read_text()
else:
    task_text = sys.argv[-1]
    import hashlib
    objective_digest = "sha256:" + hashlib.sha256(task_text.encode()).hexdigest()
    (home / "objective-digest").write_text(objective_digest)
    mission_id = "mission-0123456789abcdef"
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

    def test_record_digest_detects_private_state_tampering(self):
        # MUTATION: resuming without checking the wrapper record accepts field edits.
        readback = start_or_resume(self.claim_path, self.task_text)
        record = json.loads(readback.record.read_text(encoding="utf-8"))
        record["office_id"] = "O5"
        readback.record.write_text(json.dumps(record), encoding="utf-8")
        with self.assertRaises(MissionBridgeError) as raised:
            start_or_resume(self.claim_path, self.task_text)
        self.assertEqual(raised.exception.code, "mission-record-mismatch")

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
