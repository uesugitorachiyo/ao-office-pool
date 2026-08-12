import hashlib
import hmac
import json
import os
import stat
import subprocess
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

import internal.conversation_lifecycle as conversation_lifecycle
from internal.conversation_lifecycle import (
    ConversationError,
    ConversationEvent,
    ConversationState,
    transition,
)
from internal.pool import Pool
from internal.mission_bridge import start_or_resume


MISSION_FAKE = r'''#!/usr/bin/env python3
import hashlib, json, pathlib, sys
home = pathlib.Path(sys.argv[sys.argv.index("--home") + 1])
home.mkdir(parents=True, exist_ok=True)
if "inspect" in sys.argv:
    mission_id = sys.argv[sys.argv.index("--mission") + 1]
    objective_digest = (home / "objective-digest").read_text()
else:
    objective_digest = "sha256:" + hashlib.sha256(sys.argv[-1].encode()).hexdigest()
    (home / "objective-digest").write_text(objective_digest)
    mission_id = "mission-0123456789abcdef"
print(json.dumps({"mission_id":mission_id,"objective_digest":objective_digest,
                  "status":"active","current_route":"ao-blueprint"}))
'''


class ConversationLifecycleTests(unittest.TestCase):
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
        self.chat = "chat-a"
        self.task = "task-a"
        supplied_fake = os.environ.get("AO_TEST_FAKE_MISSION")
        if os.name == "nt" and supplied_fake:
            self.executable = self.base / "ao-mission.exe"
            import shutil

            shutil.copy2(supplied_fake, self.executable)
        else:
            self.executable = self.base / "ao-mission"
            self.executable.write_text(MISSION_FAKE, encoding="utf-8")
            self.executable.chmod(self.executable.stat().st_mode | stat.S_IXUSR)
        self.lock = self.base / "components.lock.json"
        self.lock.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "components": [
                        {
                            "name": "ao-mission",
                            "asset": self.executable.name,
                            "sha256": hashlib.sha256(self.executable.read_bytes()).hexdigest(),
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

    def _state(self, mode="conversation"):
        claim_path = self.pool.claim(self.chat, self.task, self.project, mode)
        authority = json.loads(claim_path.read_text(encoding="utf-8"))
        start_or_resume(claim_path, self.task)
        state = ConversationState(
            claim_path,
            self.chat,
            self.task,
            self.project,
            authority["office_id"],
            authority["generation"],
            mode,
            "caller-controlled-value",
        )
        return claim_path, state

    def _event(self, kind, state, **changes):
        claim_path = changes.pop("receipt", state.receipt)
        values = {
            "kind": kind,
            "chat_id": state.chat_id,
            "task_id": state.task_id,
            "project": state.project,
            "office_id": state.office_id,
            "generation": state.generation,
            "platform_goal": "active",
        }
        values.update(changes)
        return ConversationEvent(
            values["kind"],
            claim_path,
            values["chat_id"],
            values["task_id"],
            values["project"],
            values["office_id"],
            values["generation"],
            values["platform_goal"],
            values.get("replacement_task_id"),
            values.get("summary"),
            values.get("next_action"),
        )

    def test_continuation_is_not_pinned(self):
        # MUTATION: treating any continuation as long work changes conversation mode.
        _, state = self._state()
        result = transition(self._event("continue", state), state)
        self.assertEqual(result.action, "continue")
        self.assertEqual(result.state.mode, "conversation")
        self.assertFalse(result.released)

    def test_long_task_requires_explicit_pinned_receipt(self):
        # MUTATION: pinning a conversation receipt desynchronizes durable pool state.
        _, ordinary = self._state()
        with self.assertRaises(ConversationError) as raised:
            transition(self._event("pin", ordinary), ordinary)
        self.assertEqual(raised.exception.code, "pin-requires-pinned-receipt")
        self.pool.release(ordinary.receipt)
        _, pinned = self._state("pinned")
        result = transition(self._event("pin", pinned), pinned)
        self.assertEqual(result.action, "pin")
        self.assertEqual(result.state.mode, "pinned")

    def test_resume_proves_all_identities(self):
        # MUTATION: omitting one equality permits a cross-task allocation resume.
        _, state = self._state()
        other_project = self.base / "other-project"
        other_project.mkdir()
        mutations = (
            ("task_id", "task-b"),
            ("chat_id", "chat-b"),
            ("project", other_project),
            ("office_id", "O2"),
            ("generation", state.generation + 1),
            ("receipt", self.base / "other.receipt.json"),
        )
        for field, value in mutations:
            with self.subTest(field=field):
                with self.assertRaises(ConversationError) as raised:
                    transition(self._event("resume", state, **{field: value}), state)
                self.assertEqual(raised.exception.code, "identity-mismatch")

    def test_cross_chat_denial_does_not_mutate_state(self):
        # MUTATION: task-only resume authorizes another chat.
        _, state = self._state()
        before = state.receipt.read_bytes()
        with self.assertRaises(ConversationError):
            transition(self._event("continue", state, chat_id="other-chat"), state)
        self.assertEqual(state.receipt.read_bytes(), before)
        self.assertTrue((self.project / ".ao/mission").is_dir())

    def test_conversation_completion_needs_no_file(self):
        # MUTATION: a file-deliverable gate strands conversational work.
        receipt, state = self._state()
        result = transition(self._event("complete", state), state)
        self.assertEqual(result.action, "complete")
        self.assertTrue(result.released)
        self.assertFalse(receipt.exists())

    def test_goal_state_conflict_stops(self):
        # MUTATION: comparing two caller strings ignores authenticated Mission state.
        receipt, state = self._state()
        state = replace(state, mission_goal="complete")
        result = transition(
            self._event("continue", state, platform_goal="complete"), state
        )
        self.assertEqual(result.action, "stop")
        self.assertEqual(result.reason, "goal-state-conflict:active!=complete")
        self.assertFalse(result.released)
        self.assertTrue(receipt.exists())

    def test_linked_checkpoint_storage_stops_before_release(self):
        # MUTATION: lexical checkpoint paths write outside the connected project.
        receipt, state = self._state()
        outside = self.base / "outside-checkpoints"
        outside.mkdir()
        self._link_directory(self.project / ".ao/checkpoints", outside)
        with self.assertRaises(ConversationError) as raised:
            transition(self._event("cancel", state), state)
        self.assertEqual(raised.exception.code, "conversation-storage-unsafe")
        self.assertTrue(receipt.exists())
        self.assertEqual(list(outside.iterdir()), [])

    def test_checkpoint_write_retains_validated_storage_directory(self):
        # MUTATION: a checked checkpoint pathname can be swapped before atomic write.
        _, state = self._state()
        outside = self.base / "outside-checkpoint-race"
        outside.mkdir()
        real_private_file = conversation_lifecycle._private_file
        parked = []

        def swap_after_open(project, directories, name):
            result = real_private_file(project, directories, name)
            if not parked:
                parked.append(
                    self._swap_directory(project.joinpath(*directories), outside)
                )
            return result

        with mock.patch.object(
            conversation_lifecycle, "_private_file", swap_after_open
        ):
            try:
                result = transition(self._event("cancel", state), state)
            except ConversationError:
                result = None
        self.assertEqual(list(outside.iterdir()), [])
        if result is not None:
            self.assertEqual(result.action, "cancel")
        if os.name != "nt":
            self.assertIsNotNone(parked[0])

    def test_cancel_checkpoints_before_release(self):
        # MUTATION: releasing first loses the final restart checkpoint on failure.
        receipt, state = self._state()
        real_release = Pool.release

        def checked_release(pool, supplied):
            checkpoints = list((self.project / ".ao/checkpoints").glob("*.json"))
            self.assertEqual(len(checkpoints), 1)
            return real_release(pool, supplied)

        with mock.patch.object(Pool, "release", checked_release):
            result = transition(self._event("cancel", state), state)
        self.assertTrue(result.released)
        self.assertEqual(result.action, "cancel")
        self.assertFalse(receipt.exists())
        checkpoint = json.loads(result.checkpoint.read_text(encoding="utf-8"))
        self.assertEqual(checkpoint["event"], "cancel")

    def test_replacement_checkpoints_old_task_before_release(self):
        # MUTATION: replacing in place leaves the old receipt authoritative.
        receipt, state = self._state()
        result = transition(
            self._event("replace", state, replacement_task_id="task-b"), state
        )
        self.assertTrue(result.released)
        self.assertFalse(receipt.exists())
        self.assertEqual(
            result.next_task_digest,
            hashlib.sha256(b"task-b").hexdigest(),
        )
        self.assertTrue(result.checkpoint.is_relative_to(self.project / ".ao"))

    def test_compression_handoff_recovers_same_context(self):
        # MUTATION: accepting an unbound summary resumes context for another identity.
        _, state = self._state()
        compressed = transition(
            self._event(
                "compress",
                state,
                summary="Bounded work is awaiting operator input.",
                next_action="Ask for the missing input.",
            ),
            state,
        )
        self.assertEqual(compressed.action, "compress")
        self.assertTrue(compressed.handoff.is_relative_to(self.project / ".ao"))
        reconstructed = replace(compressed.state, handoff=None, handoff_digest=None)
        resumed = transition(self._event("resume", reconstructed), reconstructed)
        self.assertEqual(resumed.action, "resume")
        self.assertEqual(resumed.handoff, compressed.handoff)

    def test_linked_handoff_storage_is_rejected(self):
        # MUTATION: lexical handoff paths can escape through a linked directory.
        _, state = self._state()
        outside = self.base / "outside-handoffs"
        outside.mkdir()
        self._link_directory(self.project / ".ao/mission/handoffs", outside)
        with self.assertRaises(ConversationError) as raised:
            transition(
                self._event("compress", state, summary="one", next_action="two"),
                state,
            )
        self.assertEqual(raised.exception.code, "conversation-storage-unsafe")
        self.assertEqual(list(outside.iterdir()), [])

    def test_handoff_write_retains_validated_storage_directory(self):
        # MUTATION: a checked handoff pathname can be swapped before JSON/HMAC writes.
        _, state = self._state()
        outside = self.base / "outside-handoff-race"
        outside.mkdir()
        real_private_file = conversation_lifecycle._private_file
        parked = []

        def swap_after_open(project, directories, name):
            result = real_private_file(project, directories, name)
            if not parked:
                parked.append(
                    self._swap_directory(project.joinpath(*directories), outside)
                )
            return result

        with mock.patch.object(
            conversation_lifecycle, "_private_file", swap_after_open
        ):
            try:
                result = transition(
                    self._event("compress", state, summary="one", next_action="two"),
                    state,
                )
            except ConversationError:
                result = None
        self.assertEqual(list(outside.iterdir()), [])
        if result is not None:
            self.assertEqual(result.action, "compress")
        if os.name != "nt":
            self.assertIsNotNone(parked[0])

    def test_tampered_compression_handoff_is_denied(self):
        # MUTATION: trusting handoff fields without its digest accepts altered context.
        _, state = self._state()
        compressed = transition(
            self._event("compress", state, summary="one", next_action="two"), state
        )
        handoff = json.loads(compressed.handoff.read_text(encoding="utf-8"))
        handoff["summary"] = "altered"
        compressed.handoff.write_text(json.dumps(handoff), encoding="utf-8")
        handoff_raw = compressed.handoff.read_bytes()
        compressed.handoff.with_suffix(".hmac").write_text(
            hashlib.sha256(handoff_raw).hexdigest() + "\n", encoding="ascii"
        )
        reconstructed = replace(compressed.state, handoff=None, handoff_digest=None)
        with self.assertRaises(ConversationError) as raised:
            transition(self._event("resume", reconstructed), reconstructed)
        self.assertEqual(raised.exception.code, "handoff-mismatch")

    def test_schema_invalid_handoff_is_denied_even_with_valid_hmac(self):
        # MUTATION: production parsing ignores declared string-length constraints.
        _, state = self._state()
        compressed = transition(
            self._event("compress", state, summary="one", next_action="two"), state
        )
        value = json.loads(compressed.handoff.read_text(encoding="utf-8"))
        value["summary"] = "x" * 4097
        raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
        compressed.handoff.write_bytes(raw)
        compressed.handoff.with_suffix(".hmac").write_text(
            hmac.new(state.receipt.read_bytes(), raw, hashlib.sha256).hexdigest() + "\n",
            encoding="ascii",
        )
        reconstructed = replace(compressed.state, handoff=None, handoff_digest=None)
        with self.assertRaises(ConversationError) as raised:
            transition(self._event("resume", reconstructed), reconstructed)
        self.assertEqual(raised.exception.code, "handoff-mismatch")

    def test_context_handoff_schema_has_exact_persisted_shape(self):
        # MUTATION: an open handoff schema permits context or authority field growth.
        _, state = self._state()
        result = transition(
            self._event("compress", state, summary="one", next_action="two"), state
        )
        value = json.loads(result.handoff.read_text(encoding="utf-8"))
        schema = json.loads(
            (Path(__file__).parents[1] / "schemas/context-handoff.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(set(value), set(schema["required"]))
        self.assertEqual(set(value), set(schema["properties"]))

    def test_mission_authority_escalation_is_denied(self):
        # MUTATION: routing an execution-class event grants Mission AO2 authority.
        _, state = self._state()
        for kind in ("execute", "approve", "provider", "publish", "deploy", "mutate"):
            with self.subTest(kind=kind):
                result = transition(self._event(kind, state), state)
                self.assertEqual(result.action, "deny")
                self.assertEqual(result.reason, "mission-has-no-authority")
                self.assertFalse(result.released)


if __name__ == "__main__":
    unittest.main()
