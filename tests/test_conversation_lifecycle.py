import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from internal.conversation_lifecycle import (
    ConversationError,
    ConversationEvent,
    ConversationState,
    transition,
)
from internal.pool import Pool


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

    def tearDown(self):
        self.temporary_directory.cleanup()

    def _state(self, mode="conversation"):
        claim_path = self.pool.claim(self.chat, self.task, self.project, mode)
        authority = json.loads(claim_path.read_text(encoding="utf-8"))
        state = ConversationState(
            claim_path,
            self.chat,
            self.task,
            self.project,
            authority["office_id"],
            authority["generation"],
            mode,
            "active",
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
        self.assertFalse((self.project / ".ao").exists())

    def test_conversation_completion_needs_no_file(self):
        # MUTATION: a file-deliverable gate strands conversational work.
        receipt, state = self._state()
        result = transition(self._event("complete", state), state)
        self.assertEqual(result.action, "complete")
        self.assertTrue(result.released)
        self.assertFalse(receipt.exists())

    def test_goal_state_conflict_stops(self):
        # MUTATION: preferring either Goal source silently continues disagreement.
        receipt, state = self._state()
        result = transition(
            self._event("continue", state, platform_goal="complete"), state
        )
        self.assertEqual(result.action, "stop")
        self.assertEqual(result.reason, "goal-state-conflict:active!=complete")
        self.assertFalse(result.released)
        self.assertTrue(receipt.exists())

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
        resumed = transition(self._event("resume", compressed.state), compressed.state)
        self.assertEqual(resumed.action, "resume")
        self.assertEqual(resumed.handoff, compressed.handoff)

    def test_tampered_compression_handoff_is_denied(self):
        # MUTATION: trusting handoff fields without its digest accepts altered context.
        _, state = self._state()
        compressed = transition(
            self._event("compress", state, summary="one", next_action="two"), state
        )
        handoff = json.loads(compressed.handoff.read_text(encoding="utf-8"))
        handoff["summary"] = "altered"
        compressed.handoff.write_text(json.dumps(handoff), encoding="utf-8")
        with self.assertRaises(ConversationError) as raised:
            transition(self._event("resume", compressed.state), compressed.state)
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
