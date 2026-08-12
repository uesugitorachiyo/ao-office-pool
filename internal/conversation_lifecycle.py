import hashlib
import hmac
import json
from dataclasses import dataclass, replace
from pathlib import Path

from internal.mission_bridge import (
    MissionBridgeError,
    _canonical_bytes,
    _load_authenticated_record,
    _private_file,
    _read_authenticated,
    _validate_private_path,
    _write_authenticated,
)
from internal.pool import Pool, PoolError, _bytes_digest, _digest
from internal.transactions import atomic_write_json


HANDOFF_SCHEMA = Path(__file__).parents[1] / "schemas/context-handoff.schema.json"
_KINDS = frozenset(
    {
        "continue",
        "pin",
        "resume",
        "complete",
        "cancel",
        "replace",
        "compress",
        "execute",
        "approve",
        "provider",
        "publish",
        "deploy",
        "mutate",
    }
)
_ESCALATIONS = frozenset({"execute", "approve", "provider", "publish", "deploy", "mutate"})


class ConversationError(RuntimeError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class ConversationState:
    authority: Path
    chat_id: str
    task_id: str
    project: Path
    office_id: str
    generation: int
    mode: str
    mission_goal: str
    handoff: Path | None = None
    handoff_digest: str | None = None

    @property
    def receipt(self) -> Path:
        return self.authority


@dataclass(frozen=True)
class ConversationEvent:
    kind: str
    authority: Path
    chat_id: str
    task_id: str
    project: Path
    office_id: str
    generation: int
    platform_goal: str
    replacement_task_id: str | None = None
    summary: str | None = None
    next_action: str | None = None

    @property
    def receipt(self) -> Path:
        return self.authority


@dataclass(frozen=True)
class Transition:
    action: str
    state: ConversationState
    reason: str | None = None
    released: bool = False
    checkpoint: Path | None = None
    handoff: Path | None = None
    next_task_digest: str | None = None


def _load_authority(state: ConversationState) -> tuple[dict, bytes]:
    try:
        pool = Pool(state.receipt.parents[2])
        pool.resume(state.receipt)
        raw = state.receipt.read_bytes()
        authority = json.loads(raw)
        project = pool._project_record(state.project)
    except (OSError, IndexError, PoolError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise ConversationError("identity-mismatch") from error
    expected = {
        "holder_digest": _digest(state.chat_id),
        "task_digest": _digest(state.task_id),
        **project,
        "office_id": state.office_id,
        "generation": state.generation,
        "mode": state.mode,
    }
    if any(authority.get(field) != value for field, value in expected.items()):
        raise ConversationError("identity-mismatch")
    return authority, raw


def _validate_event(event: ConversationEvent, state: ConversationState) -> None:
    if event.kind not in _KINDS:
        raise ConversationError("invalid-event")
    for field in ("receipt", "chat_id", "task_id", "project", "office_id", "generation"):
        if getattr(event, field) != getattr(state, field):
            raise ConversationError("identity-mismatch")


def _mission_status(state: ConversationState) -> str:
    try:
        wrapper, _, _, _ = _load_authenticated_record(state.receipt, state.task_id)
        return wrapper["mission_status"]
    except (KeyError, MissionBridgeError) as error:
        raise ConversationError("mission-state-mismatch") from error


def _checkpoint(event: ConversationEvent, state: ConversationState) -> Path:
    value = {
        "schema_version": 1,
        "event": event.kind,
        "office_id": state.office_id,
        "generation": state.generation,
        "task_digest": _digest(state.task_id),
        "chat_digest": _digest(state.chat_id),
        "authority_digest": _bytes_digest(state.receipt.read_bytes()),
    }
    try:
        path = _private_file(
            state.project,
            (".ao", "checkpoints"),
            f"{state.office_id}-{state.generation}-{event.kind}.json",
        )
        atomic_write_json(path, value)
        _validate_private_path(path, state.project, directory=False)
        return path
    except (OSError, TypeError, ValueError, MissionBridgeError) as error:
        raise ConversationError("conversation-storage-unsafe") from error


def _release(state: ConversationState) -> None:
    root = state.receipt.parents[2]
    try:
        Pool(root).release(state.receipt)
    except PoolError as error:
        raise ConversationError(error.code) from error


def _handoff_path(
    state: ConversationState, authority: dict, authority_raw: bytes
) -> Path:
    identity = _canonical_bytes(
        {
            "authority_id": authority["authority_id"],
            "chat_digest": authority["holder_digest"],
            "task_digest": authority["task_digest"],
            "project_path": authority["project_path"],
        }
    )
    name = hmac.new(authority_raw, b"context-handoff\0" + identity, hashlib.sha256).hexdigest()
    try:
        return _private_file(
            state.project, (".ao", "mission", "handoffs"), name + ".json"
        )
    except MissionBridgeError as error:
        raise ConversationError("conversation-storage-unsafe") from error


def _handoff_value(
    event: ConversationEvent,
    state: ConversationState,
    authority: dict,
    authority_raw: bytes,
) -> dict:
    return {
        "schema_version": 1,
        "task_digest": authority["task_digest"],
        "chat_digest": authority["holder_digest"],
        "authority_digest": _bytes_digest(authority_raw),
        "project_path": authority["project_path"],
        "office_id": state.office_id,
        "generation": state.generation,
        "summary": event.summary,
        "next_action": event.next_action,
    }


def _read_handoff(
    state: ConversationState, authority: dict, authority_raw: bytes
) -> Path | None:
    path = _handoff_path(state, authority, authority_raw)
    seal = path.with_suffix(".hmac")
    if not path.exists() and not seal.exists():
        return None
    if not path.exists() or not seal.exists():
        raise ConversationError("handoff-mismatch")
    try:
        value = _read_authenticated(path, authority_raw, HANDOFF_SCHEMA, state.project)
        expected = {
            "task_digest": authority["task_digest"],
            "chat_digest": authority["holder_digest"],
            "authority_digest": _bytes_digest(authority_raw),
            "project_path": authority["project_path"],
            "office_id": state.office_id,
            "generation": state.generation,
        }
        if any(value.get(field) != expected_value for field, expected_value in expected.items()):
            raise ValueError("handoff identity mismatch")
        return path
    except (KeyError, TypeError, ValueError, MissionBridgeError) as error:
        raise ConversationError("handoff-mismatch") from error


def transition(event: ConversationEvent, state: ConversationState) -> Transition:
    if not isinstance(event, ConversationEvent) or not isinstance(state, ConversationState):
        raise ConversationError("invalid-transition")
    _validate_event(event, state)
    authority, authority_raw = _load_authority(state)
    mission_status = _mission_status(state)
    if event.platform_goal != mission_status:
        return Transition(
            "stop",
            state,
            reason=f"goal-state-conflict:{mission_status}!={event.platform_goal}",
        )
    if event.kind in _ESCALATIONS:
        return Transition("deny", state, reason="mission-has-no-authority")
    if event.kind == "pin":
        if state.mode != "pinned":
            raise ConversationError("pin-requires-pinned-receipt")
        return Transition("pin", state)
    if event.kind == "resume":
        return Transition(
            "resume", state, handoff=_read_handoff(state, authority, authority_raw)
        )
    if event.kind == "continue":
        return Transition("continue", state)
    if event.kind == "complete":
        _release(state)
        return Transition("complete", state, released=True)
    if event.kind in {"cancel", "replace"}:
        if event.kind == "replace" and not event.replacement_task_id:
            raise ConversationError("replacement-task-required")
        checkpoint = _checkpoint(event, state)
        _release(state)
        replacement = _digest(event.replacement_task_id) if event.replacement_task_id else None
        return Transition(
            event.kind,
            state,
            released=True,
            checkpoint=checkpoint,
            next_task_digest=replacement,
        )
    if not event.summary or not event.next_action:
        raise ConversationError("compression-context-required")
    path = _handoff_path(state, authority, authority_raw)
    value = _handoff_value(event, state, authority, authority_raw)
    try:
        _write_authenticated(path, value, authority_raw, HANDOFF_SCHEMA)
    except (OSError, TypeError, ValueError, MissionBridgeError) as error:
        if isinstance(error, MissionBridgeError) and error.code == "mission-storage-unsafe":
            raise ConversationError("conversation-storage-unsafe") from error
        raise ConversationError("handoff-mismatch") from error
    tag = path.with_suffix(".hmac").read_text(encoding="ascii").strip()
    compressed = replace(state, handoff=path, handoff_digest=tag)
    return Transition("compress", compressed, handoff=path)
