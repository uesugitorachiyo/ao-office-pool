import hashlib
import json
from dataclasses import dataclass, replace
from pathlib import Path

from internal.pool import Pool, PoolError, _bytes_digest, _digest
from internal.transactions import atomic_write_json


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


def _load_authority(state: ConversationState) -> dict:
    try:
        pool = Pool(state.receipt.parents[2])
        pool.resume(state.receipt)
        authority = json.loads(state.receipt.read_text(encoding="utf-8"))
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
    return authority


def _validate_event(event: ConversationEvent, state: ConversationState) -> None:
    if event.kind not in _KINDS:
        raise ConversationError("invalid-event")
    for field in ("receipt", "chat_id", "task_id", "project", "office_id", "generation"):
        if getattr(event, field) != getattr(state, field):
            raise ConversationError("identity-mismatch")


def _checkpoint(event: ConversationEvent, state: ConversationState) -> Path:
    root = state.project / ".ao/checkpoints"
    value = {
        "schema_version": 1,
        "event": event.kind,
        "office_id": state.office_id,
        "generation": state.generation,
        "task_digest": _digest(state.task_id),
        "chat_digest": _digest(state.chat_id),
        "authority_digest": _bytes_digest(state.receipt.read_bytes()),
    }
    path = root / f"{state.office_id}-{state.generation}-{event.kind}.json"
    atomic_write_json(path, value)
    return path


def _release(state: ConversationState) -> None:
    root = state.receipt.parents[2]
    try:
        Pool(root).release(state.receipt)
    except PoolError as error:
        raise ConversationError(error.code) from error


def _read_handoff(state: ConversationState) -> Path | None:
    if state.handoff is None and state.handoff_digest is None:
        return None
    try:
        raw = state.handoff.read_bytes()
        value = json.loads(raw)
        if _bytes_digest(raw) != state.handoff_digest:
            raise ValueError("handoff seal mismatch")
        if (
            value["task_digest"] != _digest(state.task_id)
            or value["chat_digest"] != _digest(state.chat_id)
            or value["office_id"] != state.office_id
            or value["generation"] != state.generation
        ):
            raise ValueError("handoff identity mismatch")
        return state.handoff
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise ConversationError("handoff-mismatch") from error


def transition(event: ConversationEvent, state: ConversationState) -> Transition:
    if not isinstance(event, ConversationEvent) or not isinstance(state, ConversationState):
        raise ConversationError("invalid-transition")
    _validate_event(event, state)
    _load_authority(state)
    if event.platform_goal != state.mission_goal:
        return Transition(
            "stop",
            state,
            reason=f"goal-state-conflict:{state.mission_goal}!={event.platform_goal}",
        )
    if event.kind in _ESCALATIONS:
        return Transition("deny", state, reason="mission-has-no-authority")
    if event.kind == "pin":
        if state.mode != "pinned":
            raise ConversationError("pin-requires-pinned-receipt")
        return Transition("pin", state)
    if event.kind == "resume":
        return Transition("resume", state, handoff=_read_handoff(state))
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
    value = {
        "schema_version": 1,
        "task_digest": _digest(state.task_id),
        "chat_digest": _digest(state.chat_id),
        "office_id": state.office_id,
        "generation": state.generation,
        "summary": event.summary,
        "next_action": event.next_action,
    }
    path = state.project / ".ao/mission/handoffs" / f"{state.office_id}-{state.generation}.json"
    atomic_write_json(path, value)
    digest = _bytes_digest(path.read_bytes())
    compressed = replace(state, handoff=path, handoff_digest=digest)
    return Transition("compress", compressed, handoff=path)
