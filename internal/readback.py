import hashlib
import json
import re
from pathlib import Path

from internal.pool import OFFICE_IDS, Pool, PoolError
from internal.qualification import Qualification, QualificationError
from internal.runtime_update import RuntimeUpdate, RuntimeUpdateError
from internal.transactions import read_json
from internal.windows_paths import validate_segment


_OFFICES = tuple(f"O{number}" for number in range(1, 6))
_OFFICE_STATES = {"free", "occupied", "recovery-required"}
_QUALIFICATION_STATES = {"candidate", "pilot-qualified", "release-qualified"}
_DIGEST = re.compile(r"^[0-9a-f]{64}$")


def _offices(status: dict) -> list[dict]:
    try:
        offices = status["offices"]
        if (
            not isinstance(status, dict)
            or status.get("schema_version") != 1
            or not isinstance(offices, list)
            or [office.get("office_id") for office in offices] != list(_OFFICES)
            or any(
                not isinstance(office, dict)
                or office.get("status") not in _OFFICE_STATES
                or type(office.get("generation")) is not int
                or office["generation"] < 0
                for office in offices
            )
        ):
            raise ValueError("invalid pool status")
        return [
            {
                "office_id": office["office_id"],
                "status": office["status"],
                "generation": office["generation"],
            }
            for office in offices
        ]
    except (AttributeError, KeyError, TypeError) as error:
        raise ValueError("invalid pool status") from error


def _qualification(value: dict) -> dict:
    try:
        selected = {
            "runtime_version": value["runtime_version"],
            "runtime_sha256": value["runtime_sha256"],
            "runtime_state": value["runtime_state"],
            "qualification_state": value["qualification_state"],
            "components_sha256": value["components_sha256"],
            "semantic_fingerprint": value["semantic_fingerprint"],
            "record_digest": value["record_digest"],
        }
        if (
            not isinstance(value, dict)
            or value.get("schema_version") != 1
            or validate_segment(selected["runtime_version"])
            != selected["runtime_version"]
            or len(selected["runtime_version"]) > 128
            or selected["runtime_state"] != "activated"
            or selected["qualification_state"] not in _QUALIFICATION_STATES
            or any(
                not isinstance(selected[name], str) or not _DIGEST.fullmatch(selected[name])
                for name in (
                    "runtime_sha256",
                    "components_sha256",
                    "semantic_fingerprint",
                    "record_digest",
                )
            )
        ):
            raise ValueError("invalid qualification record")
        return selected
    except (KeyError, TypeError) as error:
        raise ValueError("invalid qualification record") from error


def _active_snapshot(
    root: Path,
    status: dict | None = None,
    qualification: dict | None = None,
) -> tuple[dict, list[dict]]:
    return _with_active_snapshot(
        root,
        status,
        qualification,
        lambda selected, offices: (selected, offices),
    )


def _with_active_snapshot(root: Path, status, qualification, callback):
    if not isinstance(root, Path):
        raise TypeError("root must be pathlib.Path")
    try:
        metadata = read_json(root / "pool.json")
        pool = Pool(root, runtime_version=metadata["runtime_version"])
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise ValueError("inactive qualification record") from error
    try:
        with pool._locked():
            try:
                metadata = pool._ensure_initialized()
                live_qualification = Qualification(root)._existing()
                if live_qualification is None:
                    raise ValueError("missing qualification record")
                selected = _qualification(live_qualification)
                offices = []
                for office_id in OFFICE_IDS:
                    state = pool._read_state(office_id)
                    office_status = state["status"]
                    if office_status == "free" and pool._unknown_paths(office_id):
                        office_status = "recovery-required"
                    offices.append(
                        {
                            "office_id": office_id,
                            "status": office_status,
                            "generation": state["generation"],
                        }
                    )
                if (
                    qualification is not None
                    and qualification != live_qualification
                ):
                    raise ValueError("stale qualification record")
                if status is not None and _offices(status) != offices:
                    raise ValueError("stale pool status")
                if metadata["runtime_version"] != selected["runtime_version"]:
                    raise ValueError("inactive qualified runtime")
                manifest, _, components_raw = RuntimeUpdate(root)._staged(
                    selected["runtime_version"]
                )
                if (
                    manifest["sha256"] != selected["runtime_sha256"]
                    or hashlib.sha256(components_raw).hexdigest()
                    != selected["components_sha256"]
                ):
                    raise ValueError("qualified package mismatch")
                for office_id in OFFICE_IDS:
                    runtime = root / "offices" / office_id / "runtime"
                    if not RuntimeUpdate._runtime_matches(
                        runtime,
                        selected["runtime_version"],
                        selected["runtime_sha256"],
                    ):
                        raise ValueError("qualified runtime copy mismatch")
            except (
                OSError,
                KeyError,
                TypeError,
                ValueError,
                json.JSONDecodeError,
                PoolError,
                QualificationError,
                RuntimeUpdateError,
            ) as error:
                raise ValueError("inactive qualification record") from error
            return callback(selected, offices)
    except PoolError as error:
        raise ValueError("inactive qualification record") from error


def public_record(root: Path, status: dict, qualification: dict) -> dict:
    selected, offices = _active_snapshot(root, status, qualification)
    return {
        "schema_version": 1,
        "runtime_version": selected["runtime_version"],
        "qualification_state": selected["qualification_state"],
        "offices": offices,
    }


def protected_record(root: Path, status: dict, qualification: dict) -> dict:
    selected, offices = _active_snapshot(root, status, qualification)
    return {
        "schema_version": 1,
        "runtime": {
            "version": selected["runtime_version"],
            "sha256": selected["runtime_sha256"],
            "state": selected["runtime_state"],
        },
        "qualification": {
            "state": selected["qualification_state"],
            "semantic_fingerprint": selected["semantic_fingerprint"],
            "record_digest": selected["record_digest"],
        },
        "offices": offices,
    }
