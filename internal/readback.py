import re

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
                for name in ("runtime_sha256", "semantic_fingerprint", "record_digest")
            )
        ):
            raise ValueError("invalid qualification record")
        return selected
    except (KeyError, TypeError) as error:
        raise ValueError("invalid qualification record") from error


def public_record(status: dict, qualification: dict) -> dict:
    selected = _qualification(qualification)
    return {
        "schema_version": 1,
        "runtime_version": selected["runtime_version"],
        "qualification_state": selected["qualification_state"],
        "offices": _offices(status),
    }


def protected_record(status: dict, qualification: dict) -> dict:
    selected = _qualification(qualification)
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
        "offices": _offices(status),
    }
