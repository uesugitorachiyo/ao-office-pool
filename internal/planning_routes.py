import hashlib
import json
from dataclasses import dataclass

from internal.mission_bridge import MissionReadback


class PlanningRouteError(RuntimeError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


_ROUTES = {
    "ao-blueprint": ("ao-blueprint", True, False, False),
    "ao-atlas": ("ao-atlas", True, True, False),
    "ao-atlas-mutation": ("ao-atlas", True, True, False),
    "ao-atlas-long": ("ao-atlas", True, True, False),
    "ao-forge": ("ao-forge", True, False, True),
    "blocked": ("blocked", False, False, False),
}


@dataclass(frozen=True)
class RouteDecision:
    mission_id: str
    objective_digest: str
    mission_status: str
    source_route: str
    route: str
    blueprint_required: bool
    atlas_required: bool
    execution_candidate: bool

    def as_record(self) -> dict:
        value = {
            "schema_version": 1,
            "mission_id": self.mission_id,
            "objective_digest": self.objective_digest,
            "mission_status": self.mission_status,
            "source_route": self.source_route,
            "route": self.route,
            "blueprint_required": self.blueprint_required,
            "atlas_required": self.atlas_required,
            "execution_candidate": self.execution_candidate,
        }
        raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        return {**value, "decision_digest": hashlib.sha256(raw).hexdigest()}


def select_route(mission: MissionReadback) -> RouteDecision:
    if not isinstance(mission, MissionReadback):
        raise PlanningRouteError("invalid-mission")
    if any(
        getattr(mission, field)
        for field in (
            "executes_work",
            "approves_policy",
            "calls_providers",
            "publishes",
            "deploys",
            "mutates_repositories",
        )
    ):
        raise PlanningRouteError("mission-authority-escalation")
    try:
        route, blueprint, atlas, executable = _ROUTES[mission.current_route]
    except KeyError as error:
        raise PlanningRouteError("unsupported-route") from error
    if mission.status == "blocked":
        route, blueprint, atlas, executable = _ROUTES["blocked"]
    return RouteDecision(
        mission.mission_id,
        mission.objective_digest,
        mission.status,
        mission.current_route,
        route,
        blueprint,
        atlas,
        executable,
    )
