import hashlib
import json
import unittest
from pathlib import Path

from internal.mission_bridge import MissionReadback
from internal.planning_routes import PlanningRouteError, select_route


def mission(route: str, *, status: str = "active") -> MissionReadback:
    return MissionReadback(
        mission_id="mission-0123456789abcdef",
        objective_digest="sha256:" + hashlib.sha256(b"task").hexdigest(),
        status=status,
        current_route=route,
        record=Path("mission.json"),
        resumed=False,
    )


class PlanningRouteTests(unittest.TestCase):
    def test_bounded_work_routes_to_forge_without_atlas(self):
        decision = select_route(mission("ao-forge"))
        self.assertEqual(decision.route, "ao-forge")
        self.assertTrue(decision.blueprint_required)
        self.assertFalse(decision.atlas_required)
        self.assertTrue(decision.execution_candidate)

    def test_underspecified_work_stays_at_blueprint(self):
        decision = select_route(mission("ao-blueprint"))
        self.assertEqual(decision.route, "ao-blueprint")
        self.assertFalse(decision.execution_candidate)

    def test_oversized_mutation_and_long_work_require_atlas(self):
        for route in ("ao-atlas", "ao-atlas-mutation", "ao-atlas-long"):
            with self.subTest(route=route):
                decision = select_route(mission(route))
                self.assertEqual(decision.route, "ao-atlas")
                self.assertTrue(decision.atlas_required)
                self.assertFalse(decision.execution_candidate)

    def test_blocked_mission_cannot_become_execution_candidate(self):
        decision = select_route(mission("blocked", status="blocked"))
        self.assertEqual(decision.route, "blocked")
        self.assertFalse(decision.execution_candidate)

    def test_source_only_capability_fails_closed(self):
        with self.assertRaises(PlanningRouteError) as raised:
            select_route(mission("source-only"))
        self.assertEqual(raised.exception.code, "unsupported-route")

    def test_mission_authority_escalation_fails_closed(self):
        elevated = mission("ao-forge")
        object.__setattr__(elevated, "executes_work", True)
        with self.assertRaises(PlanningRouteError) as raised:
            select_route(elevated)
        self.assertEqual(raised.exception.code, "mission-authority-escalation")

    def test_route_decision_has_a_closed_digest_bound_record(self):
        value = select_route(mission("ao-forge")).as_record()
        self.assertEqual(
            set(value),
            {
                "schema_version",
                "mission_id",
                "objective_digest",
                "mission_status",
                "source_route",
                "route",
                "blueprint_required",
                "atlas_required",
                "execution_candidate",
                "decision_digest",
            },
        )
        digest = value.pop("decision_digest")
        expected = hashlib.sha256(
            json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        self.assertEqual(digest, expected)


if __name__ == "__main__":
    unittest.main()
