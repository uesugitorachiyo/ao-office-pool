import json
import tempfile
import unittest
from pathlib import Path

from scripts.verify_requirements import Requirement, verify_requirements


V11_REQUIREMENTS = [
    ("V11-01", "Atomic O1-O5 claims and a clear sixth-claim failure."),
    ("V11-02", "Exact receipt, owner, generation, office, task, and project authorization."),
    ("V11-03", "Private same-task resume without receipt enumeration."),
    ("V11-04", "Exact-field, secret-free, nonmutating public status."),
    ("V11-05", "No automatic expiry for pinned work."),
    ("V11-06", "Connected-project output enforcement against path and identity attacks."),
    ("V11-07", "Byte preservation and recovery-required before reuse."),
    ("V11-08", "Exact-key emergency release with evidence retention."),
    ("V11-09", "All-free activation, five equal runtimes, and full rollback."),
    ("V11-10", "Independent trust-anchor substitution detection."),
    ("V11-11", "Truthful source, verification, test, activation, and routing metadata."),
    ("V11-12", "No scheduler, automatic queue, stale release, updater, or service."),
]

B_REQUIREMENTS = [
    (f"B{number:02d}", f"V1.2 blocker B{number:02d} closure.") for number in range(1, 20)
]


class VerifyRequirementsTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary_directory.name) / "requirements.json"

    def tearDown(self):
        self.temporary_directory.cleanup()

    def rows(self):
        return [
            {
                "id": requirement_id,
                "description": description,
                "test_id": f"tests.test_{requirement_id.lower()}",
                "release_phase": "month-1",
            }
            for requirement_id, description in V11_REQUIREMENTS + B_REQUIREMENTS
        ]

    def write_requirements(self, rows=None):
        self.path.write_text(json.dumps({"schema_version": 1, "requirements": rows or self.rows()}))
        return self.path

    def test_returns_every_inherited_requirement(self):
        requirements = verify_requirements(self.write_requirements())

        self.assertEqual(set(requirements), {requirement_id for requirement_id, _ in V11_REQUIREMENTS + B_REQUIREMENTS})
        self.assertTrue(all(isinstance(requirement, Requirement) for requirement in requirements.values()))

    def test_rejects_duplicate_requirement_ids(self):
        rows = self.rows()
        rows[-1]["id"] = rows[-2]["id"]

        with self.assertRaises(ValueError):
            verify_requirements(self.write_requirements(rows))

    def test_rejects_duplicate_test_ids(self):
        rows = self.rows()
        rows[-1]["test_id"] = rows[-2]["test_id"]

        with self.assertRaises(ValueError):
            verify_requirements(self.write_requirements(rows))

    def test_rejects_missing_or_empty_test_ids(self):
        for mutation in (lambda row: row.pop("test_id"), lambda row: row.update(test_id="")):
            with self.subTest(mutation=mutation):
                rows = self.rows()
                mutation(rows[0])
                with self.assertRaises(ValueError):
                    verify_requirements(self.write_requirements(rows))

    def test_rejects_missing_or_unknown_requirement_ids(self):
        for mutation in (lambda rows: rows.pop(), lambda rows: rows.__setitem__(-1, {**rows[-1], "id": "B20"})):
            with self.subTest(mutation=mutation):
                rows = self.rows()
                mutation(rows)
                with self.assertRaises(ValueError):
                    verify_requirements(self.write_requirements(rows))

    def test_rejects_unknown_requirement_fields(self):
        rows = self.rows()
        rows[0]["unreviewed"] = True

        with self.assertRaises(ValueError):
            verify_requirements(self.write_requirements(rows))

    def test_rejects_empty_release_phases(self):
        rows = self.rows()
        rows[0]["release_phase"] = ""

        with self.assertRaises(ValueError):
            verify_requirements(self.write_requirements(rows))


if __name__ == "__main__":
    unittest.main()
