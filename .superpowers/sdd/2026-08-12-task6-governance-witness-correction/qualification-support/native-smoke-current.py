from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
from pathlib import Path
from unittest import mock

PACKAGE_ROOT = Path(os.environ["TASK6_PACKAGE_ROOT"]).resolve()
sys.path.insert(0, str(PACKAGE_ROOT))

import internal.governance_witness as governance
from internal.execution import execute
from internal.governance_witness import issue_witness
from tests.test_governance_witness import ASSETS, GovernanceWitnessTests


RELEASED_FORGE_SCHEMA_SHA256 = (
    "68a0fb154124fb4c219cc68eeffcc432e2c5c445765e9dbe24b19718fb98d74c"
)
EXPECTED = {
    "posix": {
        "ao-blueprint": "f86f221351069bbece0bd2afacdf964c812081018d71a94286bb0103927cafec",
        "ao-atlas": "e6968aeeb11bc19eb77fe3f87ca71414697dc92736556e726abe89c74f874bea",
        "ao-forge": "823ee61771608c7893287532c00929710ee1ff1149e06c13d40ff7296e937ba1",
        "ao-covenant": "9a5ca7c6920c44b6e120d6c5bd8baf190b66e188d43485639c6fc5355190868e",
        "ao2": "6cba9a1ded758506bb0a4b6d6377687e29b9d35950c799c2a0b4efb51c6f1bd7",
    },
    "nt": {
        "ao-blueprint": "00fe1168a168651a8c92e442aec9bd7b7406bd793594d0df3d9213f9327f2ee4",
        "ao-atlas": "1b7f3101104177c08cf9002b9d87825be8173643bc614f2713a8360206ebd252",
        "ao-forge": "c1dc19549299fe71a4f84f904c49523892aded070c8ce50becea18942350e363",
        "ao-covenant": "fd6e3a0033608d3f47dccb60f48191e4c4b2dc4fdce893c87d8ea96199610c5d",
        "ao2": "be96ff2baf90db208ad90612210d5df12ff981e9fb28857dfa41729ad735dd39",
    },
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    root = PACKAGE_ROOT
    native = Path(os.environ.get("TASK6_NATIVE_ROOT", root / "native")).resolve()
    expected = EXPECTED[os.name]
    suffix = ".exe" if os.name == "nt" else ""
    forge_runtime = Path(
        os.environ.get("TASK6_FORGE_RUNTIME_ROOT", root / "packaging/runtime/ao-forge")
    ).resolve()
    forge_schema_sha256 = sha256(
        forge_runtime / "docs/contracts/goal-run-v0.1.schema.json"
    )
    if (
        forge_schema_sha256 != RELEASED_FORGE_SCHEMA_SHA256
        or governance.FORGE_SCHEMA_SHA256 != RELEASED_FORGE_SCHEMA_SHA256
    ):
        raise RuntimeError("Forge schema digest mismatch")
    harness = GovernanceWitnessTests("test_consumption_is_atomic_and_one_use")
    harness.setUp()
    harness.configuration.stop()
    try:
        for name in ("ao-blueprint", "ao-atlas", "ao-forge", "ao-covenant"):
            source = native / (ASSETS[name] + suffix)
            if sha256(source) != expected[name]:
                raise RuntimeError(f"{name} digest mismatch")
            shutil.copy2(source, harness.bin_dir / ASSETS[name])
        if sha256(native / ("ao2" + suffix)) != expected["ao2"]:
            raise RuntimeError("ao2 digest mismatch")

        for component in harness.components:
            if component["name"] in expected:
                component["sha256"] = expected[component["name"]]
        harness._write_lock()
        harness._write_mission("ao-foundry")

        package = harness.project / "discount_service"
        package.mkdir()
        package.joinpath("__init__.py").write_text("", encoding="utf-8")
        package.joinpath("discounts.py").write_text(
            "def calculate_discount(price, rate):\n    return price * (1 - rate)\n",
            encoding="utf-8",
        )
        tests = harness.project / "tests"
        tests.mkdir()
        tests.joinpath("test_discounts.py").write_text(
            "from discount_service.discounts import calculate_discount\n\n"
            "def test_discount():\n    assert calculate_discount(100, .25) == 75\n",
            encoding="utf-8",
        )
        harness.project.joinpath("pytest.py").write_text(
            "import importlib.util\nimport pathlib\nimport sys\nimport traceback\n\n"
            "class Raises:\n"
            "    def __init__(self, expected): self.expected = expected\n"
            "    def __enter__(self): return self\n"
            "    def __exit__(self, exc_type, exc, tb):\n"
            "        if exc_type is None: raise AssertionError(f'expected {self.expected.__name__} to be raised')\n"
            "        return issubclass(exc_type, self.expected)\n\n"
            "def raises(expected): return Raises(expected)\n\n"
            "def main():\n"
            "    failures = []\n"
            "    for test_file in sorted((pathlib.Path.cwd() / 'tests').glob('test_*.py')):\n"
            "        spec = importlib.util.spec_from_file_location(test_file.stem, test_file)\n"
            "        module = importlib.util.module_from_spec(spec)\n"
            "        sys.modules['pytest'] = sys.modules[__name__]\n"
            "        spec.loader.exec_module(module)\n"
            "        for name in sorted(dir(module)):\n"
            "            if name.startswith('test_'):\n"
            "                try:\n"
            "                    getattr(module, name)()\n"
            "                    print(f'PASS {test_file.name}::{name}')\n"
            "                except Exception:\n"
            "                    failures.append(f'{test_file.name}::{name}')\n"
            "                    traceback.print_exc()\n"
            "    if failures:\n"
            "        print(f'FAILED {len(failures)} tests: {failures}')\n"
            "        return 1\n"
            "    print('all tests passed')\n"
            "    return 0\n\n"
            "if __name__ == '__main__': raise SystemExit(main())\n",
            encoding="utf-8",
        )
        harness.project.joinpath("pyproject.toml").write_text(
            "[project]\nname='discount-service-fixture'\nversion='0.0.0'\nrequires-python='>=3.9'\n",
            encoding="utf-8",
        )
        harness.workflow.write_text(
            "id: risky-pr-run\nversion: 0.1.0\ntarget_fixture: fixtures/discount-service\n"
            "obj"
            + "ective: Add input validation to calculate_discount and update tests.\n"
            "roles:\n  - planner\n  - implementer\n  - reviewer\n"
            "  - test-engineer\n  - evaluator-closer\n"
            "verifier:\n  command: python -m pytest\n"
            "policy:\n  deny_by_default: true\n  approval_mode: exact_action_digest\n",
            encoding="utf-8",
        )
        for child in harness.blueprint.iterdir():
            if child.is_dir():
                shutil.rmtree(child)
            else:
                child.unlink()
        blueprint_pack = os.environ.get("TASK6_BLUEPRINT_PACK")
        if blueprint_pack:
            shutil.copytree(blueprint_pack, harness.blueprint, dirs_exist_ok=True)
        else:
            shutil.unpack_archive(
                os.environ["TASK6_BLUEPRINT_PACK_ARCHIVE"], harness.blueprint
            )

        runtime = (
            harness.pool_root
            / "offices"
            / harness.authority["office_id"]
            / "runtime"
            / "versions"
            / "test-runtime"
        )
        runtime.mkdir(parents=True, exist_ok=True)
        shutil.copy2(native / ("ao2" + suffix), runtime / ("ao2" + suffix))

        with mock.patch.multiple(
            governance,
            COMPONENT_LOCK=harness.lock,
            BIN_DIR=harness.bin_dir,
            FORGE_RUNTIME_ROOT=forge_runtime,
        ):
            envelope = issue_witness(
                harness.claim_path,
                harness.task_text,
                harness.valid_artifacts(atlas=True),
            )
            result = execute(harness.claim_path, envelope, timeout_seconds=30)

        record = json.loads(result.record.read_text(encoding="utf-8"))
        output = {
            "status": result.status,
            "run_id": result.diagnostics["run_id"],
            "record_phase": record["phase"],
            "request_digest": result.request_digest,
            "record_sha256": sha256(result.record),
            "ao2_sha256": expected["ao2"],
            "producer_sha256": {
                name: expected[name]
                for name in ("ao-blueprint", "ao-atlas", "ao-forge", "ao-covenant")
            },
        }
        if output["status"] != "accepted" or output["record_phase"] != "completed":
            raise RuntimeError(output)
        print(json.dumps(output, sort_keys=True))
    except Exception:
        for label, directory in (
            ("project", harness.project / "producer-logs"),
            ("forge", harness.forge_runtime / "producer-logs"),
        ):
            for path in directory.glob("*"):
                print(
                    f"{label}:{path.name}:{path.read_text(encoding='utf-8', errors='replace')}",
                    file=sys.stderr,
                )
        raise
    finally:
        harness.tearDown()


if __name__ == "__main__":
    main()
