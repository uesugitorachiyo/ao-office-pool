import io
import hashlib
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from scripts.scan_public_tree import main, scan_tree


def text(*parts): return "".join(parts)


class ScanPublicTreeTests(unittest.TestCase):
    def setUp(self): self.temporary_directory = tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()); self.root = Path(self.temporary_directory.name)
    def tearDown(self): self.temporary_directory.cleanup()
    def write(self, relative, contents="public\n"):
        path = self.root / relative; path.parent.mkdir(parents=True, exist_ok=True); path.write_text(contents); return path
    def paths(self): return {finding.path for finding in scan_tree(self.root)}

    def test_reports_existing_public_boundary_leaks(self):
        cases = ((text(".", "env.production"), ""), (text("claim.", "receipt.json"), ""), ("owner.txt", text("owner", "Id: x")), ("prompt.txt", text("system ", "prompt", ": x")), ("path.txt", text("/", "Users/a")))
        for name, contents in cases: self.write(name, contents)
        self.assertTrue({name for name, _ in cases} <= self.paths())

    def test_reports_receipts_recovery_and_windows_paths(self):
        cases = ((text("claim.", "receipt.json"), ""), (text("recovery", "-key"), ""), ("windows.txt", text("C", ":/", "Users/a")))
        for name, contents in cases: self.write(name, contents)
        self.assertTrue({name for name, _ in cases} <= self.paths())

    def test_reports_governance_envelopes_detached_tags_and_markers(self):
        prefix = ".ao/governance/office-pool/witness-0123456789abcdef0123456789abcdef"
        names = {
            prefix + ".json",
            prefix + ".hmac",
            prefix + ".consumed",
            prefix + ".revoked",
        }
        for name in names:
            self.write(name)
        self.assertEqual(names - self.paths(), set())

    def test_reports_links_without_following_targets(self):
        target = Path(tempfile.mkdtemp(dir=Path(tempfile.gettempdir()).resolve())) / "private.txt"; target.write_text("x")
        link = self.root / "link"
        try: link.symlink_to(target)
        except OSError as error: self.skipTest(str(error))
        self.assertIn("link", self.paths())

    def test_findings_have_public_relative_metadata(self):
        self.write(text(".", "env"))
        finding = scan_tree(self.root)[0]
        self.assertEqual(finding.path, text(".", "env")); self.assertTrue(finding.rule); self.assertTrue(finding.detail)

    def test_rejects_missing_and_linked_roots(self):
        with self.assertRaises(ValueError): scan_tree(self.root / "missing")
        link = self.root / "root-link"
        try: link.symlink_to(self.root, target_is_directory=True)
        except OSError as error: self.skipTest(str(error))
        with self.assertRaises(ValueError): scan_tree(link)

    def test_propagates_walk_and_read_errors(self):
        from unittest.mock import patch
        with patch("scripts.scan_public_tree.os.walk", side_effect=OSError("walk")):
            with self.assertRaises(OSError): scan_tree(self.root)
        self.write("read.txt")
        with patch("scripts.scan_public_tree.Path.read_text", side_effect=OSError("read")):
            with self.assertRaises(OSError): scan_tree(self.root)

    def test_propagates_descendant_walk_errors_delivered_to_onerror(self):
        from unittest.mock import patch
        error = OSError("descendant")

        def walk(root, *, followlinks, onerror):
            yield root, ["child"], []
            onerror(error)

        with patch("scripts.scan_public_tree.os.walk", side_effect=walk):
            with self.assertRaises(OSError) as raised:
                scan_tree(self.root)
        self.assertIs(raised.exception, error)

    def test_reports_extended_private_markers(self):
        cases = ((text(".", "env.local"), ""), ("secret.txt", text("secret", "=x")), ("marker.txt", text("objective", ": x\nprivate", "_state: x")), ("unix.txt", text("/", "home/a")))
        self.write(text(".", "env.example"))
        for name, contents in cases: self.write(name, contents)
        self.assertTrue({name for name, _ in cases} <= self.paths())
        self.assertNotIn(text(".", "env.example"), self.paths())

    def test_reports_every_required_content_and_artifact_shape(self):
        cases = [(text(".", "env"), ""), (text(".", "env.stage"), ""), ("claim.receipt.json", ""), ("recovery-key", ""), ("owner", text("owner", ": x")), ("prompt", text("prompt", ": x")), ("mac", text("/", "Users/a\n/", "home/a\n/", "Volumes/a")), ("win", text("C", ":\\", "Users\\a\nD", ":/", "Users/a")), ("words", text("secret", "=x\ntoken", "=x\npassword", "=x\nobjective", "=x\ntranscript", "=x\nmodel", "=x\nresume", "=x\nprivate", "_state=x\nAPI", "_KEY=x\nAWS", "_SECRET_", "ACCESS_KEY=x\nrecovery", "_key=x\nreceipt", "=x")), ("__pycache__/x.pyc", ""), (".pytest_cache/x", ""), ("x.pyo", "")]
        self.write(text(".", "env.example"))
        for name, contents in cases: self.write(name, contents)
        self.assertTrue({name for name, _ in cases} <= self.paths())
        self.assertNotIn(text(".", "env.example"), self.paths())
        plurals = {
            "plural-receipts": text("receipt", "s=x"),
            "plural-tokens": text("token", "s=x"),
            "plural-secrets": text("secret", "s=x"),
            "plural-passwords": text("password", "s=x"),
        }
        for name, contents in plurals.items(): self.write(name, contents)
        self.assertEqual(set(plurals) - self.paths(), set())
        list_fields = {
            "list-receipt": text("- ", "receipt", ": public"),
            "list-tokens": text("* ", "token", "s=public"),
            "list-owner-id": text("+ ", "owner", "_id: public"),
        }
        for name, contents in list_fields.items(): self.write(name, contents)
        self.assertEqual(set(list_fields) - self.paths(), set())

    def test_controlled_current_public_python_copies_are_clean(self):
        import shutil
        public = Path(__file__).parents[1]
        for directory in ("scripts", "tests"):
            target = self.root / directory; target.mkdir()
            for source in (public / directory).glob("*.py"):
                if not source.name.startswith("._"): shutil.copy2(source, target / source.name)
        self.assertEqual(scan_tree(self.root), [])

    def test_reports_valid_python_private_strings_in_every_expression_form(self):
        source = text(
            "def call(value): return value\n",
            "def returned(): return '", "owner", "Id: x'\n",
            "call('", "token", ": x')\n",
            "mapping = {'x': 'system ", "prompt", ": x'}\n",
            "values = ['private", "_state: x']\n",
            "typed: str = '/", "Users/a'\n",
            "class Box: pass\nbox = Box()\nbox.value = 'recovery", "_key=x'\n",
            "items = {}\nitems['x'] = 'receipt", "=x'\n",
            "def defaults(value='AWS", "_SECRET_", "ACCESS_KEY=x'): return value\n",
            "formatted = f'{\"objective", ": x\"}'\n",
        )
        self.write("settings.py", source)
        self.assertIn("settings.py", self.paths())
        bindings = {
            "binding-owner.py": text("owner", " = 'public'\n"),
            "binding-api-key.py": text("api_", "key: str = 'public'\n"),
            "binding-token.py": text("box.", "token", " = 'public'\n"),
            "binding-receipt.py": text("items['", "receipt", "'] = 'public'\n"),
            "binding-recovery.py": text("mapping = {'", "recovery", "_key': 'public'}\n"),
            "binding-prompt.py": text("publish(", "prompt", "='public')\n"),
            "binding-objective.py": text("objective", " = 'public'\n"),
            "binding-transcript.py": text("transcript", ": str = 'public'\n"),
            "binding-model.py": text("box.", "model", " = 'public'\n"),
            "binding-resume.py": text("items['", "resume", "'] = 'public'\n"),
            "binding-private-state.py": text("mapping = {'", "private", "_state': 'public'}\n"),
            "binding-secret.py": text("publish(", "secret", "='public')\n"),
            "binding-password.py": text("password", " = 'public'\n"),
        }
        for name, contents in bindings.items():
            compile(contents, name, "exec")
            self.write(name, contents)
        self.assertEqual(set(bindings) - self.paths(), set())

    def test_reports_an_authentic_appledouble_file(self):
        (self.root / "._README").write_bytes(b"\x00\x05\x16\x07")
        self.assertIn("._README", self.paths())

    def test_prunes_git_metadata_before_scanning_public_files(self):
        self.write(".git/config", text("owner", "Id: private"))
        self.write("README.md")
        self.assertEqual(scan_tree(self.root), [])

    def test_ignores_a_regular_root_git_worktree_pointer(self):
        self.write(
            ".git",
            "gitdir: C:" + "\\Users\\private\\repository\\.git\\worktrees\\checkout\n",
        )
        self.write("README.md")
        self.assertEqual(scan_tree(self.root), [])

    def test_scans_a_non_pointer_root_git_file(self):
        self.write(".git", text("owner", "Id: private"))
        findings = {finding.path: finding.rule for finding in scan_tree(self.root)}
        self.assertEqual(findings, {".git": "content"})

    def test_reports_a_linked_root_git_entry(self):
        target = Path(self.temporary_directory.name) / "private-git"
        target.mkdir()
        try:
            (self.root / ".git").symlink_to(target, target_is_directory=True)
        except OSError as error:
            self.skipTest(str(error))
        findings = {finding.path: finding.rule for finding in scan_tree(self.root)}
        self.assertEqual(findings[".git"], "symlink")

    def test_accepts_only_hash_bound_pinned_forge_runtime_schema(self):
        relative = "packaging/runtime/ao-forge/docs/contracts/goal-run-v0.1.schema.json"
        packaged = Path(__file__).parents[1] / relative
        target = self.root / relative
        target.parent.mkdir(parents=True)
        target.write_bytes(packaged.read_bytes())
        self.assertNotIn(relative, self.paths())
        target.write_bytes(b"public replacement\n")
        findings = {finding.path: finding.rule for finding in scan_tree(self.root)}
        self.assertEqual(findings[relative], "identity")

    def test_accepts_only_manifest_bound_preview_binaries(self):
        binaries = {
            "components/ao2/v0.5.12/ao2.exe": b"binary owner: private\x00",
            "offices/O1/runtime/versions/v0.5.12/ao2.exe": b"runtime token=x\x00",
        }
        rows = []
        for relative, data in binaries.items():
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            rows.append(
                {
                    "path": relative,
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "size": len(data),
                }
            )
        self.write(
            "developer-preview-manifest.json",
            json.dumps(
                {
                    "schema_version": 1,
                    "label": "developer-preview",
                    "architecture": "windows-x86_64",
                    "runtime_version": "v0.5.12",
                    "files": rows,
                }
            ),
        )
        trusted = {relative: hashlib.sha256(data).hexdigest() for relative, data in binaries.items()}
        with patch("scripts.scan_public_tree.TRUSTED_PREVIEW_BINARIES", trusted):
            self.assertEqual(scan_tree(self.root), [])
        (self.root / next(iter(binaries))).write_bytes(b"changed\n")
        with patch("scripts.scan_public_tree.TRUSTED_PREVIEW_BINARIES", trusted):
            findings = {finding.path: finding.rule for finding in scan_tree(self.root)}
        self.assertEqual(findings[next(iter(binaries))], "identity")

    def test_forged_preview_manifest_cannot_authorize_an_arbitrary_binary(self):
        data = b"token=super-private\n"
        (self.root / "payload.exe").write_bytes(data)
        self.write(
            "developer-preview-manifest.json",
            json.dumps(
                {
                    "schema_version": 1,
                    "label": "developer-preview",
                    "architecture": "windows-x86_64",
                    "runtime_version": "v0.5.12",
                    "files": [{"path": "payload.exe", "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}],
                }
            ),
        )
        findings = {finding.path: finding.rule for finding in scan_tree(self.root)}
        self.assertEqual(findings["payload.exe"], "content")

    def test_main_reports_sorted_json_findings_and_summary(self):
        self.write("z/__pycache__/later.pyc")
        self.write("a/__pycache__/first.pyc")
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch("sys.argv", ["scan_public_tree.py", str(self.root)]), redirect_stdout(stdout), redirect_stderr(stderr):
            self.assertEqual(main(), 1)
        rows = [json.loads(line) for line in stdout.getvalue().splitlines()]
        self.assertEqual([row["path"] for row in rows], ["a/__pycache__/first.pyc", "z/__pycache__/later.pyc"])
        self.assertEqual(rows[0], {"detail": "private", "path": "a/__pycache__/first.pyc", "rule": "artifact"})
        self.assertEqual(stderr.getvalue(), "public-tree findings=2\n")

    def test_main_reports_a_clean_summary(self):
        self.write("README.md")
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch("sys.argv", ["scan_public_tree.py", str(self.root)]), redirect_stdout(stdout), redirect_stderr(stderr):
            self.assertEqual(main(), 0)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue(), "public-tree findings=0\n")

    def test_main_bounds_scan_errors_without_disclosing_absolute_paths(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch("sys.argv", ["scan_public_tree.py", str(self.root)]), patch("scripts.scan_public_tree.scan_tree", side_effect=OSError(str(self.root / "private.txt"))), redirect_stdout(stdout), redirect_stderr(stderr):
            self.assertEqual(main(), 2)
        self.assertEqual(json.loads(stdout.getvalue()), {"error": "scan-failed", "kind": "OSError"})
        self.assertNotIn(str(self.root), stdout.getvalue() + stderr.getvalue())
        self.assertEqual(stderr.getvalue(), "public-tree scan-error=1\n")


if __name__ == "__main__": unittest.main()
