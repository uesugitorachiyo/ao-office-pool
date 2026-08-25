import io
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

try:
    from tests import windows_compiler
except ImportError:
    windows_compiler = None


class WindowsCompilerTests(unittest.TestCase):
    def require_module(self):
        self.assertIsNotNone(windows_compiler, "shared Windows compiler helper is missing")
        return windows_compiler

    def test_discovers_an_active_cl_without_visual_studio_lookup(self):
        module = self.require_module()
        with mock.patch.object(module.shutil, "which", side_effect=lambda name: "cl.exe" if name == "cl.exe" else None):
            compiler = module.discover()
        self.assertEqual(compiler, module.Compiler("cl.exe", None))

    def test_explicit_vcvars_override_is_validated_and_selected(self):
        module = self.require_module()
        with tempfile.TemporaryDirectory() as temporary:
            vcvars = Path(temporary) / "vcvars64.bat"
            vcvars.write_text("@echo off\n", encoding="utf-8")
            with mock.patch.dict(os.environ, {module.OVERRIDE_ENV: str(vcvars)}, clear=True), mock.patch.object(module.shutil, "which", return_value=None):
                self.assertEqual(module.discover(), module.Compiler("cl.exe", vcvars))

    def test_discovers_vcvars_from_vswhere_installation(self):
        module = self.require_module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            vswhere = root / "vswhere.exe"
            vswhere.write_bytes(b"")
            vcvars = root / "VC" / "Auxiliary" / "Build" / "vcvars64.bat"
            vcvars.parent.mkdir(parents=True)
            vcvars.write_text("@echo off\n", encoding="utf-8")
            completed = mock.Mock(stdout=str(root) + "\n")
            with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(
                module.shutil,
                "which",
                side_effect=lambda name: str(vswhere) if name == "vswhere.exe" else None,
            ), mock.patch.object(module.subprocess, "run", return_value=completed) as run:
                self.assertEqual(module.discover(), module.Compiler("cl.exe", vcvars))
            self.assertIn("Microsoft.VisualStudio.Component.VC.Tools.x86.x64", run.call_args.args[0])

    def test_missing_compiler_is_a_bounded_stop_signal(self):
        module = self.require_module()
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(
            module.shutil, "which", return_value=None
        ), mock.patch.object(module, "_default_vswhere_paths", return_value=()), redirect_stdout(stdout), redirect_stderr(stderr):
            self.assertEqual(module.main(), 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("windows-c-compiler=missing", stderr.getvalue())
        self.assertIn("Build Tools", stderr.getvalue())
        self.assertNotIn(str(Path(tempfile.gettempdir()).resolve()), stderr.getvalue())

    def test_missing_compiler_skips_native_fixtures_by_name(self):
        module = self.require_module()
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            module, "discover", side_effect=module.CompilerUnavailable(module.MISSING)
        ):
            source = Path(temporary) / "source.c"
            source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
            with self.assertRaisesRegex(unittest.SkipTest, "windows-c-compiler=missing"):
                module.compile_c(source, Path(temporary) / "program.exe")

    def test_invalid_explicit_override_fails_closed(self):
        module = self.require_module()
        with mock.patch.dict(os.environ, {module.OVERRIDE_ENV: "missing-vcvars64.bat"}, clear=True), mock.patch.object(
            module.shutil, "which", return_value=None
        ), mock.patch.object(module, "_default_vswhere_paths", side_effect=AssertionError("must not fall through")):
            with self.assertRaises(module.CompilerUnavailable):
                module.discover()

    def test_compile_uses_discovered_vcvars_environment(self):
        module = self.require_module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, output, vcvars = root / "source.c", root / "program.exe", root / "vcvars64.bat"
            source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
            vcvars.write_text("@echo off\n", encoding="utf-8")
            observed = {}

            def inspect(command, **_kwargs):
                observed["command"] = command
                if command[:3] == ["cmd.exe", "/d", "/c"]:
                    observed["script"] = Path(command[-1]).read_text(encoding="utf-8")

            with mock.patch.object(module, "discover", return_value=module.Compiler("cl.exe", vcvars)), mock.patch.object(module.subprocess, "run", side_effect=inspect):
                module.compile_c(source, output)
            self.assertEqual(observed["command"][:3], ["cmd.exe", "/d", "/c"])
            self.assertIn(str(vcvars), observed["script"])
            self.assertIn(str(output), observed["script"])
            self.assertIn(str(source.with_suffix(".obj")), observed["script"])
            self.assertNotIn(str(output.with_suffix(".obj")), observed["script"])
            self.assertFalse(Path(observed["command"][-1]).exists())

    def test_fixtures_do_not_pin_a_visual_studio_installation_path(self):
        root = Path(__file__).parents[1]
        text = "\n".join(
            (root / name).read_text(encoding="utf-8")
            for name in ("tests/test_execution.py", "tests/test_governance_witness.py")
        )
        self.assertNotIn("Microsoft Visual Studio\\2022\\BuildTools", text)


if __name__ == "__main__":
    unittest.main()
