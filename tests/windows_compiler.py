from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path


OVERRIDE_ENV = "AO_TEST_VCVARS64"
MISSING = (
    "windows-c-compiler=missing; install Visual Studio Build Tools with the "
    "Desktop development with C++ workload, or set AO_TEST_VCVARS64"
)


class CompilerUnavailable(RuntimeError):
    pass


@dataclass(frozen=True)
class Compiler:
    executable: str
    vcvars: Path | None


def _default_vswhere_paths() -> tuple[Path, ...]:
    return tuple(
        Path(root) / "Microsoft Visual Studio" / "Installer" / "vswhere.exe"
        for name in ("ProgramFiles(x86)", "ProgramFiles")
        if (root := os.environ.get(name))
    )


def discover() -> Compiler:
    active = shutil.which("cl.exe")
    if active:
        return Compiler(active, None)

    override = os.environ.get(OVERRIDE_ENV)
    if override:
        vcvars = Path(override)
        if vcvars.is_file():
            return Compiler("cl.exe", vcvars)
        raise CompilerUnavailable(MISSING)

    vswhere = shutil.which("vswhere.exe")
    candidates = (Path(vswhere),) if vswhere else _default_vswhere_paths()
    for candidate in candidates:
        if not candidate.is_file():
            continue
        try:
            result = subprocess.run(
                [
                    str(candidate),
                    "-latest",
                    "-products",
                    "*",
                    "-requires",
                    "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
                    "-property",
                    "installationPath",
                ],
                check=True,
                capture_output=True,
                text=True,
            )
        except (OSError, subprocess.CalledProcessError):
            continue
        installation = result.stdout.strip()
        if installation:
            vcvars = Path(installation) / "VC" / "Auxiliary" / "Build" / "vcvars64.bat"
            if vcvars.is_file():
                return Compiler("cl.exe", vcvars)
    raise CompilerUnavailable(MISSING)


def _compile(compiler: Compiler, source: Path, output: Path) -> None:
    object_path = source.with_suffix(".obj")
    if compiler.vcvars is None:
        subprocess.run(
            [
                compiler.executable,
                "/nologo",
                f'/Fo:{object_path}',
                str(source),
                f'/Fe:{output}',
            ],
            check=True,
            capture_output=True,
        )
        return

    script = output.with_suffix(".compile.cmd")
    script.write_text(
        f'@call "{compiler.vcvars}" >nul\n'
        f'@"{compiler.executable}" /nologo /Fo:"{object_path}" '
        f'"{source}" /Fe:"{output}"\n',
        encoding="utf-8",
    )
    try:
        subprocess.run(
            ["cmd.exe", "/d", "/c", str(script)],
            check=True,
            capture_output=True,
        )
    finally:
        script.unlink(missing_ok=True)


def compile_c(source: Path, output: Path) -> None:
    try:
        compiler = discover()
    except CompilerUnavailable as error:
        raise unittest.SkipTest(str(error)) from error
    _compile(compiler, source, output)


def main() -> int:
    try:
        compiler = discover()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "preflight.c"
            source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
            _compile(compiler, source, root / "preflight.exe")
    except (CompilerUnavailable, OSError, subprocess.CalledProcessError):
        print(MISSING, file=sys.stderr)
        return 2
    print("windows-c-compiler=ready")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
