# Windows Compiler Preflight Design

## Goal

Make the documented Windows source qualification truthful on clean clones that
do and do not have Microsoft C++ Build Tools, without weakening native test or
privacy gates.

## Design

Add one test-support module that locates an already active `cl.exe`, an explicit
`AO_TEST_VCVARS64` override, or a Visual Studio installation reported by
`vswhere.exe`. It compiles the existing C fixtures through that discovered
environment. If no compiler is available, fixture setup raises a named
`unittest.SkipTest`; this prevents repeated setup errors but does not qualify the
checkout.

The README runs the module as a preflight before the suite. A missing compiler
is an actionable nonzero stop signal, and the documentation states that a run
with compiler-dependent skips is not native qualification.

The public-tree scanner ignores Git metadata represented by either a root
`.git` directory or a regular root `.git` worktree pointer. It still reports a
linked `.git` entry and scans every other regular file.

## Boundaries

- Windows x86-64 only; macOS and Linux product qualification remain out of scope.
- Standard library and installed Visual Studio discovery only; no new package or
  CI dependency.
- No release publication, repository-visibility change, or private asset
  acquisition.
- A compiler-less checkout remains `HOLD`, even when the reduced suite has no
  errors.

## Verification

Regression tests cover active compiler discovery, override discovery,
`vswhere.exe` discovery, actionable missing-compiler behavior, fixture routing,
the README gate, regular worktree pointers, and linked `.git` rejection where
Windows privileges permit link creation. Final verification runs the focused
tests, the complete documented suite, schema parsing, bootstrap verification,
and a public-tree scan from a clean tracked export.
