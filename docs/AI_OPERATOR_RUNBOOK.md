# AO Office Pool v0.1.1 Windows AI operator runbook

This runbook has one operational authority:
`scripts/Install-And-Verify.ps1`. Run it unchanged. Do not reproduce its public
acquisition, contract validation, extraction, installation, verification, or
O1 smoke lifecycle. Stop at the first failed gate; later success cannot repair
an earlier failure.

The public assets are `ao-office-pool-v0.1.1-windows-x86_64.zip` and
`ao-office-pool-v0.1.1-windows-x86_64.zip.sha256`.

## G00 — Read and bound the task

**Authority:** The checked-out `README.md`, this runbook, and the unchanged
public installer script.

**Command:** Read README.md and docs/AI_OPERATOR_RUNBOOK.md completely.

**Expected:** Installation for the current Windows user only. No publication,
visibility, repository-history, uninstall, or unrelated-system mutation.

**Stop:** Return `HOLD` if the request requires a different OS, architecture,
release, or external effect.

**Evidence:** Record only the release label and bounded intended action.

**Next:** Continue to G01.

## G01 — Check end-user prerequisites

**Authority:** The prerequisite list in `README.md` and checks enforced by the
orchestrator.

**Command:** Confirm Windows x86-64, PowerShell 7 or newer, exactly Python 3.12,
Git, a fixed local NTFS volume, and the presence of `VCRUNTIME140.dll` in the
Windows system directory. The installer does not verify a redistributable
product or version.

**Expected:** Every prerequisite is available through the ordinary executable
names `pwsh`, `python.exe`, and `git.exe`.

**Stop:** Return `HOLD` for the first missing or different prerequisite. Do not
install Visual Studio for end-user use; it is source-qualification-only.

**Evidence:** Record sanitized versions and pass/fail labels, not absolute
developer paths.

**Next:** Continue to G02.

## G02 — Run the public orchestrator

**Authority:** `scripts/Install-And-Verify.ps1` and its tracked public-release
contract.

**Command:** From the repository root, run scripts/Install-And-Verify.ps1 unchanged with PowerShell 7:

```powershell
pwsh -File .\scripts\Install-And-Verify.ps1
```

**Expected:** The script safely acquires and validates the archive and sidecar,
installs into a new private fixed-local-NTFS root, verifies the installed bytes,
creates a disposable connected project, requires all five offices free, and
completes one O1 claim/resume/release smoke lifecycle.

**Stop:** A nonzero exit or `HOLD [reason-code]` is terminal. Do not retry by
editing manifests, replacing assets, manually extracting, or invoking child
scripts. A retry is valid only after correcting the exact reported reason code
with the next safe corrective action for that reason code and only if the
script did not report `READY FOR USE`. This includes non-prerequisite HOLD
codes such as `installation-failed`.

**Evidence:** Record the exit code, exact bounded HOLD reason if any, and the
final bounded success lines. Never record receipts, recovery keys, secrets,
absolute developer paths, or raw child output.

**Next:** On exact success continue to G03; otherwise report HOLD.

## G03 — Confirm terminal state

**Authority:** The orchestrator's final status verification and returned
self-contained launcher command.

**Command:** Confirm the final output ends with `READY FOR USE`, includes
`Commands: status, claim, resume, run, release, recover`, and provides a
`Launcher:` command usable in a new PowerShell shell.

**Expected:** O1 through O5 are all free after the O1 lifecycle smoke. The
temporary connected project and installer staging roots are gone.

**Stop:** Missing success output, any occupied office, cleanup uncertainty, or
an ambiguous launcher is `HOLD`.

**Evidence:** To the requesting user, return the exact self-contained `Launcher:` line unchanged. Also return the release label, exit zero, and the statement that all
five offices finished free. Do not publish or share that private local-path command, but do not sanitize, redact, or rewrite it into an unusable command.

**Next:** Report `READY FOR USE`. For office work, follow the installed command
examples in `README.md` and the advanced operator guide.

Visual Studio Build Tools 2022 is required only for contributor source
qualification. It is not an end-user installation prerequisite. The public
installer needs no `GITHUB_TOKEN`, private release, or authenticated GitHub API.
