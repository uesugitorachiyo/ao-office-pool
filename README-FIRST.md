# Start here inside the AO Office Pool v0.1.2 archive

This is the Windows x86-64 payload named
`ao-office-pool-v0.1.2-windows-x86_64.zip`. Its external checksum sidecar is
`ao-office-pool-v0.1.2-windows-x86_64.zip.sha256`.

The archive cannot authenticate itself. The supported public installation path
starts in the repository checkout and runs `scripts/Install-And-Verify.ps1`,
which retains and verifies the release contract, archive, and sidecar before
using any extracted member. If you opened this archive directly, do not install it manually. Return to the source-checkout [README](README.md#install) and run
the public orchestrator unchanged.

Exact success reports `READY FOR USE` and a self-contained launcher command.
Any missing prerequisite, integrity disagreement, unsafe path, install or
verification failure, or incomplete O1 lifecycle reports `HOLD` and must stop.

## What the verified installer does

On Windows x86-64 with PowerShell 7, exactly Python 3.12, Git,
`VCRUNTIME140.dll` present in the Windows system directory, and fixed local
NTFS, the orchestrator:

1. acquires and independently validates the two public release assets;
2. safely extracts and installs into a new private local root;
3. verifies the installed immutable bytes;
4. requires O1 through O5 to be free;
5. creates a disposable connected Git project;
6. claims, resumes, and releases O1; and
7. requires all five offices to finish free.

Installation creates fresh governance and recovery material. Never reuse it
between installations. Use `recover` only after `recovery-required`; see
[the operator guide](docs/OPERATOR_GUIDE.md).

## Packaged operator skills

Read the applicable skill completely before using it:

- [Thought experiment](skills/thought-experiment/SKILL.md)
- [Engineering research](skills/engineering-research/SKILL.md)
- [Scope-to-deliverable workflow](skills/scope-to-deliverable-workflow/SKILL.md)

Manual update, rollback, and uninstall are advanced operations. Follow the
verified-byte and all-free requirements in the operator guide; deletion of a
preserved recovery sibling is a separate retention decision.

For an advanced offline workflow whose archive and sidecar were independently
authenticated before extraction, these are the packaged entry points:

```powershell
./packaging/Install-AOOfficePool.ps1 -Action Install -Archive $Archive -ChecksumFile $Sidecar -InstallRoot $InstallRoot
./packaging/Verify-AOOfficePool.ps1 -InstallRoot $InstallRoot -Archive $Archive -ChecksumFile $Sidecar
./packaging/Uninstall-AOOfficePool.ps1 -InstallRoot $InstallRoot -Archive $Archive -ChecksumFile $Sidecar
```

These commands do not acquire or authenticate release assets. They are not the
ordinary public install path; use them only under the advanced operator guide.
