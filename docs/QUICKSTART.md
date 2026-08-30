# AO Office Pool v0.1.3 Windows quickstart

Use Windows x86-64 with PowerShell 7, exactly Python 3.12, Git,
`VCRUNTIME140.dll` present in the Windows system directory, and a fixed local
NTFS volume.

```powershell
git clone https://github.com/uesugitorachiyo/ao-office-pool.git
Set-Location .\ao-office-pool
pwsh -File .\scripts\Install-And-Verify.ps1
```

The script acquires and verifies
`ao-office-pool-v0.1.3-windows-x86_64.zip` and
`ao-office-pool-v0.1.3-windows-x86_64.zip.sha256`, installs and verifies the
package, and performs the O1 lifecycle smoke. Exact success ends with a
self-contained `Launcher:` line and `READY FOR USE` while all five offices are
free. A nonzero exit with `HOLD [reason-code]` means stop at that first blocker.

Do not reproduce the internal acquisition, checksum, extraction, or lifecycle
steps manually. For AI execution use
[AI_OPERATOR_RUNBOOK.md](AI_OPERATOR_RUNBOOK.md). For normal office commands,
recovery, update, rollback, or uninstall use
[OPERATOR_GUIDE.md](OPERATOR_GUIDE.md).
