# AO Office Pool developer-preview operator guide

This guide covers the private Windows x86-64 `developer-preview` checkpoint for
Months 1–6. It is not GA and does not authorize publication, deployment,
provider calls, or upstream changes.

## Before each operation

Use a local, drive-absolute path on an NTFS volume. Do not use a volume root,
UNC path, link, junction, reparse point, or 8.3 alias. Keep the archive and its
checksum sidecar in private operator storage.

The archive checksum sidecar contains one line:

```text
<64 lowercase or uppercase SHA-256 hex> *<archive filename>
```

The archive root contains `developer-preview-manifest.json` with fields exactly
`schema_version`, `label`, `architecture`, `runtime_version`, and `files`.
`label` is `developer-preview`; `architecture` is `windows-x86_64`; each file
row contains exactly `path`, `sha256`, and `size`. Paths use forward slashes.
The manifest lists immutable package files except itself. It must not list the
governed mutable pool state (`pool.json`, office states, runtime,
operator-secrets, updates, or `.pool.lock`); that state is separately checked
for the exact O1--O5 all-free shape. The scripts reject missing immutable
files, extra immutable files, digest or size drift, traversal, duplicate names,
and reparse points.

Install, verify, update, rollback, and uninstall stop unless the pool contains
exactly O1, O2, O3, O4, and O5 and all five offices are free. A pending runtime
transaction also stops the operation. Finish or recover active work first.

## Install and verify

Run PowerShell from the directory containing the scripts:

```powershell
.\Install-AOOfficePool.ps1 -Action Install `
  -Archive D:\PrivatePreview\ao-office-pool-developer-preview.zip `
  -ChecksumFile D:\PrivatePreview\ao-office-pool-developer-preview.zip.sha256 `
  -InstallRoot C:\AOOfficePool

.\Verify-AOOfficePool.ps1 -InstallRoot C:\AOOfficePool `
  -Archive D:\PrivatePreview\ao-office-pool-developer-preview.zip `
  -ChecksumFile D:\PrivatePreview\ao-office-pool-developer-preview.zip.sha256
```

The installer retains one checked archive handle through member validation and
extraction, verifies the staged manifest and immutable file hashes, then takes
the pool byte-range lock, checks all five offices free again, and records a
private sibling recovery transaction before replacement. A later invocation
restores the accepted prior tree if an interrupted replacement is found.
It does not start a service, create a queue, or schedule work.

## Update and rollback

An update uses a new private archive. A rollback uses the previously accepted
archive and checksum. Both follow the same checksum, manifest, NTFS, path,
exact-tree, and all-free checks:

```powershell
.\Install-AOOfficePool.ps1 -Action Update `
  -Archive D:\PrivatePreview\next.zip `
  -ChecksumFile D:\PrivatePreview\next.zip.sha256 `
  -InstallRoot C:\AOOfficePool

.\Install-AOOfficePool.ps1 -Action Rollback `
  -Archive D:\PrivatePreview\previous.zip `
  -ChecksumFile D:\PrivatePreview\previous.zip.sha256 `
  -InstallRoot C:\AOOfficePool
```

After a successful replacement, the command reports the preserved prior tree
as `previous_install`. Keep it until verification and the required pilot smoke
run finish. If replacement fails after the first rename, the installer restores
the prior tree and preserves the rejected tree under a `.failed.<id>` sibling.
Do not merge or delete either tree before recording the private incident.

There is no network updater or background updater. The operator supplies and
verifies every archive.

## Recovery

Stop when a script reports an occupied office, `recovery-required`, a pending
runtime transaction, an unknown file, a checksum mismatch, or path ambiguity.
Do not edit the manifest to make a changed tree pass. Use the receipt-bound
recovery flow for pool state and the accepted prior archive for runtime
rollback. Unknown bytes stay in place for investigation.

The scripts never turn `source-present` into a runtime claim. Source presence
does not establish executable, accepted, activated, or routed capability.
Those states require their own existing qualification records.

## Uninstall

Verify first, then remove the active path:

```powershell
.\Verify-AOOfficePool.ps1 -InstallRoot C:\AOOfficePool `
  -Archive D:\PrivatePreview\ao-office-pool-developer-preview.zip `
  -ChecksumFile D:\PrivatePreview\ao-office-pool-developer-preview.zip.sha256
.\Uninstall-AOOfficePool.ps1 -InstallRoot C:\AOOfficePool `
  -Archive D:\PrivatePreview\ao-office-pool-developer-preview.zip `
  -ChecksumFile D:\PrivatePreview\ao-office-pool-developer-preview.zip.sha256
```

Uninstall verifies unchanged manifest-bound bytes and the all-free state, then
atomically renames the installation to a private `.uninstalled.<id>` sibling.
This removes the active installation while preserving every byte for recovery
or independent reproduction. Delete that preserved tree only under a separate
operator retention decision after the pilot record is complete.

## Claims and limits

Verification requires the accepted archive and checksum sidecar as an
independent immutable anchor; a self-consistent replacement manifest inside
the installation is not sufficient. Portable tests can validate script structure and fail-closed ordering. They do
not prove NTFS identity behavior or native Windows execution. Only a pilot run
against unchanged archive bytes on the required Windows hosts can record those
results. The preview has no scheduler, hardware controller, automatic queue,
stale auto-release, permanent background service, or unsolicited network
updater.
