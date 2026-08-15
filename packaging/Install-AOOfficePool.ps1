[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Install', 'Update', 'Rollback')]
    [string]$Action,
    [Parameter(Mandatory = $true)]
    [string]$Archive,
    [Parameter(Mandatory = $true)]
    [string]$ChecksumFile,
    [Parameter(Mandatory = $true)]
    [string]$InstallRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ExpectedOffices = @('O1', 'O2', 'O3', 'O4', 'O5')
$ManifestName = 'developer-preview-manifest.json'
$ActivationName = '.activation-transaction.json'

function Assert-ExactProperties {
    param([object]$Value, [string[]]$Names, [string]$Kind)
    $actual = @($Value.PSObject.Properties.Name | Sort-Object)
    $expected = @($Names | Sort-Object)
    if (($actual -join "`n") -cne ($expected -join "`n")) {
        throw "invalid $Kind fields"
    }
}

function Assert-SafeRelativePath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path) -or [System.IO.Path]::IsPathRooted($Path) -or $Path.Contains(':')) {
        throw 'path must be relative'
    }
    $reserved = @('CON', 'PRN', 'AUX', 'NUL', 'CONIN$', 'CONOUT$', 'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9', 'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9')
    foreach ($segment in ($Path.Replace('/', '\') -split '\\')) {
        if ([string]::IsNullOrEmpty($segment) -or $segment -in @('.', '..') -or $segment.EndsWith(' ') -or $segment.EndsWith('.') -or $segment -match '[<>"/\\|?*\x00-\x1f]') {
            throw 'path contains an unsafe segment'
        }
        if (($segment.Split('.')[0]).ToUpperInvariant() -in $reserved) {
            throw 'reserved device name is not accepted'
        }
        if ($segment -match '^[^ .~]{1,6}~[0-9]+(?:\..*)?$') {
            throw 'short-name aliases are not accepted'
        }
    }
}

function Test-HardLink {
    param([object]$Item)
    return $Item.PSObject.Properties.Match('LinkType').Count -eq 1 -and [string]$Item.LinkType -ceq 'HardLink'
}

function Assert-SafeRoot {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path) -or $Path -notmatch '^[A-Za-z]:\\') {
        throw 'install root must be a drive-absolute local path'
    }
    [void](Assert-SafeRelativePath $Path.Substring(3))
    $full = [System.IO.Path]::GetFullPath($Path)
    $drive = [System.IO.Path]::GetPathRoot($full)
    if ($full.TrimEnd('\') -ceq $drive.TrimEnd('\')) {
        throw 'install root cannot be a volume root'
    }
    $cursor = $full
    while (-not (Test-Path -LiteralPath $cursor)) {
        $parent = [System.IO.Path]::GetDirectoryName($cursor)
        if ([string]::IsNullOrEmpty($parent) -or $parent -ceq $cursor) {
            throw 'install root has no existing parent'
        }
        $cursor = $parent
    }
    while (-not [string]::IsNullOrEmpty($cursor)) {
        $item = Get-Item -LiteralPath $cursor -Force
        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'install root contains a reparse point'
        }
        if ($cursor.TrimEnd('\') -ceq $drive.TrimEnd('\')) { break }
        $cursor = [System.IO.Path]::GetDirectoryName($cursor)
    }
    return $full.TrimEnd('\')
}

function Assert-NtfsPath {
    param([string]$Path)
    $full = [System.IO.Path]::GetFullPath($Path)
    $drive = [System.IO.Path]::GetPathRoot($full)
    $information = [System.IO.DriveInfo]::new($drive)
    if (-not $information.IsReady -or $information.DriveType -ne [System.IO.DriveType]::Fixed -or $information.DriveFormat -cne 'NTFS') {
        throw 'developer preview requires a local NTFS volume'
    }
}

function Assert-ArchiveChecksum {
    param([string]$ArchivePath, [string]$SidecarPath)
    $archiveItem = Get-Item -LiteralPath $ArchivePath -Force
    $sidecarItem = Get-Item -LiteralPath $SidecarPath -Force
    if ($archiveItem.PSIsContainer -or $sidecarItem.PSIsContainer -or
        ($archiveItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
        ($sidecarItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
        (Test-HardLink $archiveItem) -or (Test-HardLink $sidecarItem)) {
        throw 'archive and checksum must be regular files'
    }
    $line = (Get-Content -LiteralPath $sidecarItem.FullName -Raw).Trim()
    if ($line -notmatch '^([0-9A-Fa-f]{64})[ \t]+\*?([^\\/:]+)$') {
        throw 'invalid checksum sidecar'
    }
    if ($Matches[2] -cne $archiveItem.Name) {
        throw 'checksum sidecar names another archive'
    }
    $stream = [System.IO.FileStream]::new($archiveItem.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    try {
        $actual = [System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash($stream)).Replace('-', '')
        if ($actual -cne $Matches[1].ToUpperInvariant()) {
            throw 'archive checksum mismatch'
        }
        $stream.Position = 0
        return $stream
    }
    catch {
        $stream.Dispose()
        throw
    }
}

function Assert-ArchiveManifest {
    param([System.IO.Stream]$ArchiveStream)
    [void](Add-Type -AssemblyName System.IO.Compression)
    $ArchiveStream.Position = 0
    $zip = [System.IO.Compression.ZipArchive]::new($ArchiveStream, [System.IO.Compression.ZipArchiveMode]::Read, $true)
    try {
        $entry = $zip.GetEntry($ManifestName)
        if ($null -eq $entry) { throw 'archive has no preview manifest' }
        $reader = [System.IO.StreamReader]::new($entry.Open())
        try { $raw = $reader.ReadToEnd() } finally { $reader.Dispose() }
    }
    finally { $zip.Dispose() }
    $manifest = $raw | ConvertFrom-Json
    Assert-ExactProperties $manifest @('schema_version', 'label', 'architecture', 'runtime_version', 'files') 'preview manifest'
    if ($manifest.schema_version -ne 1 -or $manifest.label -cne 'developer-preview' -or $manifest.architecture -cne 'windows-x86_64') {
        throw 'archive is not the Windows developer preview'
    }
    if ([string]::IsNullOrWhiteSpace([string]$manifest.runtime_version)) {
        throw 'preview manifest has no runtime version'
    }
    [pscustomobject]@{
        manifest = $manifest
        manifest_sha256 = [System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($raw))).Replace('-', '').ToLowerInvariant()
    }
}

function Read-PreviewManifest {
    param([string]$Root)
    return (Get-Content -LiteralPath (Join-Path $Root $ManifestName) -Raw | ConvertFrom-Json)
}

function Expand-VerifiedArchive {
    param([System.IO.Stream]$ArchiveStream, [string]$Destination)
    [void](Add-Type -AssemblyName System.IO.Compression)
    [void](Add-Type -AssemblyName System.IO.Compression.FileSystem)
    [void][System.IO.Directory]::CreateDirectory($Destination)
    $root = [System.IO.Path]::GetFullPath($Destination).TrimEnd('\') + '\'
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $ArchiveStream.Position = 0
    $zip = [System.IO.Compression.ZipArchive]::new($ArchiveStream, [System.IO.Compression.ZipArchiveMode]::Read, $true)
    try {
        foreach ($entry in $zip.Entries) {
            $name = $entry.FullName
            if ([string]::IsNullOrWhiteSpace($name) -or $name.Contains('\') -or $name.Contains(':') -or $name.StartsWith('/') -or $name -match '(^|/)\.\.(/|$)') {
                throw 'archive contains an unsafe path'
            }
            [void](Assert-SafeRelativePath $name.TrimEnd('/'))
            if (-not $seen.Add($name)) {
                throw 'archive contains a duplicate path'
            }
            $target = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($Destination, $name.Replace('/', '\')))
            if (-not $target.StartsWith($root, [System.StringComparison]::OrdinalIgnoreCase)) {
                throw 'archive path escapes staging root'
            }
            if ($name.EndsWith('/')) {
                [void][System.IO.Directory]::CreateDirectory($target)
            }
            else {
                [void][System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($target))
                $entry.ExtractToFile($target, $false)
            }
        }
    }
    finally {
        $zip.Dispose()
    }
}

function Test-MutableStatePath {
    param([string]$Path)
    return $Path -in @('pool.json', '.pool.lock') -or
        $Path -match '^offices/O[1-5]/office-state\.json$' -or
        $Path -match '^(runtime|operator-secrets|updates)/'
}

function Assert-AllFree {
    param([string]$Root, [string]$ExpectedRuntimeVersion = '')
    $pool = Get-Content -LiteralPath (Join-Path $Root 'pool.json') -Raw | ConvertFrom-Json
    Assert-ExactProperties $pool @('schema_version', 'office_count', 'offices', 'runtime_version') 'pool'
    if ($pool.schema_version -ne 1 -or $pool.office_count -ne 5 -or (@($pool.offices) -join ',') -cne ($ExpectedOffices -join ',') -or (-not [string]::IsNullOrEmpty($ExpectedRuntimeVersion) -and [string]$pool.runtime_version -cne $ExpectedRuntimeVersion)) {
        throw 'pool must contain exactly O1 through O5 and runtime version differs'
    }
    if (Test-Path -LiteralPath (Join-Path $Root 'updates\runtime-transaction.json')) {
        throw 'runtime recovery is pending'
    }
    foreach ($office in $ExpectedOffices) {
        $statePath = Join-Path $Root "offices\$office\office-state.json"
        $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
        Assert-ExactProperties $state @('schema_version', 'office_id', 'generation', 'status') "office $office"
        if ($state.schema_version -ne 1 -or $state.office_id -cne $office -or $state.status -cne 'free' -or $state.generation -lt 0) {
            throw "office $office is not free"
        }
    }
}

function Assert-InstalledTree {
    param([string]$Root, [object]$ExpectedManifest = $null, [string]$ExpectedManifestSha256 = '')
    $rootFull = [System.IO.Path]::GetFullPath($Root).TrimEnd('\')
    $rootPrefix = $rootFull + '\'
    $raw = Get-Content -LiteralPath (Join-Path $rootFull $ManifestName) -Raw
    $manifestSha256 = [System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($raw))).Replace('-', '').ToLowerInvariant()
    if (-not [string]::IsNullOrEmpty($ExpectedManifestSha256) -and $manifestSha256 -cne $ExpectedManifestSha256) { throw 'installed preview manifest does not match the checked archive' }
    $manifest = if ($null -eq $ExpectedManifest) { $raw | ConvertFrom-Json } else { $ExpectedManifest }
    Assert-ExactProperties $manifest @('schema_version', 'label', 'architecture', 'runtime_version', 'files') 'preview manifest'
    if ($manifest.schema_version -ne 1 -or $manifest.label -cne 'developer-preview' -or $manifest.architecture -cne 'windows-x86_64' -or [string]::IsNullOrWhiteSpace([string]$manifest.runtime_version)) { throw 'invalid developer preview manifest' }
    $expected = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    [void]$expected.Add($ManifestName)
    foreach ($file in @($manifest.files)) {
        Assert-ExactProperties $file @('path', 'sha256', 'size') 'manifest file'
        $relative = [string]$file.path
        if ([string]::IsNullOrWhiteSpace($relative) -or (Test-MutableStatePath $relative) -or $relative.Contains('\') -or $relative.Contains(':') -or $relative.StartsWith('/') -or $relative -match '(^|/)\.\.(/|$)' -or -not $expected.Add($relative)) { throw 'manifest contains an unsafe or duplicate path' }
        [void](Assert-SafeRelativePath $relative)
        if ([string]$file.sha256 -notmatch '^[0-9a-f]{64}$' -or $file.size -lt 0) { throw 'manifest contains invalid file metadata' }
        $target = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($rootFull, $relative.Replace('/', '\')))
        if (-not $target.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) { throw 'manifest path escapes install root' }
        $item = Get-Item -LiteralPath $target -Force
        if ($item.PSIsContainer -or ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or (Test-HardLink $item) -or $item.Length -ne [long]$file.size) { throw "unsafe installed member: $relative" }
        if ((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant() -cne [string]$file.sha256) { throw "installed checksum mismatch: $relative" }
    }
    $actual = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($item in Get-ChildItem -LiteralPath $rootFull -Recurse -Force) {
        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or (-not $item.PSIsContainer -and (Test-HardLink $item))) { throw 'installed tree contains a reparse point or hard link' }
        $relative = $item.FullName.Substring($rootPrefix.Length).Replace('\', '/')
        if (-not $item.PSIsContainer -and -not (Test-MutableStatePath $relative)) { [void]$actual.Add($relative) }
    }
    if ($actual.Count -ne $expected.Count -or @($actual | Where-Object { -not $expected.Contains($_) }).Count -ne 0) { throw 'installed tree contains unknown or missing bytes' }
    return $manifest
}

function Restore-PreviousInstall {
    param([string]$Root, [string]$Backup, [string]$Failed, [string]$Staging)
    if ((Test-Path -LiteralPath $Backup) -and (Test-Path -LiteralPath $Root)) {
        $rootLock = Join-Path $Root '.pool.lock'
        if (Test-Path -LiteralPath $rootLock) { Move-Item -LiteralPath $rootLock -Destination (Join-Path $Backup '.pool.lock') }
        Move-Item -LiteralPath $Root -Destination $Failed
    }
    $stagedLock = Join-Path $Staging '.pool.lock'
    if ((Test-Path -LiteralPath $Backup) -and -not (Test-Path -LiteralPath (Join-Path $Backup '.pool.lock')) -and (Test-Path -LiteralPath $stagedLock)) {
        Move-Item -LiteralPath $stagedLock -Destination (Join-Path $Backup '.pool.lock')
    }
    if (Test-Path -LiteralPath $Backup) {
        Move-Item -LiteralPath $Backup -Destination $Root
    }
    if (Test-Path -LiteralPath $Root) { [System.IO.File]::Delete("$Root$ActivationName") }
}

function Enter-PoolLock {
    param([string]$Root)
    $stream = [System.IO.FileStream]::new((Join-Path $Root '.pool.lock'), [System.IO.FileMode]::OpenOrCreate, [System.IO.FileAccess]::ReadWrite, ([System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete))
    try { $stream.Lock(0, 1); return $stream } catch { $stream.Dispose(); throw }
}

function Write-ActivationTransaction {
    param([string]$Root, [string]$Backup, [string]$Staging, [ValidateSet('prepared', 'backup', 'staging-locked', 'active')][string]$Phase)
    [System.IO.File]::WriteAllText("$Root$ActivationName", (@{ schema_version = 1; backup = $Backup; staging = $Staging; phase = $Phase } | ConvertTo-Json -Compress), [System.Text.Encoding]::UTF8)
}

function Recover-PendingActivation {
    param([string]$Root)
    $path = "$Root$ActivationName"
    if (-not (Test-Path -LiteralPath $path)) { return }
    $transaction = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    Assert-ExactProperties $transaction @('schema_version', 'backup', 'staging', 'phase') 'activation transaction'
    if ($transaction.schema_version -ne 1) { throw 'invalid activation transaction' }
    switch ([string]$transaction.phase) {
        'prepared' {
            if (-not (Test-Path -LiteralPath $Root) -or (Test-Path -LiteralPath $transaction.backup)) { throw 'invalid prepared activation state' }
        }
        'backup' {
            if ((Test-Path -LiteralPath $Root) -or -not (Test-Path -LiteralPath $transaction.backup)) { throw 'invalid backup activation state' }
            Move-Item -LiteralPath $transaction.backup -Destination $Root
        }
        'staging-locked' {
            $stagedLock = Join-Path $transaction.staging '.pool.lock'
            if ((Test-Path -LiteralPath $Root) -or -not (Test-Path -LiteralPath $transaction.backup) -or -not (Test-Path -LiteralPath $stagedLock)) { throw 'invalid staged-lock activation state' }
            Move-Item -LiteralPath $stagedLock -Destination (Join-Path $transaction.backup '.pool.lock')
            Move-Item -LiteralPath $transaction.backup -Destination $Root
        }
        'active' {
            $failed = "$Root.failed.recovery.$([guid]::NewGuid().ToString('N'))"
            if (-not (Test-Path -LiteralPath $Root) -or -not (Test-Path -LiteralPath $transaction.backup)) { throw 'invalid active activation state' }
            Move-Item -LiteralPath $Root -Destination $failed
            Move-Item -LiteralPath (Join-Path $failed '.pool.lock') -Destination (Join-Path $transaction.backup '.pool.lock')
            Move-Item -LiteralPath $transaction.backup -Destination $Root
        }
        default { throw 'invalid activation phase' }
    }
    [System.IO.File]::Delete($path)
}

function Invoke-AtomicInstall {
    param([string]$Operation, [string]$ArchivePath, [string]$SidecarPath, [string]$Root)
    $safeRoot = Assert-SafeRoot $Root
    Assert-NtfsPath $safeRoot
    $archiveStream = Assert-ArchiveChecksum $ArchivePath $SidecarPath
    try {
        $archiveManifest = Assert-ArchiveManifest $archiveStream
        $exists = Test-Path -LiteralPath $safeRoot
        if ($exists) {
            $recoveryLock = Enter-PoolLock $safeRoot
            try { Recover-PendingActivation $safeRoot } finally { $recoveryLock.Dispose() }
        }
        else { Recover-PendingActivation $safeRoot }
        $exists = Test-Path -LiteralPath $safeRoot
        if ($Operation -ceq 'Install' -and $exists) { throw 'install root already exists' }
        if ($Operation -cne 'Install' -and -not $exists) { throw 'update or rollback requires an existing install' }
        $suffix = [guid]::NewGuid().ToString('N')
        $staging = "$safeRoot.staging.$suffix"
        $backup = "$safeRoot.previous.$suffix"
        $failed = "$safeRoot.failed.$suffix"
        Expand-VerifiedArchive $archiveStream $staging
        Assert-NtfsPath $staging
        Assert-InstalledTree $staging $archiveManifest.manifest $archiveManifest.manifest_sha256
        Assert-AllFree $staging $archiveManifest.manifest.runtime_version
        if ($exists) {
            $lock = Enter-PoolLock $safeRoot
            try {
                Assert-InstalledTree $safeRoot
                Assert-AllFree $safeRoot
                Write-ActivationTransaction $safeRoot $backup $staging 'prepared'
                Move-Item -LiteralPath $safeRoot -Destination $backup
                Write-ActivationTransaction $safeRoot $backup $staging 'backup'
                Move-Item -LiteralPath (Join-Path $backup '.pool.lock') -Destination (Join-Path $staging '.pool.lock')
                Write-ActivationTransaction $safeRoot $backup $staging 'staging-locked'
                Move-Item -LiteralPath $staging -Destination $safeRoot
                Write-ActivationTransaction $safeRoot $backup $staging 'active'
                Assert-InstalledTree $safeRoot $archiveManifest.manifest $archiveManifest.manifest_sha256
                Assert-AllFree $safeRoot $archiveManifest.manifest.runtime_version
                [System.IO.File]::Delete("$safeRoot$ActivationName")
            }
            catch { Restore-PreviousInstall $safeRoot $backup $failed $staging; throw }
            finally { $lock.Dispose() }
        }
        else {
            Move-Item -LiteralPath $staging -Destination $safeRoot
            Assert-InstalledTree $safeRoot $archiveManifest.manifest $archiveManifest.manifest_sha256
            Assert-AllFree $safeRoot $archiveManifest.manifest.runtime_version
        }
        [pscustomobject]@{
            action = $Operation
            label = 'developer-preview'
            install_root = $safeRoot
            previous_install = $(if ($exists) { $backup } else { $null })
        }
    }
    finally {
        $archiveStream.Dispose()
    }
}

Invoke-AtomicInstall $Action $Archive $ChecksumFile $InstallRoot
