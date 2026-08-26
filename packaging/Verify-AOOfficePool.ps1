[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$InstallRoot,
    [Parameter(Mandatory = $true)]
    [string]$Archive,
    [Parameter(Mandatory = $true)]
    [string]$ChecksumFile
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$Python = (Get-Command python.exe -ErrorAction Stop).Source
& $Python -c "import sys; raise SystemExit(0 if sys.version_info[:2] == (3, 12) else 1)"
if ($LASTEXITCODE -ne 0) { throw 'AO Office Pool requires Python 3.12' }
$ExpectedOffices = @('O1', 'O2', 'O3', 'O4', 'O5')
$ManifestName = 'developer-preview-manifest.json'
$MutableStateFiles = @(
    'pool.json'
    '.pool.lock'
    'offices/O1/office-state.json'
    'offices/O2/office-state.json'
    'offices/O3/office-state.json'
    'offices/O4/office-state.json'
    'offices/O5/office-state.json'
)
$MutableStateDirectories = @(
    'runtime'
    'operator-secrets'
    'updates'
    'offices/O1/history'
    'offices/O1/work'
    'offices/O2/history'
    'offices/O2/work'
    'offices/O3/history'
    'offices/O3/work'
    'offices/O4/history'
    'offices/O4/work'
    'offices/O5/history'
    'offices/O5/work'
)

function Test-MutableStatePath {
    param([string]$Path)
    if ($Path -cin $MutableStateFiles) { return $true }
    foreach ($directory in $MutableStateDirectories) {
        if ($Path -ceq $directory -or $Path.StartsWith("$directory/", [System.StringComparison]::Ordinal)) { return $true }
    }
    return $false
}

function Assert-ExactProperties {
    param([object]$Value, [string[]]$Names, [string]$Kind)
    $actual = @($Value.PSObject.Properties.Name | Sort-Object)
    $expected = @($Names | Sort-Object)
    if (($actual -join "`n") -cne ($expected -join "`n")) { throw "invalid $Kind fields" }
}

function Assert-ArchiveManifest {
    param([string]$ArchivePath, [string]$SidecarPath)
    $line = (Get-Content -LiteralPath $SidecarPath -Raw).Trim()
    if ($line -notmatch '^([0-9A-Fa-f]{64})[ \t]+\*?([^\\/:]+)$' -or $Matches[2] -cne (Split-Path $ArchivePath -Leaf)) { throw 'archive checksum mismatch' }
    $stream = [System.IO.FileStream]::new($ArchivePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    if ([System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash($stream)).Replace('-', '') -cne $Matches[1].ToUpperInvariant()) { $stream.Dispose(); throw 'archive checksum mismatch' }
    $stream.Position = 0
    $zip = [System.IO.Compression.ZipArchive]::new($stream, [System.IO.Compression.ZipArchiveMode]::Read, $true)
    try {
        $entry = $zip.GetEntry($ManifestName)
        if ($null -eq $entry) { throw 'archive has no preview manifest' }
        $reader = [System.IO.StreamReader]::new($entry.Open())
        try { $raw = $reader.ReadToEnd() } finally { $reader.Dispose() }
    } finally { $zip.Dispose(); $stream.Dispose() }
    $manifest = $raw | ConvertFrom-Json
    Assert-ExactProperties $manifest @('schema_version', 'label', 'architecture', 'runtime_version', 'files') 'preview manifest'
    if ($manifest.schema_version -ne 1 -or $manifest.label -cne 'developer-preview' -or $manifest.architecture -cne 'windows-x86_64' -or [string]::IsNullOrWhiteSpace([string]$manifest.runtime_version)) { throw 'invalid developer preview manifest' }
    [pscustomobject]@{ manifest = $manifest; manifest_sha256 = [System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($raw))).Replace('-', '').ToLowerInvariant() }
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

function Assert-ExactChildNames {
    param([string]$Path, [string[]]$Names, [string]$Kind)
    $actual = @(Get-ChildItem -LiteralPath $Path -Force | ForEach-Object { $_.Name } | Sort-Object)
    $expected = @($Names | Sort-Object)
    if (($actual -join "`n") -cne ($expected -join "`n")) { throw "invalid $Kind shape" }
}

function Assert-RegularStateFile {
    param([string]$Path, [string]$Kind)
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or (Test-HardLink $item)) {
        throw "invalid $Kind"
    }
}

function Assert-SafeStateTree {
    param([string]$Path)
    $root = Get-Item -LiteralPath $Path -Force
    if (-not $root.PSIsContainer -or ($root.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'mutable state root is not a regular directory'
    }
    $prefix = $root.FullName.TrimEnd('\') + '\'
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($item in Get-ChildItem -LiteralPath $root.FullName -Recurse -Force) {
        $relative = $item.FullName.Substring($prefix.Length).Replace('\', '/')
        [void](Assert-SafeRelativePath $relative)
        if (-not $seen.Add($relative) -or ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
            (-not $item.PSIsContainer -and (Test-HardLink $item))) {
            throw 'mutable state contains an ambiguous path, reparse point, or hard link'
        }
    }
}

function Assert-GovernanceMarkerDirectory {
    param([string]$Path)
    Assert-SafeStateTree $Path
    foreach ($item in Get-ChildItem -LiteralPath $Path -Force) {
        if ($item.Name -cnotmatch '^[0-9a-f]{64}-witness-[0-9a-f]{32}$') {
            throw 'invalid governance marker name'
        }
        Assert-RegularStateFile $item.FullName "governance marker: $($item.Name)"
    }
}

function Assert-MutableStateShape {
    param([string]$Root, [switch]$AllowMissingLock)
    foreach ($relative in $MutableStateFiles) {
        if ($AllowMissingLock -and $relative -ceq '.pool.lock') { continue }
        Assert-RegularStateFile (Join-Path $Root $relative) "mutable state file: $relative"
    }
    foreach ($relative in $MutableStateDirectories) {
        $path = Join-Path $Root $relative
        if ($relative -ceq 'updates' -and -not (Test-Path -LiteralPath $path)) { continue }
        Assert-SafeStateTree $path
    }
    Assert-ExactChildNames (Join-Path $Root 'runtime') @(
        'generations.json', 'governance', 'pointers', 'receipts', 'recovery',
        'recovery-authority.json', 'runtime-update-state.json', 'transactions'
    ) 'runtime state'
    foreach ($relative in @(
        'runtime\generations.json',
        'runtime\recovery-authority.json',
        'runtime\runtime-update-state.json'
    )) {
        Assert-RegularStateFile (Join-Path $Root $relative) "mutable state file: $relative"
    }
    foreach ($relative in @(
        'runtime\governance',
        'runtime\pointers',
        'runtime\receipts',
        'runtime\recovery',
        'runtime\transactions'
    )) {
        Assert-SafeStateTree (Join-Path $Root $relative)
    }
    Assert-ExactChildNames (Join-Path $Root 'runtime\governance') @('consumed', 'issued', 'revoked') 'runtime governance'
    foreach ($relative in @(
        'runtime\governance\consumed',
        'runtime\governance\issued',
        'runtime\governance\revoked'
    )) {
        Assert-GovernanceMarkerDirectory (Join-Path $Root $relative)
    }
    Assert-ExactChildNames (Join-Path $Root 'operator-secrets') @(
        'governance-witness.key', 'recovery-key-O1', 'recovery-key-O2',
        'recovery-key-O3', 'recovery-key-O4', 'recovery-key-O5'
    ) 'operator secrets'
    foreach ($relative in @(
        'operator-secrets\governance-witness.key',
        'operator-secrets\recovery-key-O1',
        'operator-secrets\recovery-key-O2',
        'operator-secrets\recovery-key-O3',
        'operator-secrets\recovery-key-O4',
        'operator-secrets\recovery-key-O5'
    )) {
        Assert-RegularStateFile (Join-Path $Root $relative) "mutable state file: $relative"
    }
    foreach ($relative in @('runtime\pointers', 'runtime\receipts', 'runtime\recovery', 'runtime\transactions')) {
        Assert-ExactChildNames (Join-Path $Root $relative) @() $relative
    }
    foreach ($office in $ExpectedOffices) {
        Assert-ExactChildNames (Join-Path $Root "offices\$office\work") @() "office $office work"
    }
    $updates = Join-Path $Root 'updates'
    if (Test-Path -LiteralPath $updates) {
        Assert-ExactChildNames $updates @('runtime-transactions') 'runtime updates'
        $transactions = Join-Path $updates 'runtime-transactions'
        $transactionItem = Get-Item -LiteralPath $transactions -Force
        if (-not $transactionItem.PSIsContainer -or ($transactionItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'invalid runtime transaction directory'
        }
        Assert-ExactChildNames $transactions @() 'runtime transactions'
    }
}

function Assert-SafeRoot {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path) -or $Path -notmatch '^[A-Za-z]:\\') {
        throw 'install root must be a drive-absolute local path'
    }
    [void](Assert-SafeRelativePath $Path.Substring(3))
    $full = [System.IO.Path]::GetFullPath($Path).TrimEnd('\')
    if (-not (Test-Path -LiteralPath $full -PathType Container)) { throw 'install root does not exist' }
    $drive = [System.IO.Path]::GetPathRoot($full)
    if ($full -ceq $drive.TrimEnd('\')) { throw 'install root cannot be a volume root' }
    $cursor = $full
    while (-not [string]::IsNullOrEmpty($cursor)) {
        $item = Get-Item -LiteralPath $cursor -Force
        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'install root contains a reparse point'
        }
        if ($cursor -ceq $drive.TrimEnd('\')) { break }
        $cursor = [System.IO.Path]::GetDirectoryName($cursor)
    }
    return $full
}

function Assert-NtfsPath {
    param([string]$Path)
    $drive = [System.IO.Path]::GetPathRoot([System.IO.Path]::GetFullPath($Path))
    $information = [System.IO.DriveInfo]::new($drive)
    if (-not $information.IsReady -or $information.DriveType -ne [System.IO.DriveType]::Fixed -or $information.DriveFormat -cne 'NTFS') {
        throw 'developer preview requires a local NTFS volume'
    }
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
        $state = Get-Content -LiteralPath (Join-Path $Root "offices\$office\office-state.json") -Raw | ConvertFrom-Json
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
    $manifestPath = Join-Path $rootFull $ManifestName
    $manifestItem = Get-Item -LiteralPath $manifestPath -Force
    if ($manifestItem.PSIsContainer -or ($manifestItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'unsafe preview manifest'
    }
    $raw = Get-Content -LiteralPath $manifestPath -Raw
    $manifestSha256 = [System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($raw))).Replace('-', '').ToLowerInvariant()
    if (-not [string]::IsNullOrEmpty($ExpectedManifestSha256) -and $manifestSha256 -cne $ExpectedManifestSha256) { throw 'installed preview manifest does not match the checked archive' }
    $manifest = if ($null -eq $ExpectedManifest) { $raw | ConvertFrom-Json } else { $ExpectedManifest }
    Assert-ExactProperties $manifest @('schema_version', 'label', 'architecture', 'runtime_version', 'files') 'preview manifest'
    if ($manifest.schema_version -ne 1 -or $manifest.label -cne 'developer-preview' -or $manifest.architecture -cne 'windows-x86_64' -or [string]::IsNullOrWhiteSpace([string]$manifest.runtime_version)) {
        throw 'invalid developer preview manifest'
    }
    $expected = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    [void]$expected.Add($ManifestName)
    foreach ($file in @($manifest.files)) {
        Assert-ExactProperties $file @('path', 'sha256', 'size') 'manifest file'
        $relative = [string]$file.path
        if ([string]::IsNullOrWhiteSpace($relative) -or (Test-MutableStatePath $relative) -or $relative.Contains('\') -or $relative.Contains(':') -or $relative.StartsWith('/') -or $relative -match '(^|/)\.\.(/|$)' -or -not $expected.Add($relative)) {
            throw 'manifest contains an unsafe or duplicate path'
        }
        [void](Assert-SafeRelativePath $relative)
        if ([string]$file.sha256 -notmatch '^[0-9a-f]{64}$' -or $file.size -lt 0) {
            throw 'manifest contains invalid file metadata'
        }
        $target = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($rootFull, $relative.Replace('/', '\')))
        if (-not $target.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw 'manifest path escapes install root'
        }
        $item = Get-Item -LiteralPath $target -Force
        if ($item.PSIsContainer -or ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or (Test-HardLink $item) -or $item.Length -ne [long]$file.size) {
            throw "unsafe installed member: $relative"
        }
        if ((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant() -cne [string]$file.sha256) {
            throw "installed checksum mismatch: $relative"
        }
    }
    $actual = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($item in Get-ChildItem -LiteralPath $rootFull -Recurse -Force) {
        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or (-not $item.PSIsContainer -and (Test-HardLink $item))) {
            throw 'installed tree contains a reparse point'
        }
        if (-not $item.PSIsContainer -and -not (Test-MutableStatePath $item.FullName.Substring($rootPrefix.Length).Replace('\', '/'))) {
            [void]$actual.Add($item.FullName.Substring($rootPrefix.Length).Replace('\', '/'))
        }
    }
    if ($actual.Count -ne $expected.Count -or @($actual | Where-Object { -not $expected.Contains($_) }).Count -ne 0) {
        throw 'installed tree contains unknown or missing bytes'
    }
    return $manifest
}

function Invoke-Verification {
    param([string]$Root)
    $safeRoot = Assert-SafeRoot $Root
    Assert-NtfsPath $safeRoot
    $archiveManifest = Assert-ArchiveManifest $Archive $ChecksumFile
    $manifest = Assert-InstalledTree $safeRoot $archiveManifest.manifest $archiveManifest.manifest_sha256
    Assert-AllFree $safeRoot $manifest.runtime_version
    Assert-MutableStateShape $safeRoot
    [pscustomobject]@{
        label = $manifest.label
        architecture = $manifest.architecture
        runtime_version = $manifest.runtime_version
        offices = $ExpectedOffices
        state = 'verified-all-free'
    }
}

Invoke-Verification $InstallRoot
