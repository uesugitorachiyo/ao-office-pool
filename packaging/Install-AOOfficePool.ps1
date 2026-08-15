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
                [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $target, $false)
            }
        }
    }
    finally {
        $zip.Dispose()
    }
}

function Test-MutableStatePath {
    param([string]$Path)
    if ($Path -cin $MutableStateFiles) { return $true }
    foreach ($directory in $MutableStateDirectories) {
        if ($Path -ceq $directory -or $Path.StartsWith("$directory/", [System.StringComparison]::Ordinal)) { return $true }
    }
    return $false
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

function Copy-StatePath {
    param([string]$Source, [string]$Destination)
    if (Test-Path -LiteralPath $Destination) { throw 'mutable state copy destination already exists' }
    $item = Get-Item -LiteralPath $Source -Force
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or (-not $item.PSIsContainer -and (Test-HardLink $item))) {
        throw 'unsafe mutable state copy source'
    }
    if ($item.PSIsContainer) {
        [void][System.IO.Directory]::CreateDirectory($Destination)
        foreach ($child in Get-ChildItem -LiteralPath $item.FullName -Force | Sort-Object Name) {
            [void](Assert-SafeRelativePath $child.Name)
            Copy-StatePath $child.FullName (Join-Path $Destination $child.Name)
        }
        return
    }
    [void][System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($Destination))
    $input = [System.IO.FileStream]::new($item.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    try {
        $output = [System.IO.FileStream]::new($Destination, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None, 1048576, [System.IO.FileOptions]::WriteThrough)
        try {
            $input.CopyTo($output)
            $output.Flush($true)
        }
        finally { $output.Dispose() }
    }
    finally { $input.Dispose() }
}

function Remove-StatePath {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or (-not $item.PSIsContainer -and (Test-HardLink $item))) {
        throw 'unsafe mutable state removal target'
    }
    if ($item.PSIsContainer) {
        foreach ($child in Get-ChildItem -LiteralPath $item.FullName -Force) { Remove-StatePath $child.FullName }
        [System.IO.Directory]::Delete($item.FullName)
    }
    else { [System.IO.File]::Delete($item.FullName) }
}

function Copy-MutableStateRoots {
    param([string]$Source, [string]$Destination, [switch]$IncludeLock)
    foreach ($relative in @($MutableStateFiles + $MutableStateDirectories)) {
        if (-not $IncludeLock -and $relative -ceq '.pool.lock') { continue }
        $path = Join-Path $Source $relative
        if (Test-Path -LiteralPath $path) { Copy-StatePath $path (Join-Path $Destination $relative) }
    }
}

function Clear-MutableStateRoots {
    param([string]$Root, [switch]$IncludeLock)
    foreach ($relative in @($MutableStateFiles + $MutableStateDirectories)) {
        if (-not $IncludeLock -and $relative -ceq '.pool.lock') { continue }
        Remove-StatePath (Join-Path $Root $relative)
    }
}

function Get-MutableStateInventory {
    param([string]$Root, [switch]$IncludeLock)
    $result = [System.Collections.Generic.List[object]]::new()
    foreach ($relative in @($MutableStateFiles + $MutableStateDirectories)) {
        if (-not $IncludeLock -and $relative -ceq '.pool.lock') { continue }
        $path = Join-Path $Root $relative
        if (-not (Test-Path -LiteralPath $path)) { continue }
        $item = Get-Item -LiteralPath $path -Force
        $members = @($item)
        if ($item.PSIsContainer) { $members += @(Get-ChildItem -LiteralPath $item.FullName -Recurse -Force) }
        foreach ($member in $members) {
            $memberRelative = $member.FullName.Substring([System.IO.Path]::GetFullPath($Root).TrimEnd('\').Length + 1).Replace('\', '/')
            if ($member.PSIsContainer) {
                $result.Add([pscustomobject]@{ path = $memberRelative; kind = 'directory'; size = 0; sha256 = '' })
            }
            else {
                $result.Add([pscustomobject]@{
                    path = $memberRelative
                    kind = 'file'
                    size = [long]$member.Length
                    sha256 = (Get-FileHash -LiteralPath $member.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
                })
            }
        }
    }
    return @($result | Sort-Object path)
}

function Assert-MutableStateEquivalent {
    param([string]$Accepted, [string]$Candidate, [switch]$IncludeLock)
    $acceptedInventory = @(Get-MutableStateInventory $Accepted -IncludeLock:$IncludeLock)
    $candidateInventory = @(Get-MutableStateInventory $Candidate -IncludeLock:$IncludeLock)
    $acceptedJson = ConvertTo-Json -InputObject $acceptedInventory -Depth 4 -Compress
    $candidateJson = ConvertTo-Json -InputObject $candidateInventory -Depth 4 -Compress
    if ($acceptedJson -cne $candidateJson) { throw 'mutable state bytes differ after transfer' }
}

function Save-CandidateMutableState {
    param([string]$Staging, [string]$CandidateState)
    if (Test-Path -LiteralPath $CandidateState) { throw 'candidate mutable state path already exists' }
    [void][System.IO.Directory]::CreateDirectory($CandidateState)
    Copy-MutableStateRoots $Staging $CandidateState -IncludeLock
    Assert-MutableStateShape $CandidateState
    Assert-MutableStateEquivalent $Staging $CandidateState -IncludeLock
}

function Copy-AcceptedMutableState {
    param([string]$Accepted, [string]$Staging)
    Clear-MutableStateRoots $Staging -IncludeLock
    Copy-MutableStateRoots $Accepted $Staging
    Assert-MutableStateShape $Staging -AllowMissingLock
    Assert-MutableStateEquivalent $Accepted $Staging
}

function Restore-CandidateMutableState {
    param([string]$Staging, [string]$CandidateState)
    Assert-MutableStateShape $CandidateState
    Clear-MutableStateRoots $Staging -IncludeLock
    Copy-MutableStateRoots $CandidateState $Staging -IncludeLock
    Assert-MutableStateShape $Staging
    Assert-MutableStateEquivalent $CandidateState $Staging -IncludeLock
}

function Assert-MatchingRuntimeVersion {
    param([string]$Root, [string]$ExpectedRuntimeVersion)
    $active = Get-Content -LiteralPath (Join-Path $Root 'pool.json') -Raw | ConvertFrom-Json
    if ([string]$active.runtime_version -cne $ExpectedRuntimeVersion) {
        throw 'archive runtime version differs; complete the governed RuntimeUpdate transition before package activation'
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
    param([string]$Root, [string]$Backup, [switch]$LockHeld)
    if (Test-Path -LiteralPath "$Root$ActivationName") {
        Recover-PendingActivation $Root -LockHeld:$LockHeld
    }
    elseif (Test-Path -LiteralPath $Backup) {
        throw 'activation recovery is required'
    }
}

function Enter-PoolLock {
    param([string]$Root)
    $path = Join-Path $Root '.pool.lock'
    $item = Get-Item -LiteralPath $path -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or (Test-HardLink $item)) {
        throw 'pool lock is not a regular unique file'
    }
    $stream = [System.IO.FileStream]::new($item.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, ([System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete))
    try { $stream.Lock(0, 1); return $stream } catch { $stream.Dispose(); throw }
}

function Publish-ActivationTransaction {
    param([string]$Source, [string]$Destination)
    if ($null -eq ('AOOfficePool.NativeJournalPublisher' -as [type])) {
        Add-Type -TypeDefinition @'
using System.Runtime.InteropServices;
namespace AOOfficePool {
    public static class NativeJournalPublisher {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool MoveFileExW(string source, string destination, uint flags);
    }
}
'@
    }
    if (-not [AOOfficePool.NativeJournalPublisher]::MoveFileExW($Source, $Destination, [uint32]9)) {
        $errorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw "activation transaction publication failed with Win32 error $errorCode"
    }
}

function Write-ActivationTransaction {
    param(
        [string]$Root,
        [string]$Backup,
        [string]$Staging,
        [string]$CandidateState,
        [ValidateSet('prepared', 'candidate-saved', 'state-copied', 'backup', 'staging-locked', 'active', 'committed')][string]$Phase
    )
    $path = "$Root$ActivationName"
    $temporary = "$path.$([guid]::NewGuid().ToString('N')).new"
    $bytes = [System.Text.Encoding]::UTF8.GetBytes(([ordered]@{
        schema_version = 1
        backup = $Backup
        staging = $Staging
        candidate_state = $CandidateState
        phase = $Phase
    } | ConvertTo-Json -Compress))
    $stream = [System.IO.FileStream]::new($temporary, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None, 4096, [System.IO.FileOptions]::WriteThrough)
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    }
    finally { $stream.Dispose() }
    Publish-ActivationTransaction $temporary $path
}

function Assert-ActivationTransactionPaths {
    param([string]$Root, [object]$Transaction)
    $prefix = "$Root.staging."
    if (-not ([string]$Transaction.staging).StartsWith($prefix, [System.StringComparison]::Ordinal)) {
        throw 'invalid activation staging path'
    }
    $suffix = ([string]$Transaction.staging).Substring($prefix.Length)
    if ($suffix -notmatch '^[0-9a-f]{32}$' -or [string]$Transaction.backup -cne "$Root.previous.$suffix" -or
        [string]$Transaction.candidate_state -cne "$Root.staging.$suffix.mutable") {
        throw 'invalid activation transaction paths'
    }
}

function Recover-PendingActivation {
    param([string]$Root, [switch]$LockHeld)
    $path = "$Root$ActivationName"
    if (-not (Test-Path -LiteralPath $path)) { return }
    $transactionItem = Get-Item -LiteralPath $path -Force
    if ($transactionItem.PSIsContainer -or ($transactionItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or (Test-HardLink $transactionItem)) {
        throw 'invalid activation transaction file'
    }
    try { $transaction = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json }
    catch { throw 'invalid activation transaction' }
    Assert-ExactProperties $transaction @('schema_version', 'backup', 'staging', 'candidate_state', 'phase') 'activation transaction'
    if ($transaction.schema_version -ne 1 -or [string]$transaction.phase -notin @('prepared', 'candidate-saved', 'state-copied', 'backup', 'staging-locked', 'active', 'committed')) {
        throw 'invalid activation transaction'
    }
    Assert-ActivationTransactionPaths $Root $transaction
    $rootLock = Join-Path $Root '.pool.lock'
    $backupLock = Join-Path $transaction.backup '.pool.lock'
    $stagedLock = Join-Path $transaction.staging '.pool.lock'
    if (-not $LockHeld) {
        $lockRoot = if (Test-Path -LiteralPath $rootLock) { $Root }
        elseif (Test-Path -LiteralPath $backupLock) { [string]$transaction.backup }
        elseif (Test-Path -LiteralPath $stagedLock) { [string]$transaction.staging }
        else {
            throw 'activation recovery has no authoritative lock'
        }
        $recoveryLock = Enter-PoolLock $lockRoot
        try { Recover-PendingActivation $Root -LockHeld } finally { $recoveryLock.Dispose() }
        return
    }
    $hasRoot = Test-Path -LiteralPath $Root
    $hasBackup = Test-Path -LiteralPath $transaction.backup
    $hasStaging = Test-Path -LiteralPath $transaction.staging
    if ([string]$transaction.phase -ceq 'committed') {
        if (-not $hasRoot -or -not $hasBackup -or $hasStaging -or -not (Test-Path -LiteralPath (Join-Path $Root '.pool.lock'))) {
            throw 'invalid committed activation state'
        }
        Remove-StatePath ([string]$transaction.candidate_state)
        [System.IO.File]::Delete($path)
        return
    }
    if ($hasRoot -and $hasBackup) {
        if ($hasStaging -or -not (Test-Path -LiteralPath (Join-Path $Root '.pool.lock')) -or (Test-Path -LiteralPath $backupLock)) {
            throw 'invalid active activation recovery state'
        }
        Move-Item -LiteralPath $Root -Destination $transaction.staging
        Move-Item -LiteralPath $stagedLock -Destination $backupLock
        Move-Item -LiteralPath $transaction.backup -Destination $Root
    }
    elseif (-not $hasRoot -and $hasBackup) {
        if (-not $hasStaging) { throw 'activation recovery lost the candidate tree' }
        if (-not (Test-Path -LiteralPath $backupLock)) {
            if (-not (Test-Path -LiteralPath $stagedLock)) { throw 'activation recovery has no authoritative lock' }
            Move-Item -LiteralPath $stagedLock -Destination $backupLock
        }
        Move-Item -LiteralPath $transaction.backup -Destination $Root
    }
    elseif ($hasRoot -and -not $hasBackup) {
        if (-not $hasStaging -or -not (Test-Path -LiteralPath (Join-Path $Root '.pool.lock'))) {
            throw 'activation recovery lost an installation tree or lock'
        }
    }
    else { throw 'invalid activation recovery state' }
    if ([string]$transaction.phase -ceq 'prepared') {
        Remove-StatePath ([string]$transaction.candidate_state)
    }
    else {
        if (-not (Test-Path -LiteralPath $transaction.candidate_state)) { throw 'activation recovery lost candidate mutable state' }
        Restore-CandidateMutableState ([string]$transaction.staging) ([string]$transaction.candidate_state)
        Write-ActivationTransaction $Root $transaction.backup $transaction.staging $transaction.candidate_state 'prepared'
        Remove-StatePath ([string]$transaction.candidate_state)
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
            try { Recover-PendingActivation $safeRoot -LockHeld } finally { $recoveryLock.Dispose() }
        }
        else { Recover-PendingActivation $safeRoot }
        $exists = Test-Path -LiteralPath $safeRoot
        if ($Operation -ceq 'Install' -and $exists) { throw 'install root already exists' }
        if ($Operation -cne 'Install' -and -not $exists) { throw 'update or rollback requires an existing install' }
        $suffix = [guid]::NewGuid().ToString('N')
        $staging = "$safeRoot.staging.$suffix"
        $backup = "$safeRoot.previous.$suffix"
        $candidateState = "$staging.mutable"
        Expand-VerifiedArchive $archiveStream $staging
        Assert-NtfsPath $staging
        Assert-InstalledTree $staging $archiveManifest.manifest $archiveManifest.manifest_sha256
        Assert-AllFree $staging $archiveManifest.manifest.runtime_version
        Assert-MutableStateShape $staging
        if ($exists) {
            $lock = Enter-PoolLock $safeRoot
            try {
                Assert-InstalledTree $safeRoot
                Assert-AllFree $safeRoot
                Assert-MutableStateShape $safeRoot
                Assert-MatchingRuntimeVersion $safeRoot $archiveManifest.manifest.runtime_version
                Write-ActivationTransaction $safeRoot $backup $staging $candidateState 'prepared'
                Save-CandidateMutableState $staging $candidateState
                Write-ActivationTransaction $safeRoot $backup $staging $candidateState 'candidate-saved'
                Copy-AcceptedMutableState $safeRoot $staging
                Assert-InstalledTree $safeRoot
                Assert-AllFree $safeRoot
                Assert-MutableStateShape $safeRoot
                Assert-MatchingRuntimeVersion $safeRoot $archiveManifest.manifest.runtime_version
                Write-ActivationTransaction $safeRoot $backup $staging $candidateState 'state-copied'
                Move-Item -LiteralPath $safeRoot -Destination $backup
                Write-ActivationTransaction $safeRoot $backup $staging $candidateState 'backup'
                Move-Item -LiteralPath (Join-Path $backup '.pool.lock') -Destination (Join-Path $staging '.pool.lock')
                Assert-MutableStateShape $staging
                Assert-MutableStateEquivalent $backup $staging
                Write-ActivationTransaction $safeRoot $backup $staging $candidateState 'staging-locked'
                Move-Item -LiteralPath $staging -Destination $safeRoot
                Write-ActivationTransaction $safeRoot $backup $staging $candidateState 'active'
                Assert-InstalledTree $safeRoot $archiveManifest.manifest $archiveManifest.manifest_sha256
                Assert-AllFree $safeRoot $archiveManifest.manifest.runtime_version
                Assert-MutableStateShape $safeRoot
                Assert-MutableStateEquivalent $backup $safeRoot
                Write-ActivationTransaction $safeRoot $backup $staging $candidateState 'committed'
                Remove-StatePath $candidateState
                [System.IO.File]::Delete("$safeRoot$ActivationName")
            }
            catch {
                $failure = $_
                Restore-PreviousInstall $safeRoot $backup -LockHeld
                throw $failure
            }
            finally { $lock.Dispose() }
        }
        else {
            Move-Item -LiteralPath $staging -Destination $safeRoot
            Assert-InstalledTree $safeRoot $archiveManifest.manifest $archiveManifest.manifest_sha256
            Assert-AllFree $safeRoot $archiveManifest.manifest.runtime_version
            Assert-MutableStateShape $safeRoot
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
