[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$InstallRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ExpectedOffices = @('O1', 'O2', 'O3', 'O4', 'O5')
$ManifestName = 'developer-preview-manifest.json'

function Assert-ExactProperties {
    param([object]$Value, [string[]]$Names, [string]$Kind)
    $actual = @($Value.PSObject.Properties.Name | Sort-Object)
    $expected = @($Names | Sort-Object)
    if (($actual -join "`n") -cne ($expected -join "`n")) { throw "invalid $Kind fields" }
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
    if (-not $information.IsReady -or $information.DriveFormat -cne 'NTFS') {
        throw 'developer preview requires an NTFS volume'
    }
}

function Assert-AllFree {
    param([string]$Root)
    $pool = Get-Content -LiteralPath (Join-Path $Root 'pool.json') -Raw | ConvertFrom-Json
    Assert-ExactProperties $pool @('schema_version', 'office_count', 'offices', 'runtime_version') 'pool'
    if ($pool.schema_version -ne 1 -or $pool.office_count -ne 5 -or (@($pool.offices) -join ',') -cne ($ExpectedOffices -join ',')) {
        throw 'pool must contain exactly O1 through O5'
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
    param([string]$Root)
    $rootFull = [System.IO.Path]::GetFullPath($Root).TrimEnd('\')
    $rootPrefix = $rootFull + '\'
    $manifestPath = Join-Path $rootFull $ManifestName
    $manifestItem = Get-Item -LiteralPath $manifestPath -Force
    if ($manifestItem.PSIsContainer -or ($manifestItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'unsafe preview manifest'
    }
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    Assert-ExactProperties $manifest @('schema_version', 'label', 'architecture', 'runtime_version', 'files') 'preview manifest'
    if ($manifest.schema_version -ne 1 -or $manifest.label -cne 'developer-preview' -or $manifest.architecture -cne 'windows-x86_64' -or [string]::IsNullOrWhiteSpace([string]$manifest.runtime_version)) {
        throw 'invalid developer preview manifest'
    }
    $expected = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    [void]$expected.Add($ManifestName)
    foreach ($file in @($manifest.files)) {
        Assert-ExactProperties $file @('path', 'sha256', 'size') 'manifest file'
        $relative = [string]$file.path
        if ([string]::IsNullOrWhiteSpace($relative) -or $relative.Contains('\') -or $relative.Contains(':') -or $relative.StartsWith('/') -or $relative -match '(^|/)\.\.(/|$)' -or -not $expected.Add($relative)) {
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
        if (-not $item.PSIsContainer) {
            [void]$actual.Add($item.FullName.Substring($rootPrefix.Length).Replace('\', '/'))
        }
    }
    if ($actual.Count -ne $expected.Count -or @($actual | Where-Object { -not $expected.Contains($_) }).Count -ne 0) {
        throw 'installed tree contains unknown or missing bytes'
    }
    $pool = Get-Content -LiteralPath (Join-Path $rootFull 'pool.json') -Raw | ConvertFrom-Json
    if ([string]$pool.runtime_version -cne [string]$manifest.runtime_version) {
        throw 'manifest and pool runtime versions differ'
    }
    return $manifest
}

function Invoke-Verification {
    param([string]$Root)
    $safeRoot = Assert-SafeRoot $Root
    Assert-NtfsPath $safeRoot
    $manifest = Assert-InstalledTree $safeRoot
    Assert-AllFree $safeRoot
    [pscustomobject]@{
        label = $manifest.label
        architecture = $manifest.architecture
        runtime_version = $manifest.runtime_version
        offices = $ExpectedOffices
        state = 'verified-all-free'
    }
}

Invoke-Verification $InstallRoot
