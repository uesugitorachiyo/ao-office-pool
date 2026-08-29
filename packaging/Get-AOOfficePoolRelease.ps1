[CmdletBinding(DefaultParameterSetName = 'Authenticated')]
param(
    [string]$Contract = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\manifests\developer-preview-release.json')),
    [string]$Destination = [IO.Path]::GetFullPath((Join-Path (Get-Location) 'downloads')),
    [Parameter(ParameterSetName = 'Offline', Mandatory = $true)]
    [string]$OfflineAssetRoot,
    [Parameter(ParameterSetName = 'Authenticated')]
    [string]$Repository,
    [Parameter(ParameterSetName = 'Authenticated')]
    [string]$Tag
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ExpectedRepository = 'uesugitorachiyo/ao-office-pool'
$script:ExpectedAssets = @(
    'candidate-manifest.json',
    'ao-office-pool-developer-preview.zip',
    'ao-office-pool-developer-preview.zip.sha256',
    'member-inventory.json',
    'provenance.json',
    'RELEASE-NOTES.md',
    'SBOM.json',
    'SHA256SUMS'
)
$script:ReleaseFields = @(
    'schema_version', 'repository', 'visibility', 'tag',
    'product_source_commit', 'architecture', 'asset_names',
    'candidate_manifest'
)
$script:CandidateFields = @(
    'schema_version', 'candidate_id', 'label', 'architecture', 'source',
    'component_lock_sha256', 'archive', 'components', 'metadata',
    'installer', 'immutable', 'authority'
)
$script:IdentityFields = @('name', 'size', 'sha256')
$script:ComponentFields = @('name', 'version', 'repository', 'commit', 'asset', 'license', 'sha256')
$script:InstallerContract = [ordered]@{
    acquire = 'packaging/Get-AOOfficePoolRelease.ps1'
    ai_runbook = 'docs/AI_OPERATOR_RUNBOOK.md'
    install = 'packaging/Install-AOOfficePool.ps1'
    read_first = 'README-FIRST.md'
    uninstall = 'packaging/Uninstall-AOOfficePool.ps1'
    verify = 'packaging/Verify-AOOfficePool.ps1'
}

function Assert-ExactFields {
    param([object]$Value, [string[]]$Names, [string]$Kind)
    if ($null -eq $Value -or $Value -isnot [pscustomobject]) {
        throw "$Kind must be an object"
    }
    $actual = @($Value.PSObject.Properties.Name)
    if ($actual.Count -ne $Names.Count) {
        throw "$Kind fields are invalid"
    }
    foreach ($name in $Names) {
        if ($actual -cnotcontains $name) {
            throw "$Kind fields are invalid"
        }
    }
}

function Get-Sha256Bytes {
    param([byte[]]$Bytes)
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        return ([Convert]::ToHexString($algorithm.ComputeHash($Bytes))).ToLowerInvariant()
    }
    finally {
        $algorithm.Dispose()
    }
}

function Read-JsonBytes {
    param([byte[]]$Bytes, [string]$Kind)
    try {
        $text = [Text.UTF8Encoding]::new($false, $true).GetString($Bytes)
        return $text | ConvertFrom-Json
    }
    catch {
        throw "$Kind is not valid UTF-8 JSON"
    }
}

function Assert-SafePath {
    param([string]$Path, [bool]$MustExist, [string]$Kind)
    if ([string]::IsNullOrWhiteSpace($Path) -or $Path.IndexOfAny([IO.Path]::GetInvalidPathChars()) -ge 0) {
        throw "$Kind path is invalid"
    }
    $full = [IO.Path]::GetFullPath($Path)
    if (-not [IO.Path]::IsPathFullyQualified($full)) {
        throw "$Kind path must be absolute"
    }
    if ($MustExist -and -not (Test-Path -LiteralPath $full)) {
        throw "$Kind does not exist"
    }
    $cursor = $full
    if (-not (Test-Path -LiteralPath $cursor)) {
        $cursor = Split-Path -Parent $cursor
    }
    while (-not [string]::IsNullOrEmpty($cursor)) {
        if (Test-Path -LiteralPath $cursor) {
            $item = Get-Item -LiteralPath $cursor -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "$Kind path contains a reparse point"
            }
        }
        $parent = Split-Path -Parent $cursor
        if ($parent -eq $cursor) { break }
        $cursor = $parent
    }
    return $full
}

function Assert-RegularUnlinkedFile {
    param([string]$Path, [string]$Kind)
    $item = Get-Item -LiteralPath $Path -Force
    $linkType = $item.PSObject.Properties['LinkType']
    if (
        $item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        ($null -ne $linkType -and -not [string]::IsNullOrEmpty([string]$linkType.Value))
    ) {
        throw "$Kind must be a regular unlinked file"
    }
}

function Assert-Identity {
    param([object]$Value, [string]$ExpectedName, [string]$Kind)
    Assert-ExactFields $Value $script:IdentityFields $Kind
    if (
        $Value.name -isnot [string] -or
        $Value.name -cne $ExpectedName -or
        $Value.size -is [bool] -or
        -not ($Value.size -is [int] -or $Value.size -is [long]) -or
        [long]$Value.size -lt 1 -or
        $Value.sha256 -isnot [string] -or
        $Value.sha256 -cnotmatch '^[0-9a-f]{64}$'
    ) {
        throw "$Kind identity is invalid"
    }
    return [ordered]@{
        name = [string]$Value.name
        size = [long]$Value.size
        sha256 = [string]$Value.sha256
    }
}

function Read-ReleaseContract {
    param([string]$Path)
    Assert-RegularUnlinkedFile $Path 'release contract'
    $bytes = [IO.File]::ReadAllBytes($Path)
    $value = Read-JsonBytes $bytes 'release contract'
    Assert-ExactFields $value $script:ReleaseFields 'release contract'
    if (
        -not ($value.schema_version -is [int] -or $value.schema_version -is [long]) -or
        [long]$value.schema_version -cne 1 -or
        $value.repository -cne $script:ExpectedRepository -or
        $value.visibility -cne 'private' -or
        $value.tag -isnot [string] -or
        $value.tag -cnotmatch '^developer-preview-v[0-9]{2}$' -or
        $value.product_source_commit -isnot [string] -or
        $value.product_source_commit -cnotmatch '^[0-9a-f]{40}$' -or
        $value.architecture -cne 'windows-x86_64'
    ) {
        throw 'release contract identity is invalid'
    }
    $names = @($value.asset_names)
    if ($names.Count -ne $script:ExpectedAssets.Count) {
        throw 'release contract asset set is invalid'
    }
    for ($index = 0; $index -lt $script:ExpectedAssets.Count; $index++) {
        if ($names[$index] -cne $script:ExpectedAssets[$index]) {
            throw 'release contract asset set is invalid'
        }
    }
    $identity = Assert-Identity $value.candidate_manifest 'candidate-manifest.json' 'candidate manifest'
    return [pscustomobject]@{ Value = $value; CandidateIdentity = $identity }
}

function Read-CandidateManifestBytes {
    param([byte[]]$Bytes, [object]$Release)
    $identity = $Release.CandidateIdentity
    if ($Bytes.Length -ne $identity.size -or (Get-Sha256Bytes $Bytes) -cne $identity.sha256) {
        throw 'candidate manifest identity mismatch'
    }
    $value = Read-JsonBytes $Bytes 'candidate manifest'
    Assert-ExactFields $value $script:CandidateFields 'candidate manifest'
    Assert-ExactFields $value.source @('commit', 'clean') 'candidate source'
    if (
        -not ($value.schema_version -is [int] -or $value.schema_version -is [long]) -or
        [long]$value.schema_version -cne 1 -or
        $value.architecture -isnot [string] -or
        $value.architecture -cne $Release.Value.architecture -or
        $value.immutable -isnot [bool] -or
        $value.immutable -cne $true -or
        $value.source.commit -isnot [string] -or
        $value.source.commit -cne $Release.Value.product_source_commit -or
        $value.source.clean -isnot [bool] -or
        $value.source.clean -cne $true
    ) {
        throw 'candidate manifest contract mismatch'
    }
    $rows = @($value.metadata)
    if ($rows.Count -ne ($script:ExpectedAssets.Count - 1)) {
        throw 'candidate metadata set is invalid'
    }
    $identities = @([ordered]@{
        name = $identity.name
        size = $identity.size
        sha256 = $identity.sha256
    })
    for ($index = 0; $index -lt $rows.Count; $index++) {
        $expectedName = $script:ExpectedAssets[$index + 1]
        $identities += Assert-Identity $rows[$index] $expectedName 'candidate metadata'
    }
    $archive = Assert-Identity $value.archive $script:ExpectedAssets[1] 'candidate archive'
    if (
        $archive.name -cne $identities[1].name -or
        $archive.size -ne $identities[1].size -or
        $archive.sha256 -cne $identities[1].sha256
    ) {
        throw 'candidate archive identity is not metadata-bound'
    }
    $lockPath = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\manifests\components.lock.json'))
    $lockBytes = [IO.File]::ReadAllBytes($lockPath)
    $lock = Read-JsonBytes $lockBytes 'component lock'
    $lockedComponents = @($lock.components)
    $candidateComponents = @($value.components)
    if ($lockedComponents.Count -ne 8 -or $candidateComponents.Count -ne 8) {
        throw 'candidate components are not lock-bound'
    }
    for ($index = 0; $index -lt 8; $index++) {
        Assert-ExactFields $lockedComponents[$index] $script:ComponentFields 'locked component'
        Assert-ExactFields $candidateComponents[$index] $script:ComponentFields 'candidate component'
        foreach ($name in $script:ComponentFields) {
            if (
                $candidateComponents[$index].$name -isnot [string] -or
                $lockedComponents[$index].$name -isnot [string] -or
                $candidateComponents[$index].$name -cne $lockedComponents[$index].$name
            ) {
                throw 'candidate components are not lock-bound'
            }
        }
    }
    if ($value.component_lock_sha256 -isnot [string] -or $value.component_lock_sha256 -cne (Get-Sha256Bytes $lockBytes)) {
        throw 'candidate components are not lock-bound'
    }
    $version = $Release.Value.tag.Substring('developer-preview-'.Length)
    $expectedCandidateId = "windows-ai-bootstrap-$version-$($Release.Value.product_source_commit.Substring(0, 7))"
    if ($value.candidate_id -isnot [string] -or $value.candidate_id -cne $expectedCandidateId -or $value.label -isnot [string] -or $value.label -cne 'developer-preview') {
        throw 'candidate identity is invalid'
    }
    Assert-ExactFields $value.installer @($script:InstallerContract.Keys) 'candidate installer'
    foreach ($name in $script:InstallerContract.Keys) {
        if ($value.installer.$name -isnot [string] -or $value.installer.$name -cne $script:InstallerContract[$name]) {
            throw 'candidate installer contract is invalid'
        }
    }
    Assert-ExactFields $value.authority @('publication_authorized', 'release_visibility', 'tag_target') 'candidate authority'
    if (
        $value.authority.publication_authorized -isnot [bool] -or
        $value.authority.publication_authorized -cne $false -or
        $value.authority.release_visibility -isnot [string] -or
        $value.authority.release_visibility -cne 'private' -or
        $value.authority.tag_target -isnot [string] -or
        $value.authority.tag_target -cne $Release.Value.product_source_commit
    ) {
        throw 'candidate authority contract is invalid'
    }
    return [pscustomobject]@{ Value = $value; Identities = $identities }
}

function Read-CandidateManifest {
    param([string]$Path, [object]$Release)
    Assert-RegularUnlinkedFile $Path 'candidate manifest'
    return Read-CandidateManifestBytes ([IO.File]::ReadAllBytes($Path)) $Release
}

function Assert-LocalDestination {
    param([string]$Path)
    if ($env:OS -ne 'Windows_NT') {
        throw 'destination requires Windows'
    }
    $root = [IO.Path]::GetPathRoot($Path)
    $drive = [IO.DriveInfo]::new($root)
    if ($drive.DriveType -ne [IO.DriveType]::Fixed -or $drive.DriveFormat -cne 'NTFS') {
        throw 'destination must be fixed local NTFS'
    }
}

function Assert-RedirectUri {
    param([string]$Value)
    try { $uri = [Uri]$Value }
    catch { throw 'asset redirect URI is invalid' }
    if (
        $uri.Scheme -cne 'https' -or
        @('objects.githubusercontent.com', 'release-assets.githubusercontent.com') -cnotcontains $uri.Host
    ) {
        throw 'asset redirect host is invalid'
    }
    return $uri
}

function Assert-GitHubMetadata {
    param(
        [object]$RepositoryValue,
        [object]$ReleaseValue,
        [object]$ReleaseContract,
        [object[]]$ExpectedIdentities,
        [object[]]$Redirects = @()
    )
    if (
        $null -eq $RepositoryValue -or
        $RepositoryValue.full_name -cne $ReleaseContract.Value.repository -or
        $RepositoryValue.private -ne $true -or
        $RepositoryValue.visibility -cne 'private'
    ) {
        throw 'GitHub repository metadata is invalid'
    }
    if (
        $null -eq $ReleaseValue -or
        $ReleaseValue.tag_name -cne $ReleaseContract.Value.tag -or
        $ReleaseValue.target_commitish -isnot [string] -or
        [string]::IsNullOrWhiteSpace($ReleaseValue.target_commitish) -or
        $ReleaseValue.draft -ne $false -or
        $ReleaseValue.prerelease -ne $true
    ) {
        throw 'GitHub release metadata is invalid'
    }
    $assets = @($ReleaseValue.assets)
    if ($assets.Count -ne $script:ExpectedAssets.Count) {
        throw 'GitHub release asset set is invalid'
    }
    $assetMap = @{}
    foreach ($asset in $assets) {
        if ($null -eq $asset -or $asset.name -isnot [string] -or $assetMap.ContainsKey($asset.name.ToLowerInvariant())) {
            throw 'GitHub release asset set is invalid'
        }
        try { $uri = [Uri]$asset.url }
        catch { throw 'GitHub asset API URI is invalid' }
        $expectedPrefix = '/repos/' + $script:ExpectedRepository + '/releases/assets/'
        if ($uri.Scheme -cne 'https' -or $uri.Host -cne 'api.github.com' -or -not $uri.AbsolutePath.StartsWith($expectedPrefix, [StringComparison]::Ordinal)) {
            throw 'GitHub asset API host is invalid'
        }
        $assetMap[$asset.name.ToLowerInvariant()] = $asset
    }
    foreach ($name in $script:ExpectedAssets) {
        if (-not $assetMap.ContainsKey($name.ToLowerInvariant())) {
            throw 'GitHub release asset set is invalid'
        }
    }
    foreach ($identity in $ExpectedIdentities) {
        $asset = $assetMap[$identity.name.ToLowerInvariant()]
        if ($asset.size -is [bool] -or $asset.size -isnot [ValueType] -or [long]$asset.size -ne $identity.size) {
            throw 'GitHub release asset size is invalid'
        }
    }
    if ($Redirects.Count -gt 0) {
        if ($Redirects.Count -ne $script:ExpectedAssets.Count) {
            throw 'asset redirect set is invalid'
        }
        $redirectNames = @{}
        foreach ($redirect in $Redirects) {
            if ($null -eq $redirect -or $redirect.name -isnot [string] -or $redirectNames.ContainsKey($redirect.name.ToLowerInvariant())) {
                throw 'asset redirect set is invalid'
            }
            if (-not $assetMap.ContainsKey($redirect.name.ToLowerInvariant())) {
                throw 'asset redirect set is invalid'
            }
            [void](Assert-RedirectUri $redirect.url)
            $redirectNames[$redirect.name.ToLowerInvariant()] = $true
        }
    }
    return $assetMap
}

function Assert-GitHubTagObjects {
    param([object[]]$Objects, [object]$ReleaseContract)
    if ($Objects.Count -lt 1 -or $Objects.Count -gt 8) {
        throw 'GitHub tag ref is missing or too deep'
    }
    $first = $Objects[0]
    if ($null -eq $first -or $first.ref -cne ('refs/tags/' + $ReleaseContract.Value.tag) -or $null -eq $first.object) {
        throw 'GitHub tag ref is invalid'
    }
    $current = $first.object
    $seen = @{}
    $used = 1
    while ($true) {
        if ($null -eq $current -or $current.sha -isnot [string] -or $current.sha -cnotmatch '^[0-9a-f]{40}$') {
            throw 'GitHub tag object is invalid'
        }
        if ($current.type -ceq 'commit') {
            if ($current.sha -cne $ReleaseContract.Value.product_source_commit -or $used -ne $Objects.Count) {
                throw 'GitHub tag does not resolve to the pinned commit'
            }
            return
        }
        if ($current.type -cne 'tag' -or $current.url -isnot [string]) {
            throw 'GitHub tag object type is invalid'
        }
        $expectedPrefix = 'https://api.github.com/repos/' + $script:ExpectedRepository + '/git/tags/'
        if (-not $current.url.StartsWith($expectedPrefix, [StringComparison]::Ordinal) -or $seen.ContainsKey($current.sha)) {
            throw 'GitHub tag chain is invalid'
        }
        $seen[$current.sha] = $true
        if ($used -ge $Objects.Count) {
            throw 'GitHub annotated tag object is missing'
        }
        $tag = $Objects[$used]
        $used++
        if ($null -eq $tag -or $tag.sha -cne $current.sha -or $null -eq $tag.object) {
            throw 'GitHub annotated tag object is invalid'
        }
        $current = $tag.object
    }
}

function Get-GitHubTagObjects {
    param([string]$ApiRoot, [object]$ReleaseContract, [string]$Credential)
    $refUri = $ApiRoot + '/git/ref/tags/' + [Uri]::EscapeDataString($ReleaseContract.Value.tag)
    $objects = @((Invoke-GitHubJson $refUri $Credential))
    $current = $objects[0].object
    $seen = @{}
    while ($null -ne $current -and $current.type -ceq 'tag') {
        if ($objects.Count -ge 8 -or $current.sha -isnot [string] -or $seen.ContainsKey($current.sha)) {
            throw 'GitHub tag chain is invalid'
        }
        $seen[$current.sha] = $true
        $expectedPrefix = 'https://api.github.com/repos/' + $script:ExpectedRepository + '/git/tags/'
        if ($current.url -isnot [string] -or -not $current.url.StartsWith($expectedPrefix, [StringComparison]::Ordinal)) {
            throw 'GitHub tag object URI is invalid'
        }
        $objects += Invoke-GitHubJson $current.url $Credential
        $current = $objects[-1].object
    }
    Assert-GitHubTagObjects $objects $ReleaseContract
    return $objects
}

function Write-VerifiedStream {
    param([IO.Stream]$InputStream, [string]$Path, [object]$Identity)
    $output = $null
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        $output = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        $buffer = [byte[]]::new(1048576)
        [long]$count = 0
        while (($read = $InputStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $output.Write($buffer, 0, $read)
            [void]$algorithm.TransformBlock($buffer, 0, $read, $buffer, 0)
            $count += $read
        }
        [void]$algorithm.TransformFinalBlock([byte[]]::new(0), 0, 0)
        $digest = ([Convert]::ToHexString($algorithm.Hash)).ToLowerInvariant()
        if ($count -ne $Identity.size -or $digest -cne $Identity.sha256) {
            throw "asset identity mismatch: $($Identity.name)"
        }
    }
    catch {
        if ($null -ne $output) { $output.Dispose(); $output = $null }
        if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Force }
        throw
    }
    finally {
        if ($null -ne $output) { $output.Dispose() }
        $algorithm.Dispose()
    }
}

function Copy-VerifiedFile {
    param([string]$Source, [string]$Destination, [object]$Identity)
    $input = [IO.File]::Open($Source, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try { Write-VerifiedStream $input $Destination $Identity }
    finally { $input.Dispose() }
}

function Stage-OfflineAssets {
    param([string]$SourceRoot, [object]$Release, [string]$StagingRoot)
    $entries = @(Get-ChildItem -LiteralPath $SourceRoot -Force)
    if ($entries.Count -ne $script:ExpectedAssets.Count) {
        throw 'offline source asset set is invalid'
    }
    foreach ($entry in $entries) {
        if (-not $entry.PSIsContainer -and $script:ExpectedAssets -ccontains $entry.Name) {
            Assert-RegularUnlinkedFile $entry.FullName 'offline asset'
            continue
        }
        throw 'offline source asset set is invalid'
    }
    $candidateSource = Join-Path $SourceRoot 'candidate-manifest.json'
    $candidateDestination = Join-Path $StagingRoot 'candidate-manifest.json'
    Copy-VerifiedFile $candidateSource $candidateDestination $Release.CandidateIdentity
    $candidate = Read-CandidateManifest $candidateDestination $Release
    foreach ($identity in $candidate.Identities | Select-Object -Skip 1) {
        Copy-VerifiedFile (Join-Path $SourceRoot $identity.name) (Join-Path $StagingRoot $identity.name) $identity
    }
    return $candidate.Identities
}

function New-AssetStaging {
    param([string]$DestinationPath)
    if (Test-Path -LiteralPath $DestinationPath) {
        throw 'destination must not exist'
    }
    $parent = Split-Path -Parent $DestinationPath
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        [void][IO.Directory]::CreateDirectory($parent)
    }
    $staging = Join-Path $parent ('.ao-office-pool-staging-' + [guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($staging)
    return $staging
}

function Publish-StagedAssets {
    param([string]$StagingRoot, [string]$DestinationPath)
    if (Test-Path -LiteralPath $DestinationPath) { throw 'destination already exists' }
    [IO.Directory]::Move($StagingRoot, $DestinationPath)
}

function Get-PortableDestination {
    param([string]$Path)
    $working = [IO.Path]::GetFullPath((Get-Location).Path)
    $prefix = $working.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    if ($Path.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        return [IO.Path]::GetRelativePath($working, $Path).Replace('\', '/')
    }
    return Split-Path -Leaf $Path
}

function Invoke-GitHubJson {
    param([string]$Uri, [string]$Credential)
    $handler = [Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false
    $client = [Net.Http.HttpClient]::new($handler)
    try {
        $request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Get, $Uri)
        $request.Headers.Authorization = [Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer', $Credential)
        $request.Headers.Accept.Add([Net.Http.Headers.MediaTypeWithQualityHeaderValue]::new('application/vnd.github+json'))
        $request.Headers.UserAgent.ParseAdd('ao-office-pool-bootstrap/1')
        try {
            $response = $client.SendAsync($request).GetAwaiter().GetResult()
            try {
                if (-not $response.IsSuccessStatusCode) {
                    throw 'GitHub metadata request failed'
                }
                $bytes = $response.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult()
                return Read-JsonBytes $bytes 'GitHub metadata'
            }
            finally { $response.Dispose() }
        }
        finally { $request.Dispose() }
    }
    finally {
        $client.Dispose()
        $handler.Dispose()
    }
}

function Invoke-GitHubAsset {
    param([Uri]$ApiUri, [string]$Credential, [string]$DestinationPath, [object]$Identity)
    if ($ApiUri.Scheme -cne 'https' -or $ApiUri.Host -cne 'api.github.com') {
        throw 'GitHub asset API host is invalid'
    }
    $handler = [Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false
    $client = [Net.Http.HttpClient]::new($handler)
    try {
        $request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Get, $ApiUri)
        $request.Headers.Authorization = [Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer', $Credential)
        $request.Headers.Accept.Add([Net.Http.Headers.MediaTypeWithQualityHeaderValue]::new('application/octet-stream'))
        $request.Headers.UserAgent.ParseAdd('ao-office-pool-bootstrap/1')
        try {
            $response = $client.SendAsync($request).GetAwaiter().GetResult()
            try {
                if ([int]$response.StatusCode -lt 300 -or [int]$response.StatusCode -ge 400 -or $null -eq $response.Headers.Location) {
                    throw 'GitHub asset redirect is invalid'
                }
                $redirect = Assert-RedirectUri $response.Headers.Location.AbsoluteUri
            }
            finally { $response.Dispose() }
        }
        finally { $request.Dispose() }
    }
    finally {
        $client.Dispose()
        $handler.Dispose()
    }

    $downloadHandler = [Net.Http.HttpClientHandler]::new()
    $downloadHandler.AllowAutoRedirect = $false
    $downloadClient = [Net.Http.HttpClient]::new($downloadHandler)
    try {
        $request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Get, $redirect)
        try {
            $response = $downloadClient.SendAsync($request, [Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
            try {
            if (-not $response.IsSuccessStatusCode) {
                throw 'GitHub asset download failed'
            }
                $input = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
                try { Write-VerifiedStream $input $DestinationPath $Identity }
                finally { $input.Dispose() }
            }
            finally { $response.Dispose() }
        }
        finally { $request.Dispose() }
    }
    finally {
        $downloadClient.Dispose()
        $downloadHandler.Dispose()
    }
}

function Invoke-MetadataFixture {
    if ($env:AO_OFFICE_POOL_TEST_MODE -cne '1') {
        throw 'metadata fixture is not allowed'
    }
    $fixturePath = Assert-SafePath $env:AO_OFFICE_POOL_METADATA_FIXTURE $true 'metadata fixture'
    $fixture = Read-JsonBytes ([IO.File]::ReadAllBytes($fixturePath)) 'metadata fixture'
    Assert-ExactFields $fixture @('repository', 'release', 'tag_objects', 'redirects', 'candidate_manifest_path') 'metadata fixture'
    $contractPath = Assert-SafePath $Contract $true 'contract'
    $release = Read-ReleaseContract $contractPath
    $candidatePath = Assert-SafePath $fixture.candidate_manifest_path $true 'candidate fixture'
    $candidate = Read-CandidateManifest $candidatePath $release
    Assert-GitHubTagObjects @($fixture.tag_objects) $release
    [void](Assert-GitHubMetadata $fixture.repository $fixture.release $release $candidate.Identities @($fixture.redirects))
    [ordered]@{ metadata = 'valid' } | ConvertTo-Json -Compress
}

function Invoke-Acquisition {
    $packageContract = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\manifests\developer-preview-release.json'))
    $contractPath = Assert-SafePath $Contract $true 'contract'
    if ($env:AO_OFFICE_POOL_TEST_MODE -cne '1' -and -not $contractPath.Equals($packageContract, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'alternate contract is not allowed'
    }
    $destinationPath = Assert-SafePath $Destination $false 'destination'
    Assert-LocalDestination $destinationPath
    $release = Read-ReleaseContract $contractPath
    $stagingPath = New-AssetStaging $destinationPath
    try {
      if ($PSCmdlet.ParameterSetName -eq 'Offline') {
        $sourcePath = Assert-SafePath $OfflineAssetRoot $true 'offline source'
        if (-not (Get-Item -LiteralPath $sourcePath -Force).PSIsContainer) {
            throw 'offline source must be a directory'
        }
        $identities = Stage-OfflineAssets $sourcePath $release $stagingPath
        $mode = 'offline'
      }
      else {
        if ((-not [string]::IsNullOrEmpty($Repository) -and $Repository -cne $release.Value.repository) -or
            (-not [string]::IsNullOrEmpty($Tag) -and $Tag -cne $release.Value.tag)) {
            throw 'requested release does not match the package contract'
        }
        $githubCredential = [Environment]::GetEnvironmentVariable('GITHUB_TOKEN')
        if ([string]::IsNullOrWhiteSpace($githubCredential)) {
            throw 'GITHUB_TOKEN is required'
        }
        try {
            $apiRoot = 'https://api.github.com/repos/' + $script:ExpectedRepository
            $repositoryValue = Invoke-GitHubJson $apiRoot $githubCredential
            $releaseUri = $apiRoot + '/releases/tags/' + [Uri]::EscapeDataString($release.Value.tag)
            $releaseValue = Invoke-GitHubJson $releaseUri $githubCredential
            [void](Get-GitHubTagObjects $apiRoot $release $githubCredential)
            $assetMap = Assert-GitHubMetadata $repositoryValue $releaseValue $release @($release.CandidateIdentity)
            $candidateAsset = $assetMap['candidate-manifest.json']
            $candidatePath = Join-Path $stagingPath 'candidate-manifest.json'
            Invoke-GitHubAsset ([Uri]$candidateAsset.url) $githubCredential $candidatePath $release.CandidateIdentity
            $candidate = Read-CandidateManifest $candidatePath $release
            $assetMap = Assert-GitHubMetadata $repositoryValue $releaseValue $release $candidate.Identities
            foreach ($identity in $candidate.Identities | Select-Object -Skip 1) {
                $asset = $assetMap[$identity.name.ToLowerInvariant()]
                Invoke-GitHubAsset ([Uri]$asset.url) $githubCredential (Join-Path $stagingPath $identity.name) $identity
            }
            $identities = $candidate.Identities
            $mode = 'authenticated'
        }
        finally {
            $githubCredential = $null
        }
      }
      Publish-StagedAssets $stagingPath $destinationPath
      $stagingPath = $null
    }
    finally {
      if ($null -ne $stagingPath -and (Test-Path -LiteralPath $stagingPath)) {
        Remove-Item -LiteralPath $stagingPath -Recurse -Force
      }
    }
    $rows = @($identities | ForEach-Object { [ordered]@{
        name = $_.name
        size = $_.size
        sha256 = $_.sha256
    } })
    [ordered]@{
        schema_version = 1
        mode = $mode
        repository = $release.Value.repository
        tag = $release.Value.tag
        product_source_commit = $release.Value.product_source_commit
        architecture = $release.Value.architecture
        destination = Get-PortableDestination $destinationPath
        assets = $rows
    } | ConvertTo-Json -Depth 5 -Compress
}

try {
    if ([string]::IsNullOrEmpty($env:AO_OFFICE_POOL_METADATA_FIXTURE)) {
        Invoke-Acquisition
    }
    else {
        Invoke-MetadataFixture
    }
}
catch {
    [Console]::Error.WriteLine('AO office pool acquisition failed: ' + $_.Exception.Message)
    exit 1
}
