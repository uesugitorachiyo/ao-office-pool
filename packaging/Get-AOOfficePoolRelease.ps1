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

function Assert-Identity {
    param([object]$Value, [string]$ExpectedName, [string]$Kind)
    Assert-ExactFields $Value $script:IdentityFields $Kind
    if (
        $Value.name -cne $ExpectedName -or
        $Value.size -is [bool] -or
        $Value.size -isnot [ValueType] -or
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
    $bytes = [IO.File]::ReadAllBytes($Path)
    $value = Read-JsonBytes $bytes 'release contract'
    Assert-ExactFields $value $script:ReleaseFields 'release contract'
    if (
        $value.schema_version -ne 1 -or
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
        $value.schema_version -ne 1 -or
        $value.architecture -cne $Release.Value.architecture -or
        $value.immutable -ne $true -or
        $value.source.commit -cne $Release.Value.product_source_commit -or
        $value.source.clean -ne $true
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
    return [pscustomobject]@{ Value = $value; Identities = $identities }
}

function Read-CandidateManifest {
    param([string]$Path, [object]$Release)
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
        $ReleaseValue.target_commitish -cne $ReleaseContract.Value.product_source_commit -or
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

function Get-OfflineAssets {
    param([string]$SourceRoot, [object]$Release)
    $entries = @(Get-ChildItem -LiteralPath $SourceRoot -Force)
    if ($entries.Count -ne $script:ExpectedAssets.Count) {
        throw 'offline source asset set is invalid'
    }
    foreach ($entry in $entries) {
        if (-not $entry.PSIsContainer -and $script:ExpectedAssets -ccontains $entry.Name) { continue }
        throw 'offline source asset set is invalid'
    }
    $candidate = Read-CandidateManifest (Join-Path $SourceRoot 'candidate-manifest.json') $Release
    $assets = @()
    foreach ($identity in $candidate.Identities) {
        $path = Join-Path $SourceRoot $identity.name
        $bytes = [IO.File]::ReadAllBytes($path)
        if ($bytes.Length -ne $identity.size -or (Get-Sha256Bytes $bytes) -cne $identity.sha256) {
            throw "asset identity mismatch: $($identity.name)"
        }
        $assets += [pscustomobject]@{ Identity = $identity; Bytes = $bytes }
    }
    return $assets
}

function Write-VerifiedAssets {
    param([object[]]$Assets, [string]$DestinationPath)
    if (Test-Path -LiteralPath $DestinationPath) {
        $item = Get-Item -LiteralPath $DestinationPath -Force
        if (-not $item.PSIsContainer -or @(Get-ChildItem -LiteralPath $DestinationPath -Force).Count -ne 0) {
            throw 'destination must not contain files'
        }
    }
    else {
        [void](New-Item -ItemType Directory -Path $DestinationPath)
    }
    $temporaryFiles = [Collections.Generic.List[string]]::new()
    try {
        foreach ($asset in $Assets) {
            $final = Join-Path $DestinationPath $asset.Identity.name
            if (Test-Path -LiteralPath $final) {
                throw 'destination asset already exists'
            }
            $temporary = Join-Path $DestinationPath ('.' + $asset.Identity.name + '.' + [guid]::NewGuid().ToString('N') + '.tmp')
            $temporaryFiles.Add($temporary)
            $stream = [IO.File]::Open($temporary, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
            try { $stream.Write($asset.Bytes, 0, $asset.Bytes.Length) }
            finally { $stream.Dispose() }
            $written = [IO.File]::ReadAllBytes($temporary)
            if ($written.Length -ne $asset.Identity.size -or (Get-Sha256Bytes $written) -cne $asset.Identity.sha256) {
                throw 'written asset identity mismatch'
            }
            [IO.File]::Move($temporary, $final)
            [void]$temporaryFiles.Remove($temporary)
        }
    }
    finally {
        foreach ($temporary in $temporaryFiles) {
            if (Test-Path -LiteralPath $temporary) {
                Remove-Item -LiteralPath $temporary -Force
            }
        }
    }
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
    param([Uri]$ApiUri, [string]$Credential)
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
        $response = $downloadClient.GetAsync($redirect).GetAwaiter().GetResult()
        try {
            if (-not $response.IsSuccessStatusCode) {
                throw 'GitHub asset download failed'
            }
            return $response.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult()
        }
        finally { $response.Dispose() }
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
    Assert-ExactFields $fixture @('repository', 'release', 'redirects', 'candidate_manifest_path') 'metadata fixture'
    $contractPath = Assert-SafePath $Contract $true 'contract'
    $release = Read-ReleaseContract $contractPath
    $candidatePath = Assert-SafePath $fixture.candidate_manifest_path $true 'candidate fixture'
    $candidate = Read-CandidateManifest $candidatePath $release
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
    if ($PSCmdlet.ParameterSetName -eq 'Offline') {
        $sourcePath = Assert-SafePath $OfflineAssetRoot $true 'offline source'
        if (-not (Get-Item -LiteralPath $sourcePath -Force).PSIsContainer) {
            throw 'offline source must be a directory'
        }
        $assets = Get-OfflineAssets $sourcePath $release
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
            $assetMap = Assert-GitHubMetadata $repositoryValue $releaseValue $release @($release.CandidateIdentity)
            $candidateAsset = $assetMap['candidate-manifest.json']
            $candidateBytes = Invoke-GitHubAsset ([Uri]$candidateAsset.url) $githubCredential
            $candidate = Read-CandidateManifestBytes $candidateBytes $release
            $assetMap = Assert-GitHubMetadata $repositoryValue $releaseValue $release $candidate.Identities
            $assets = @()
            foreach ($identity in $candidate.Identities) {
                if ($identity.name -ceq 'candidate-manifest.json') {
                    $bytes = $candidateBytes
                }
                else {
                    $asset = $assetMap[$identity.name.ToLowerInvariant()]
                    $bytes = Invoke-GitHubAsset ([Uri]$asset.url) $githubCredential
                }
                if ($bytes.Length -ne $identity.size -or (Get-Sha256Bytes $bytes) -cne $identity.sha256) {
                    throw "asset identity mismatch: $($identity.name)"
                }
                $assets += [pscustomobject]@{ Identity = $identity; Bytes = $bytes }
            }
            $mode = 'authenticated'
        }
        finally {
            $githubCredential = $null
        }
    }
    Write-VerifiedAssets $assets $destinationPath
    $rows = @($assets | ForEach-Object { [ordered]@{
        name = $_.Identity.name
        size = $_.Identity.size
        sha256 = $_.Identity.sha256
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
