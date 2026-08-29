[CmdletBinding()]
param(
  [string]$Contract = (Join-Path $PSScriptRoot '..\manifests\public-release.json'),
  [Parameter(Mandatory = $true)]
  [string]$Destination
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:Repository = 'uesugitorachiyo/ao-office-pool'
$script:Tag = 'v0.1.2'
$script:Architecture = 'windows-x86_64'
$script:AssetNames = @(
  'ao-office-pool-v0.1.2-windows-x86_64.zip',
  'ao-office-pool-v0.1.2-windows-x86_64.zip.sha256'
)

Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

public sealed class AOOfficePoolTransaction : IDisposable {
  private const uint GENERIC_READ = 0x80000000;
  private const uint GENERIC_WRITE = 0x40000000;
  private const uint FILE_SHARE_READ = 1;
  private const uint CREATE_NEW = 1;
  private const uint FILE_ATTRIBUTE_NORMAL = 0x80;
  private SafeFileHandle transaction;
  private bool complete;

  [DllImport("KtmW32.dll", SetLastError = true)]
  private static extern SafeFileHandle CreateTransaction(
    IntPtr attributes, IntPtr transactionId, uint options, uint isolationLevel,
    uint isolationFlags, uint timeout, string description);

  [DllImport("KtmW32.dll", SetLastError = true)]
  private static extern bool CommitTransaction(SafeFileHandle transaction);

  [DllImport("KtmW32.dll", SetLastError = true)]
  private static extern bool RollbackTransaction(SafeFileHandle transaction);

  [DllImport("Kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  private static extern bool CreateDirectoryTransactedW(
    string template, string path, IntPtr security, SafeFileHandle transaction);

  [DllImport("Kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  private static extern SafeFileHandle CreateFileTransactedW(
    string path, uint access, uint share, IntPtr security, uint creation,
    uint flags, IntPtr template, SafeFileHandle transaction, IntPtr miniVersion,
    IntPtr extendedParameter);

  [DllImport("Kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  private static extern bool GetVolumePathNameW(
    string path, StringBuilder volumePath, int length);

  [DllImport("Kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  private static extern bool GetVolumeInformationW(
    string root, StringBuilder name, int nameLength, out uint serial,
    out uint maximumComponentLength, out uint flags, StringBuilder fileSystem,
    int fileSystemLength);

  public static void RequireNtfs(string path) {
    StringBuilder root = new StringBuilder(260);
    if (!GetVolumePathNameW(path, root, root.Capacity)) {
      throw new Win32Exception(Marshal.GetLastWin32Error());
    }
    uint serial, maximumComponentLength, flags;
    StringBuilder fileSystem = new StringBuilder(32);
    if (!GetVolumeInformationW(
        root.ToString(), null, 0, out serial, out maximumComponentLength,
        out flags, fileSystem, fileSystem.Capacity)) {
      throw new Win32Exception(Marshal.GetLastWin32Error());
    }
    if (!String.Equals(fileSystem.ToString(), "NTFS", StringComparison.Ordinal)) {
      throw new InvalidOperationException("public acquisition requires local NTFS");
    }
  }

  public AOOfficePoolTransaction() {
    transaction = CreateTransaction(
      IntPtr.Zero, IntPtr.Zero, 0, 0, 0, 0, "AO office pool public acquisition");
    if (transaction.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
  }

  public void CreateDirectory(string path) {
    if (!CreateDirectoryTransactedW(null, path, IntPtr.Zero, transaction)) {
      throw new Win32Exception(Marshal.GetLastWin32Error());
    }
  }

  public FileStream CreateFile(string path) {
    SafeFileHandle handle = CreateFileTransactedW(
      path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, IntPtr.Zero,
      CREATE_NEW, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero, transaction,
      IntPtr.Zero, IntPtr.Zero);
    if (handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
    try { return new FileStream(handle, FileAccess.ReadWrite); }
    catch { handle.Dispose(); throw; }
  }

  public void Commit() {
    if (!CommitTransaction(transaction)) {
      throw new Win32Exception(Marshal.GetLastWin32Error());
    }
    complete = true;
  }

  public void Dispose() {
    if (transaction == null) return;
    if (!complete && !transaction.IsInvalid && !transaction.IsClosed) {
      RollbackTransaction(transaction);
    }
    transaction.Dispose();
    transaction = null;
  }
}
'@

function Assert-ExactFields {
  param([object]$Value, [string[]]$Names, [string]$Kind)
  if ($null -eq $Value -or $Value -isnot [pscustomobject]) { throw "$Kind is invalid" }
  $actual = @($Value.PSObject.Properties.Name)
  if ($actual.Count -ne $Names.Count) { throw "$Kind is invalid" }
  foreach ($name in $Names) {
    if ($actual -cnotcontains $name) { throw "$Kind is invalid" }
  }
}

function Assert-PathAncestry {
  param([object]$Path, [bool]$MustExist, [string]$Kind)
  if (
    $Path -isnot [string] -or [string]::IsNullOrWhiteSpace($Path) -or
    -not [IO.Path]::IsPathFullyQualified($Path) -or
    $Path.IndexOfAny([IO.Path]::GetInvalidPathChars()) -ge 0
  ) {
    throw "$Kind path is invalid"
  }
  $full = [IO.Path]::GetFullPath($Path)
  if ($MustExist -and -not (Test-Path -LiteralPath $full)) { throw "$Kind path is invalid" }
  $cursor = if (Test-Path -LiteralPath $full) { $full } else { Split-Path -Parent $full }
  if ([string]::IsNullOrEmpty($cursor) -or -not (Test-Path -LiteralPath $cursor)) {
    throw "$Kind parent is invalid"
  }
  while (-not [string]::IsNullOrEmpty($cursor)) {
    $item = Get-Item -LiteralPath $cursor -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
      throw "$Kind path is invalid"
    }
    $parent = Split-Path -Parent $cursor
    if ($parent -eq $cursor) { break }
    $cursor = $parent
  }
  return $full
}

function Assert-RegularSingleLinkFile {
  param([string]$Path, [string]$Kind)
  $item = Get-Item -LiteralPath $Path -Force
  if (
    $item.PSIsContainer -or
    ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
    $item.LinkType -ceq 'HardLink'
  ) {
    throw "$Kind is invalid"
  }
}

function Read-JsonFile {
  param([string]$Path, [string]$Kind)
  Assert-RegularSingleLinkFile $Path $Kind
  try {
    $text = [Text.UTF8Encoding]::new($false, $true).GetString([IO.File]::ReadAllBytes($Path))
    return $text | ConvertFrom-Json
  }
  catch { throw "$Kind is invalid" }
}

function Assert-Identity {
  param([object]$Value, [string]$Name, [string]$Kind)
  Assert-ExactFields $Value @('name', 'size', 'sha256') $Kind
  if (
    $Value.name -isnot [string] -or $Value.name -cne $Name -or
    $Value.size -is [bool] -or -not ($Value.size -is [int] -or $Value.size -is [long]) -or [long]$Value.size -lt 1 -or
    $Value.sha256 -isnot [string] -or $Value.sha256 -cnotmatch '^[0-9a-f]{64}$' -or $Value.sha256 -ceq ('0' * 64)
  ) { throw "$Kind is invalid" }
  return [pscustomobject][ordered]@{ name = $Name; size = [long]$Value.size; sha256 = [string]$Value.sha256 }
}

function Test-ExactString {
  param([object]$Value, [string]$Expected)
  return $Value -is [string] -and $Value -ceq $Expected
}

function Test-ExactBoolean {
  param([object]$Value, [bool]$Expected)
  return $Value -is [bool] -and $Value -eq $Expected
}

function Test-Integer {
  param([object]$Value)
  return $Value -isnot [bool] -and ($Value -is [int] -or $Value -is [long])
}

function Get-PublicFailureReason {
  param([string]$Message)
  switch -Regex ($Message) {
    '^contract ' { return @('contract-invalid', 'contract validation failed') }
    '^repository metadata ' { return @('repository-metadata-invalid', 'repository metadata validation failed') }
    '^release metadata ' { return @('release-metadata-invalid', 'release metadata validation failed') }
    '^release asset |^download URI ' { return @('release-assets-invalid', 'release asset set validation failed') }
    '^destination exists$' { return @('destination-exists', 'choose an absent destination') }
    '^asset |^sidecar |^transaction asset |^transaction identity ' {
      return @('asset-content-invalid', 'downloaded asset verification failed')
    }
    '^fixture ' { return @('fixture-invalid', 'fixture validation failed') }
    ' path is invalid$| parent is invalid$' { return @('path-invalid', 'path validation failed') }
    '^unsupported platform$|^PowerShell 7 is required$|^live acquisition requires Windows x64$' {
      return @('unsupported-platform', 'Windows local NTFS transaction support is required')
    }
    '^test mode |^test staging controls ' { return @('test-controls-invalid', 'test controls validation failed') }
    '^public metadata ' { return @('metadata-request-failed', 'public metadata acquisition failed') }
    '^public asset ' { return @('asset-request-failed', 'public asset acquisition failed') }
    default { return @('internal-error', 'acquisition failed safely') }
  }
}

function Read-PublicContract {
  param([string]$Path)
  $value = Read-JsonFile $Path 'contract'
  Assert-ExactFields $value @('schema_version', 'repository', 'visibility', 'tag', 'source_commit', 'architecture', 'assets') 'contract'
  if (
    -not (Test-Integer $value.schema_version) -or [long]$value.schema_version -ne 1 -or
    -not (Test-ExactString $value.repository $script:Repository) -or
    -not (Test-ExactString $value.visibility 'public') -or
    -not (Test-ExactString $value.tag $script:Tag) -or
    $value.source_commit -isnot [string] -or $value.source_commit -cnotmatch '^[0-9a-f]{40}$' -or $value.source_commit -ceq ('0' * 40) -or
    -not (Test-ExactString $value.architecture $script:Architecture)
  ) { throw 'contract identity is invalid' }
  if ($value.assets -isnot [object[]]) { throw 'contract asset set is invalid' }
  $assets = @($value.assets)
  if ($assets.Count -ne 2) { throw 'contract asset set is invalid' }
  $identities = for ($index = 0; $index -lt 2; $index++) {
    Assert-Identity $assets[$index] $script:AssetNames[$index] 'contract asset'
  }
  return [pscustomobject]@{ Value = $value; Identities = @($identities) }
}

function Assert-DownloadUri {
  param([object]$Value, [string]$Name, [bool]$RequireGitHubPath)
  if ($Value -isnot [string] -or [string]::IsNullOrEmpty($Value)) { throw 'download URI is invalid' }
  try { $uri = [Uri]$Value } catch { throw 'download URI is invalid' }
  if (
    -not $uri.IsAbsoluteUri -or $uri.Scheme -cne 'https' -or -not $uri.IsDefaultPort -or
    -not [string]::IsNullOrEmpty($uri.UserInfo) -or
    @('github.com', 'objects.githubusercontent.com', 'release-assets.githubusercontent.com') -cnotcontains $uri.Host -or
    -not $uri.AbsolutePath.EndsWith('/' + $Name, [StringComparison]::Ordinal)
  ) { throw 'download URI is invalid' }
  if ($RequireGitHubPath) {
    $expected = '/' + $script:Repository + '/releases/download/' + $script:Tag + '/' + $Name
    if ($uri.Host -cne 'github.com' -or $uri.AbsolutePath -cne $expected) {
      throw 'download URI is invalid'
    }
  }
  return $uri
}

function Assert-PublicMetadata {
  param([object]$RepositoryValue, [object]$ReleaseValue, [object[]]$Identities)
  if ($null -eq $RepositoryValue -or $RepositoryValue -isnot [pscustomobject]) {
    throw 'repository metadata is invalid'
  }
  $repositoryFields = @($RepositoryValue.PSObject.Properties | ForEach-Object { $_.Name })
  if (
    $repositoryFields -cnotcontains 'full_name' -or
    $repositoryFields -cnotcontains 'private' -or
    $repositoryFields -cnotcontains 'visibility' -or
    -not (Test-ExactString $RepositoryValue.full_name $script:Repository) -or
    -not (Test-ExactBoolean $RepositoryValue.private $false) -or
    -not (Test-ExactString $RepositoryValue.visibility 'public')
  ) { throw 'repository metadata is invalid' }
  if ($null -eq $ReleaseValue -or $ReleaseValue -isnot [pscustomobject]) {
    throw 'release metadata is invalid'
  }
  $releaseFields = @($ReleaseValue.PSObject.Properties | ForEach-Object { $_.Name })
  if (
    $releaseFields -cnotcontains 'tag_name' -or
    $releaseFields -cnotcontains 'draft' -or
    $releaseFields -cnotcontains 'prerelease' -or
    -not (Test-ExactString $ReleaseValue.tag_name $script:Tag) -or
    -not (Test-ExactBoolean $ReleaseValue.draft $false) -or
    -not (Test-ExactBoolean $ReleaseValue.prerelease $false)
  ) { throw 'release metadata is invalid' }
  if ($releaseFields -cnotcontains 'assets') { throw 'release asset set is invalid' }
  if ($ReleaseValue.assets -isnot [object[]]) { throw 'release asset set is invalid' }
  $assets = @($ReleaseValue.assets)
  if ($assets.Count -ne 2) { throw 'release asset set is invalid' }
  $byName = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
  foreach ($asset in $assets) {
    if ($null -eq $asset -or $asset -isnot [pscustomobject]) {
      throw 'release asset set is invalid'
    }
    $assetFields = @($asset.PSObject.Properties | ForEach-Object { $_.Name })
    if (
      $assetFields -cnotcontains 'name' -or
      $assetFields -cnotcontains 'size' -or
      $assetFields -cnotcontains 'browser_download_url' -or
      $asset.name -isnot [string] -or
      $asset.size -is [bool] -or -not (Test-Integer $asset.size) -or
      $asset.browser_download_url -isnot [string] -or [string]::IsNullOrEmpty($asset.browser_download_url)
    ) { throw 'release asset set is invalid' }
    $matchingIdentities = @($Identities | Where-Object { $_.name -ceq $asset.name })
    if (
      $matchingIdentities.Count -ne 1 -or
      $byName.ContainsKey($asset.name)
    ) { throw 'release asset set is invalid' }
    $identity = $matchingIdentities[0]
    if (
      [long]$asset.size -ne $identity.size
    ) { throw 'release asset set is invalid' }
    [void](Assert-DownloadUri $asset.browser_download_url $identity.name $true)
    $byName.Add($asset.name, $asset)
  }
  return @($Identities | ForEach-Object { $byName[$_.name] })
}

function Write-VerifiedStream {
  param([IO.Stream]$InputStream, [IO.Stream]$OutputStream, [object]$Identity)
  $hash = [Security.Cryptography.SHA256]::Create()
  try {
    $buffer = [byte[]]::new(1048576)
    [long]$count = 0
    while (($read = $InputStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
      if ($count + $read -gt $Identity.size) { throw 'asset identity mismatch' }
      $OutputStream.Write($buffer, 0, $read)
      [void]$hash.TransformBlock($buffer, 0, $read, $buffer, 0)
      $count += $read
    }
    [void]$hash.TransformFinalBlock([byte[]]::new(0), 0, 0)
    $digest = ([Convert]::ToHexString($hash.Hash)).ToLowerInvariant()
    if ($count -ne $Identity.size -or $digest -cne $Identity.sha256) { throw 'asset identity mismatch' }
    $OutputStream.Flush()
    $OutputStream.Position = 0
  }
  finally {
    $hash.Dispose()
  }
}

function Assert-VerifiedStream {
  param([IO.Stream]$InputStream, [object]$Identity)
  $hash = [Security.Cryptography.SHA256]::Create()
  try {
    $InputStream.Position = 0
    $buffer = [byte[]]::new(1048576)
    [long]$count = 0
    while (($read = $InputStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
      if ($count + $read -gt $Identity.size) { throw 'asset identity mismatch' }
      [void]$hash.TransformBlock($buffer, 0, $read, $buffer, 0)
      $count += $read
    }
    [void]$hash.TransformFinalBlock([byte[]]::new(0), 0, 0)
    $digest = ([Convert]::ToHexString($hash.Hash)).ToLowerInvariant()
    if ($count -ne $Identity.size -or $digest -cne $Identity.sha256) {
      throw 'asset identity mismatch'
    }
    $InputStream.Position = 0
  }
  finally {
    $hash.Dispose()
  }
}

function Assert-TransactionClosure {
  param([IO.Stream[]]$Streams, [object[]]$Identities, [int]$EntryCount)
  if ($EntryCount -ne 2 -or $Streams.Count -ne 2) { throw 'asset set is invalid' }
  for ($index = 0; $index -lt 2; $index++) {
    Assert-VerifiedStream $Streams[$index] $Identities[$index]
  }
  $expectedSidecar = [Text.Encoding]::ASCII.GetBytes($Identities[0].sha256 + '  ' + $script:AssetNames[0] + "`n")
  $Streams[1].Position = 0
  $actualSidecar = [byte[]]::new($Identities[1].size)
  $read = $Streams[1].Read($actualSidecar, 0, $actualSidecar.Length)
  if ([Convert]::ToBase64String($actualSidecar) -cne [Convert]::ToBase64String($expectedSidecar)) {
    throw 'sidecar content is invalid'
  }
  $Streams[1].Position = 0
}

function Copy-FixtureAsset {
  param([object]$Download, [IO.Stream]$DestinationStream, [object]$Identity)
  Assert-ExactFields $Download @('name', 'source_path', 'final_url') 'fixture download'
  if (
    -not (Test-ExactString $Download.name $Identity.name) -or
    $Download.source_path -isnot [string] -or [string]::IsNullOrEmpty($Download.source_path) -or
    $Download.final_url -isnot [string] -or [string]::IsNullOrEmpty($Download.final_url)
  ) {
    throw 'fixture download is invalid'
  }
  [void](Assert-DownloadUri $Download.final_url $Identity.name $false)
  $source = Assert-PathAncestry $Download.source_path $true 'fixture asset'
  Assert-RegularSingleLinkFile $source 'fixture asset'
  $input = [IO.File]::Open($source, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
  try { Write-VerifiedStream $input $DestinationStream $Identity } finally { $input.Dispose() }
}

function New-PublicHttpClient {
  $handler = [Net.Http.HttpClientHandler]::new()
  $handler.AllowAutoRedirect = $true
  return [Net.Http.HttpClient]::new($handler, $true)
}

function Invoke-PublicJson {
  param([Net.Http.HttpClient]$Client, [string]$Uri)
  $request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Get, $Uri)
  $request.Headers.Accept.ParseAdd('application/vnd.github+json')
  $request.Headers.UserAgent.ParseAdd('ao-office-pool-public-acquisition/1')
  $request.Headers.Add('X-GitHub-Api-Version', '2022-11-28')
  try {
    $response = $Client.SendAsync($request).GetAwaiter().GetResult()
    try {
      if (-not $response.IsSuccessStatusCode) { throw 'public metadata request failed' }
      $bytes = $response.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult()
      try {
        return [Text.UTF8Encoding]::new($false, $true).GetString($bytes) | ConvertFrom-Json
      }
      catch { throw 'public metadata response is invalid' }
    }
    finally { $response.Dispose() }
  }
  finally { $request.Dispose() }
}

function Invoke-PublicAsset {
  param([Net.Http.HttpClient]$Client, [Uri]$Uri, [IO.Stream]$DestinationStream, [object]$Identity)
  $request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Get, $Uri)
  try {
    $response = $Client.SendAsync($request, [Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
    try {
      if (-not $response.IsSuccessStatusCode -or $null -eq $response.RequestMessage -or $null -eq $response.RequestMessage.RequestUri) {
        throw 'public asset request failed'
      }
      [void](Assert-DownloadUri $response.RequestMessage.RequestUri.AbsoluteUri $Identity.name $false)
      $input = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
      try { Write-VerifiedStream $input $DestinationStream $Identity } finally { $input.Dispose() }
    }
    finally { $response.Dispose() }
  }
  finally { $request.Dispose() }
}

function Invoke-PublicAcquisition {
  if ($PSVersionTable.PSVersion.Major -lt 7) { throw 'PowerShell 7 is required' }
  $testModeValue = [Environment]::GetEnvironmentVariable('AO_OFFICE_POOL_TEST_MODE')
  $fixtureValue = [Environment]::GetEnvironmentVariable('AO_OFFICE_POOL_PUBLIC_RELEASE_FIXTURE')
  $testHookValue = [Environment]::GetEnvironmentVariable('AO_OFFICE_POOL_PUBLIC_RELEASE_TEST_HOOK')
  $testStagingName = [Environment]::GetEnvironmentVariable('AO_OFFICE_POOL_PUBLIC_RELEASE_TEST_STAGING_NAME')
  if (-not [string]::IsNullOrEmpty($testModeValue) -and $testModeValue -cne '1') { throw 'test mode is invalid' }
  if (-not [string]::IsNullOrEmpty($fixtureValue) -and $testModeValue -cne '1') { throw 'fixture mode is invalid' }
  if ($testModeValue -ceq '1' -and [string]::IsNullOrEmpty($fixtureValue)) { throw 'fixture mode is invalid' }
  if (
    $testModeValue -cne '1' -and
    (-not [string]::IsNullOrEmpty($testHookValue) -or -not [string]::IsNullOrEmpty($testStagingName))
  ) { throw 'test staging controls are invalid' }
  if ($testModeValue -ceq '1') {
    if (
      -not [string]::IsNullOrEmpty($testHookValue) -and
      @(
        'collision', 'extra-file', 'subdirectory', 'reparse', 'replace-file', 'replace-directory',
        'replace-between-create-and-lease', 'replace-between-validation-and-publish',
        'inject-between-validation-and-publish', 'replace-between-cleanup-check-and-delete'
      ) -cnotcontains $testHookValue
    ) { throw 'test staging controls are invalid' }
    if (
      -not [string]::IsNullOrEmpty($testStagingName) -and
      $testStagingName -cnotmatch '^\.ao-office-pool-public-staging-[0-9a-f]{32}$'
    ) { throw 'test staging controls are invalid' }
    if (-not [string]::IsNullOrEmpty($testHookValue) -and [string]::IsNullOrEmpty($testStagingName)) {
      throw 'test staging controls are invalid'
    }
  }

  $contractPath = Assert-PathAncestry $Contract $true 'contract'
  $destinationPath = Assert-PathAncestry $Destination $false 'destination'
  if (Test-Path -LiteralPath $destinationPath) { throw 'destination exists' }
  $destinationParent = Split-Path -Parent $destinationPath
  if (-not (Get-Item -LiteralPath $destinationParent -Force).PSIsContainer) { throw 'destination parent is invalid' }
  $contractValue = Read-PublicContract $contractPath

  $fixture = $null
  $client = $null
  if ($testModeValue -ceq '1') {
    $fixturePath = Assert-PathAncestry $fixtureValue $true 'fixture'
    $fixture = Read-JsonFile $fixturePath 'fixture'
    Assert-ExactFields $fixture @('repository', 'release', 'downloads') 'fixture'
    $assets = Assert-PublicMetadata $fixture.repository $fixture.release $contractValue.Identities
    if ($fixture.downloads -isnot [object[]]) { throw 'fixture download set is invalid' }
    $downloads = @($fixture.downloads)
    if ($downloads.Count -ne 2) { throw 'fixture download set is invalid' }
  }
  else {
    if ($env:OS -cne 'Windows_NT' -or -not [Environment]::Is64BitOperatingSystem -or -not [Environment]::Is64BitProcess) {
      throw 'live acquisition requires Windows x64'
    }
    $client = New-PublicHttpClient
    $apiRoot = 'https://api.github.com/repos/' + $script:Repository
    $repositoryMetadata = Invoke-PublicJson $client $apiRoot
    $releaseMetadata = Invoke-PublicJson $client ($apiRoot + '/releases/tags/' + $script:Tag)
    $assets = Assert-PublicMetadata $repositoryMetadata $releaseMetadata $contractValue.Identities
  }

  $hookBase = if ([string]::IsNullOrEmpty($testStagingName)) {
    Join-Path $destinationParent ('.ao-office-pool-public-staging-' + [Convert]::ToHexString(
      [Security.Cryptography.RandomNumberGenerator]::GetBytes(16)
    ).ToLowerInvariant())
  }
  else { Join-Path $destinationParent $testStagingName }
  if ($testHookValue -ceq 'collision' -and (Test-Path -LiteralPath $hookBase)) {
    throw 'staging directory creation failed'
  }

  $transaction = $null
  try {
    [AOOfficePoolTransaction]::RequireNtfs($destinationParent)
    $transaction = [AOOfficePoolTransaction]::new()
  }
  catch { throw 'unsupported platform' }
  $streams = [Collections.Generic.List[IO.Stream]]::new()
  try {
    $transaction.CreateDirectory($destinationPath)
    if ($testHookValue -ceq 'replace-between-create-and-lease') {
      [IO.File]::WriteAllText(($hookBase + '.hook-observed'), '1')
      [void][IO.Directory]::CreateDirectory($destinationPath)
      [IO.File]::WriteAllText((Join-Path $destinationPath 'replacement.txt'), 'keep')
    }
    for ($index = 0; $index -lt 2; $index++) {
      $identity = $contractValue.Identities[$index]
      $target = Join-Path $destinationPath $identity.name
      $output = $transaction.CreateFile($target)
      $streams.Add($output)
      if ($null -ne $fixture) {
        Copy-FixtureAsset $downloads[$index] $output $identity
      }
      else {
        Invoke-PublicAsset $client ([Uri]$assets[$index].browser_download_url) $output $identity
      }
    }
    $entryCount = 2
    if ($testModeValue -ceq '1') {
      switch ($testHookValue) {
        'extra-file' {
          $extra = $transaction.CreateFile((Join-Path $destinationPath 'extra.txt'))
          try { $extra.WriteByte(1); $extra.Flush() } finally { $extra.Dispose() }
          $entryCount++
        }
        'subdirectory' {
          $transaction.CreateDirectory((Join-Path $destinationPath 'extra-directory'))
          $entryCount++
        }
        'reparse' {
          throw 'transaction asset set is invalid'
        }
      }
    }
    Assert-TransactionClosure $streams.ToArray() $contractValue.Identities $entryCount
    if ($testModeValue -ceq '1') {
      switch ($testHookValue) {
        'replace-file' {
          $streams[0].SetLength(0)
          $streams[0].Write([Text.Encoding]::ASCII.GetBytes('drift'))
          $streams[0].Flush()
        }
        'replace-directory' {
          [void][IO.Directory]::CreateDirectory(($hookBase + '.displaced'))
          [void][IO.Directory]::CreateDirectory($hookBase)
          [IO.File]::WriteAllText((Join-Path $hookBase 'replacement.txt'), 'keep')
          throw 'transaction identity changed'
        }
      }
    }
    Assert-TransactionClosure $streams.ToArray() $contractValue.Identities $entryCount
    if ($testHookValue -ceq 'replace-between-validation-and-publish') {
      [IO.File]::WriteAllText(($hookBase + '.hook-observed'), '1')
      [void][IO.Directory]::CreateDirectory($destinationPath)
      [IO.File]::WriteAllText((Join-Path $destinationPath 'replacement.txt'), 'keep')
    }
    if ($testHookValue -ceq 'inject-between-validation-and-publish') {
      [IO.File]::WriteAllText(($hookBase + '.hook-observed'), '1')
      [void][IO.Directory]::CreateDirectory($destinationPath)
      [IO.File]::WriteAllText((Join-Path $destinationPath 'injected.txt'), 'keep')
    }
    foreach ($stream in $streams) { $stream.Dispose() }
    $streams.Clear()
    $transaction.Commit()
    $transaction.Dispose()
    $transaction = $null
  }
  finally {
    if ($null -ne $client) { $client.Dispose() }
    foreach ($stream in $streams) { $stream.Dispose() }
    $streams.Clear()
    if ($null -ne $transaction) {
      if ($testHookValue -ceq 'replace-between-cleanup-check-and-delete') {
        [IO.File]::WriteAllText(($hookBase + '.hook-observed'), '1')
        if (-not (Test-Path -LiteralPath $destinationPath)) {
          [void][IO.Directory]::CreateDirectory($destinationPath)
          [IO.File]::WriteAllText((Join-Path $destinationPath 'replacement.txt'), 'keep')
          [IO.File]::WriteAllText(($hookBase + '.replacement-created'), '1')
        }
      }
      $transaction.Dispose()
    }
  }

  [ordered]@{
    mode = 'public'
    repository = $script:Repository
    tag = $script:Tag
    architecture = $script:Architecture
    destination = Split-Path -Leaf $destinationPath
    assets = @($contractValue.Identities | ForEach-Object {
      [ordered]@{ name = $_.name; size = $_.size; sha256 = $_.sha256 }
    })
  } | ConvertTo-Json -Depth 4 -Compress
}

try { Invoke-PublicAcquisition }
catch {
  $reason = Get-PublicFailureReason $_.Exception.Message
  [Console]::Error.WriteLine(
    'AO office pool public acquisition failed [' + $reason[0] + ']: ' + $reason[1]
  )
  exit 1
}
