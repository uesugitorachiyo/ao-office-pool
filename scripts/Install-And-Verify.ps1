[CmdletBinding()]
param(
  [string]$InstallRoot = (Join-Path $env:LOCALAPPDATA '.ao-office-pool-private\AOOfficePool'),
  [string]$DownloadRoot = (Join-Path $env:LOCALAPPDATA '.ao-office-pool-private\downloads-v0.1.1')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ArchiveName = 'ao-office-pool-v0.1.1-windows-x86_64.zip'
$SidecarName = "$ArchiveName.sha256"
$ExpectedOffices = @('O1', 'O2', 'O3', 'O4', 'O5')
$receipt = $null
$claim = $null
$resume = $null
$claimSucceeded = $false
$releaseSucceeded = $false
$terminalFree = $false
$postReleaseStatusChecked = $false
$claimedOffice = $null
$extractRoot = $null
$projectRoot = $null
$downloadRun = $null
$installContainer = $null
$installStage = $null
$archiveLease = $null
$sidecarLease = $null
$contractLease = $null
$privateAnchorLease = $null
$downloadBaseLease = $null
$downloadRunLease = $null
$installerLease = $null
$verifierLease = $null
$launcherLease = $null
$extractRootLease = $null
$installStageLease = $null
$installContainerLease = $null
$projectRootLease = $null
$memberLeases = @()
$installedMemberLeases = @()
$failureCode = 'internal-error'

Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public sealed class AOIVDirectoryLease : IDisposable {
  const uint GENERIC_READ = 0x80000000;
  const uint DELETE = 0x00010000;
  const uint FILE_SHARE_READ = 1;
  const uint FILE_SHARE_WRITE = 2;
  const uint FILE_SHARE_DELETE = 4;
  const uint OPEN_EXISTING = 3;
  const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
  SafeFileHandle handle;
  readonly ulong volume;
  readonly ulong index;

  [StructLayout(LayoutKind.Sequential)] struct BY_HANDLE_FILE_INFORMATION {
    public uint attributes; public System.Runtime.InteropServices.ComTypes.FILETIME creation;
    public System.Runtime.InteropServices.ComTypes.FILETIME access;
    public System.Runtime.InteropServices.ComTypes.FILETIME write; public uint volume;
    public uint sizeHigh; public uint sizeLow; public uint links;
    public uint indexHigh; public uint indexLow;
  }
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  static extern SafeFileHandle CreateFileW(string path, uint access, uint share,
    IntPtr security, uint creation, uint flags, IntPtr template);
  [StructLayout(LayoutKind.Sequential)] struct SECURITY_ATTRIBUTES {
    public int length; public IntPtr descriptor; public bool inherit;
  }
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(
    string value, uint revision, out IntPtr descriptor, out uint size);
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  static extern bool CreateDirectoryW(string path, ref SECURITY_ATTRIBUTES security);
  [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr memory);
  [DllImport("kernel32.dll", SetLastError=true)]
  static extern bool GetFileInformationByHandle(SafeFileHandle file, out BY_HANDLE_FILE_INFORMATION info);

  static SafeFileHandle Open(string path, uint access, uint share) {
    var h = CreateFileW(path, access, share,
      IntPtr.Zero, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, IntPtr.Zero);
    if (h.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
    return h;
  }
  static void Identity(SafeFileHandle h, out ulong volume, out ulong index) {
    BY_HANDLE_FILE_INFORMATION i;
    if (!GetFileInformationByHandle(h, out i)) throw new Win32Exception(Marshal.GetLastWin32Error());
    volume = i.volume; index = ((ulong)i.indexHigh << 32) | i.indexLow;
  }
  public static void ValidateRegularSingleLink(SafeFileHandle file) {
    BY_HANDLE_FILE_INFORMATION i;
    if (!GetFileInformationByHandle(file, out i)) throw new Win32Exception(Marshal.GetLastWin32Error());
    if ((i.attributes & 0x10) != 0 || (i.attributes & 0x400) != 0 || i.links != 1)
      throw new IOException("file is not a regular single-link file");
  }
  public static bool IsSameFile(SafeFileHandle file, string path) {
    try {
      ulong volume, index; Identity(file, out volume, out index);
      using (var current = Open(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)) {
        ulong v, i; Identity(current, out v, out i); return v == volume && i == index;
      }
    } catch { return false; }
  }
  public AOIVDirectoryLease(string path) {
    handle = Open(path, GENERIC_READ | DELETE, FILE_SHARE_READ | FILE_SHARE_WRITE); Identity(handle, out volume, out index);
  }
  public static AOIVDirectoryLease CreatePrivate(string path, string ownerSid) {
    IntPtr descriptor = IntPtr.Zero;
    string sddl = "O:" + ownerSid + "G:" + ownerSid +
      "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + ownerSid + ")";
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, out descriptor, out _))
      throw new Win32Exception(Marshal.GetLastWin32Error());
    try {
      SECURITY_ATTRIBUTES security = new SECURITY_ATTRIBUTES {
        length = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES)), descriptor = descriptor, inherit = false
      };
      if (!CreateDirectoryW(path, ref security)) throw new Win32Exception(Marshal.GetLastWin32Error());
      return new AOIVDirectoryLease(path);
    } finally { if (descriptor != IntPtr.Zero) LocalFree(descriptor); }
  }
  public bool IsSamePath(string path) {
    try {
      using (var current = Open(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)) {
        ulong v, i; Identity(current, out v, out i); return v == volume && i == index;
      }
    } catch { return false; }
  }
  [DllImport("kernel32.dll", SetLastError=true)]
  static extern bool SetFileInformationByHandle(SafeFileHandle file, int infoClass, IntPtr info, uint size);
  public void RenameTo(string destination) {
    byte[] name = System.Text.Encoding.Unicode.GetBytes(destination);
    int rootOffset = IntPtr.Size == 8 ? 8 : 4;
    int lengthOffset = IntPtr.Size == 8 ? 16 : 8;
    int nameOffset = IntPtr.Size == 8 ? 20 : 12;
    IntPtr buffer = Marshal.AllocHGlobal(nameOffset + name.Length + 2);
    try {
      for (int n = 0; n < nameOffset + name.Length + 2; n++) Marshal.WriteByte(buffer, n, 0);
      Marshal.WriteIntPtr(buffer, rootOffset, IntPtr.Zero);
      Marshal.WriteInt32(buffer, lengthOffset, name.Length);
      Marshal.Copy(name, 0, IntPtr.Add(buffer, nameOffset), name.Length);
      if (!SetFileInformationByHandle(handle, 3, buffer, (uint)(nameOffset + name.Length + 2)))
        throw new Win32Exception(Marshal.GetLastWin32Error());
    } finally { Marshal.FreeHGlobal(buffer); }
  }
  public void DeleteOnClose() {
    IntPtr buffer = Marshal.AllocHGlobal(1);
    try {
      Marshal.WriteByte(buffer, 0, 1);
      if (!SetFileInformationByHandle(handle, 4, buffer, 1))
        throw new Win32Exception(Marshal.GetLastWin32Error());
    } finally { Marshal.FreeHGlobal(buffer); }
  }
  public void Dispose() { if (handle != null) { handle.Dispose(); handle = null; } }
}
'@

function Get-CurrentUserSid {
  return [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
}

function Assert-PrivateDirectoryAcl {
  param([string]$Path, [bool]$RequireProtected = $true)
  $acl = Get-Acl -LiteralPath $Path
  $currentSid = Get-CurrentUserSid
  $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
  if ($owner -cne $currentSid -or ($RequireProtected -and -not $acl.AreAccessRulesProtected)) {
    throw 'private directory ownership differs'
  }
  $trusted = @($currentSid, 'S-1-5-18', 'S-1-5-32-544')
  $currentFull = $false
  foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
    if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { continue }
    $sid = $rule.IdentityReference.Value
    if ($trusted -cnotcontains $sid) { throw 'private directory grants an untrusted principal' }
    if ($sid -ceq $currentSid -and
        (($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -eq
         [Security.AccessControl.FileSystemRights]::FullControl)) { $currentFull = $true }
  }
  if (-not $currentFull) { throw 'private directory lacks owner control' }
}

function Assert-PrivateTreeAcl {
  param([string]$Root, [bool]$RequireProtectedRoot = $true)
  Assert-PrivateDirectoryAcl $Root $RequireProtectedRoot
  $currentSid = Get-CurrentUserSid
  $trusted = @($currentSid, 'S-1-5-18', 'S-1-5-32-544')
  foreach ($item in Get-ChildItem -LiteralPath $Root -Force -Recurse) {
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'private tree contains a reparse point' }
    $acl = Get-Acl -LiteralPath $item.FullName
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne $currentSid) { throw 'private tree owner differs' }
    foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
      if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
          $trusted -cnotcontains $rule.IdentityReference.Value) { throw 'private tree grants an untrusted principal' }
    }
  }
}

function New-PrivateDirectoryLease {
  param([string]$Path)
  $lease = [AOIVDirectoryLease]::CreatePrivate($Path, (Get-CurrentUserSid))
  try {
    if (-not $lease.IsSamePath($Path)) { throw 'private directory identity differs' }
    Assert-PrivateDirectoryAcl $Path $true
    return $lease
  }
  catch { $lease.Dispose(); throw }
}

function Protect-PrivateDirectoryRoot {
  param([string]$Path, [AOIVDirectoryLease]$Lease)
  if (-not $Lease.IsSamePath($Path)) { throw 'private directory identity differs' }
  $acl = Get-Acl -LiteralPath $Path
  $acl.SetAccessRuleProtection($true, $true)
  Set-Acl -LiteralPath $Path -AclObject $acl
  if (-not $Lease.IsSamePath($Path)) { throw 'private directory identity differs' }
  Assert-PrivateTreeAcl $Path $true
}

function Assert-DirectPrivateChildPath {
  param([string]$Path, [string]$Anchor, [string]$Kind)
  $full = [IO.Path]::GetFullPath($Path).TrimEnd('\')
  if ([IO.Path]::GetDirectoryName($full).TrimEnd('\') -cne $Anchor.TrimEnd('\')) {
    throw "$Kind must be a direct child of the private application root"
  }
  return $full
}

function Assert-SafeNewNtfsRoot {
  param([string]$Path, [string]$Kind)
  if ([string]::IsNullOrWhiteSpace($Path) -or
      -not [System.IO.Path]::IsPathFullyQualified($Path) -or
      $Path -notmatch '^[A-Za-z]:\\') {
    throw "$Kind must be a drive-absolute local path"
  }
  $full = [System.IO.Path]::GetFullPath($Path).TrimEnd('\')
  $drive = [System.IO.Path]::GetPathRoot($full)
  if ($full -ceq $drive.TrimEnd('\') -or $full.Length -gt 120) {
    throw "$Kind exceeds the safe path budget"
  }
  if (Test-Path -LiteralPath $full) {
    throw "$Kind already exists"
  }
  $cursor = [System.IO.Path]::GetDirectoryName($full)
  while (-not (Test-Path -LiteralPath $cursor -PathType Container)) {
    $parent = [System.IO.Path]::GetDirectoryName($cursor)
    if ([string]::IsNullOrEmpty($parent) -or $parent -ceq $cursor) {
      throw "$Kind has no existing parent"
    }
    $cursor = $parent
  }
  while (-not [string]::IsNullOrEmpty($cursor)) {
    $item = Get-Item -LiteralPath $cursor -Force
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
      throw "$Kind contains a reparse-point ancestor"
    }
    if ($cursor.TrimEnd('\') -ceq $drive.TrimEnd('\')) { break }
    $cursor = [System.IO.Path]::GetDirectoryName($cursor)
  }
  $information = [System.IO.DriveInfo]::new($drive)
  if (-not $information.IsReady -or
      $information.DriveType -ne [System.IO.DriveType]::Fixed -or
      $information.DriveFormat -cne 'NTFS') {
    throw "$Kind must be on fixed local NTFS"
  }
  return $full
}

function Assert-SafeNtfsBase {
  param([string]$Path, [string]$Kind, [switch]$NoCreate)
  if ([string]::IsNullOrWhiteSpace($Path) -or
      -not [IO.Path]::IsPathFullyQualified($Path) -or
      $Path -notmatch '^[A-Za-z]:\\') {
    throw "$Kind must be a drive-absolute local path"
  }
  $full = [IO.Path]::GetFullPath($Path).TrimEnd('\')
  $drive = [IO.Path]::GetPathRoot($full)
  if ($full -ceq $drive.TrimEnd('\') -or $full.Length -gt 120) { throw "$Kind exceeds the safe path budget" }
  $cursor = if (Test-Path -LiteralPath $full) { $full } else { [IO.Path]::GetDirectoryName($full) }
  while (-not (Test-Path -LiteralPath $cursor -PathType Container)) {
    $parent = [IO.Path]::GetDirectoryName($cursor)
    if ([string]::IsNullOrEmpty($parent) -or $parent -ceq $cursor) { throw "$Kind has no existing parent" }
    $cursor = $parent
  }
  while (-not [string]::IsNullOrEmpty($cursor)) {
    $item = Get-Item -LiteralPath $cursor -Force
    if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
      throw "$Kind contains an invalid ancestor"
    }
    if ($cursor.TrimEnd('\') -ceq $drive.TrimEnd('\')) { break }
    $cursor = [IO.Path]::GetDirectoryName($cursor)
  }
  $information = [IO.DriveInfo]::new($drive)
  if (-not $information.IsReady -or $information.DriveType -ne [IO.DriveType]::Fixed -or
      $information.DriveFormat -cne 'NTFS') { throw "$Kind must be on fixed local NTFS" }
  if (Test-Path -LiteralPath $full) {
    if (-not (Test-Path -LiteralPath $full -PathType Container)) { throw "$Kind is not a directory" }
  }
  elseif (-not $NoCreate) { [void][IO.Directory]::CreateDirectory($full) }
  return $full
}

function Assert-RegularSingleLinkFile {
  param([string]$Path, [string]$Kind)
  $item = Get-Item -LiteralPath $Path -Force
  if ($item.PSIsContainer -or
      ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
      ($item.PSObject.Properties.Match('LinkType').Count -eq 1 -and
       [string]$item.LinkType -ceq 'HardLink')) {
    throw "$Kind must be a regular single-link file"
  }
  return $item
}

function Read-ExactStreamBytes {
  param([IO.Stream]$Stream, [long]$Maximum, [string]$Kind)
  if ($Stream.Length -lt 1 -or $Stream.Length -gt $Maximum) { throw "$Kind is invalid" }
  $bytes = [byte[]]::new($Stream.Length)
  $offset = 0
  $Stream.Position = 0
  while ($offset -lt $bytes.Length) {
    $count = $Stream.Read($bytes, $offset, $bytes.Length - $offset)
    if ($count -le 0) { throw "$Kind is invalid" }
    $offset += $count
  }
  $Stream.Position = 0
  return $bytes
}

function Assert-ExactJsonFields {
  param([object]$Value, [string[]]$Names, [string]$Kind)
  if ($null -eq $Value -or $Value -isnot [pscustomobject]) { throw "$Kind is invalid" }
  $actual = @($Value.PSObject.Properties.Name)
  if ($actual.Count -ne $Names.Count) { throw "$Kind is invalid" }
  foreach ($name in $Names) { if ($actual -cnotcontains $name) { throw "$Kind is invalid" } }
}

function Test-ExactJsonInteger {
  param([object]$Value)
  return $Value -isnot [bool] -and ($Value -is [int] -or $Value -is [long])
}

function Read-TrustedPublicContract {
  param([string]$Path)
  $full = [IO.Path]::GetFullPath($Path)
  $expected = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\manifests\public-release.json'))
  if ($full -cne $expected) { throw 'public contract path differs' }
  $cursor = [IO.Path]::GetDirectoryName($full)
  $drive = [IO.Path]::GetPathRoot($full)
  while (-not [string]::IsNullOrEmpty($cursor)) {
    $item = Get-Item -LiteralPath $cursor -Force
    if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
      throw 'public contract ancestry is invalid'
    }
    if ($cursor.TrimEnd('\') -ceq $drive.TrimEnd('\')) { break }
    $cursor = [IO.Path]::GetDirectoryName($cursor)
  }
  $stream = [IO.FileStream]::new($full, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
  try {
    [AOIVDirectoryLease]::ValidateRegularSingleLink($stream.SafeFileHandle)
    if (-not [AOIVDirectoryLease]::IsSameFile($stream.SafeFileHandle, $full)) { throw 'public contract identity differs' }
    try { $contract = ([Text.UTF8Encoding]::new($false, $true).GetString((Read-ExactStreamBytes $stream 1048576 'public contract')) | ConvertFrom-Json) }
    catch { throw 'public contract is invalid' }
    Assert-ExactJsonFields $contract @('schema_version','repository','visibility','tag','source_commit','architecture','assets') 'public contract'
    if (-not (Test-ExactJsonInteger $contract.schema_version) -or [long]$contract.schema_version -ne 1 -or
        $contract.repository -isnot [string] -or $contract.repository -cne 'uesugitorachiyo/ao-office-pool' -or
        $contract.visibility -isnot [string] -or $contract.visibility -cne 'public' -or
        $contract.tag -isnot [string] -or $contract.tag -cne 'v0.1.1' -or
        $contract.source_commit -isnot [string] -or $contract.source_commit -cnotmatch '^[0-9a-f]{40}$' -or
        $contract.source_commit -ceq ('0' * 40) -or
        $contract.architecture -isnot [string] -or $contract.architecture -cne 'windows-x86_64' -or
        $contract.assets -isnot [System.Array] -or $contract.assets.Count -ne 2) {
      throw 'public contract is invalid'
    }
    $names = @($ArchiveName, $SidecarName)
    $identities = for ($index = 0; $index -lt 2; $index++) {
      $asset = $contract.assets[$index]
      Assert-ExactJsonFields $asset @('name','size','sha256') 'public contract asset'
      if ($asset.name -isnot [string] -or $asset.name -cne $names[$index] -or
          -not (Test-ExactJsonInteger $asset.size) -or [long]$asset.size -lt 1 -or
          $asset.sha256 -isnot [string] -or $asset.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
          $asset.sha256 -ceq ('0' * 64)) { throw 'public contract asset is invalid' }
      [pscustomobject]@{ name = $asset.name; size = [long]$asset.size; sha256 = $asset.sha256 }
    }
    return [pscustomobject]@{ lease = $stream; identities = @($identities) }
  }
  catch { $stream.Dispose(); throw }
}

function Assert-ArchiveSidecar {
  param([string]$ArchivePath, [string]$SidecarPath, [object[]]$Identities)
  $stream = $null
  $sidecarStream = $null
  try {
    if ($Identities.Count -ne 2 -or [IO.Path]::GetFileName($ArchivePath) -cne $Identities[0].name -or
        [IO.Path]::GetFileName($SidecarPath) -cne $Identities[1].name) { throw 'release asset names differ' }
    $stream = [IO.FileStream]::new($ArchivePath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $sidecarStream = [IO.FileStream]::new($SidecarPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    [AOIVDirectoryLease]::ValidateRegularSingleLink($stream.SafeFileHandle)
    [AOIVDirectoryLease]::ValidateRegularSingleLink($sidecarStream.SafeFileHandle)
    if (-not [AOIVDirectoryLease]::IsSameFile($stream.SafeFileHandle, $ArchivePath) -or
        -not [AOIVDirectoryLease]::IsSameFile($sidecarStream.SafeFileHandle, $SidecarPath)) { throw 'release asset identity differs' }
    $archiveDigest = [Convert]::ToHexString([Security.Cryptography.SHA256]::Create().ComputeHash($stream)).ToLowerInvariant()
    $sidecarDigest = [Convert]::ToHexString([Security.Cryptography.SHA256]::Create().ComputeHash($sidecarStream)).ToLowerInvariant()
    if ($stream.Length -ne $Identities[0].size -or $archiveDigest -cne $Identities[0].sha256 -or
        $sidecarStream.Length -ne $Identities[1].size -or $sidecarDigest -cne $Identities[1].sha256) {
      throw 'release asset identity differs'
    }
    $sidecarStream.Position = 0
    $actualSidecar = Read-ExactStreamBytes $sidecarStream 4096 'checksum sidecar'
    $expectedLf = [Text.Encoding]::ASCII.GetBytes($Identities[0].sha256 + '  ' + $ArchiveName + "`n")
    $expectedCrLf = [Text.Encoding]::ASCII.GetBytes($Identities[0].sha256 + '  ' + $ArchiveName + "`r`n")
    $actualBase64 = [Convert]::ToBase64String($actualSidecar)
    if ($actualBase64 -cne [Convert]::ToBase64String($expectedLf) -and
        $actualBase64 -cne [Convert]::ToBase64String($expectedCrLf)) {
      throw 'checksum sidecar is invalid'
    }
    $stream.Position = 0
    return [pscustomobject]@{ archive = $stream; sidecar = $sidecarStream }
  }
  catch {
    if ($null -ne $stream) { $stream.Dispose() }
    if ($null -ne $sidecarStream) { $sidecarStream.Dispose() }
    throw
  }
}

function Expand-SafeArchive {
  param([System.IO.Stream]$ArchiveStream, [string]$Destination)
  Add-Type -AssemblyName System.IO.Compression
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  if (-not (Test-Path -LiteralPath $Destination -PathType Container)) { throw 'secure extraction root is absent' }
  $prefix = [System.IO.Path]::GetFullPath($Destination).TrimEnd('\') + '\'
  $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
  $directories = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
  $identities = @{}
  $leases = [System.Collections.Generic.List[System.IO.FileStream]]::new()
  $ArchiveStream.Position = 0
  $zip = [System.IO.Compression.ZipArchive]::new($ArchiveStream, [System.IO.Compression.ZipArchiveMode]::Read, $true)
  try {
    foreach ($entry in $zip.Entries) {
      $name = $entry.FullName
      if ([string]::IsNullOrWhiteSpace($name) -or $name.Contains('\') -or
          $name.Contains(':') -or $name.StartsWith('/') -or
          $name -match '(^|/)\.\.(/|$)' -or -not $seen.Add($name)) {
        throw 'archive contains an unsafe path'
      }
      $target = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($Destination, $name.Replace('/', '\')))
      if (-not $target.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'archive path escapes extraction root'
      }
      if ($name.EndsWith('/')) {
        [void][System.IO.Directory]::CreateDirectory($target)
        $relativeDirectory = $name.TrimEnd('/')
        while (-not [string]::IsNullOrEmpty($relativeDirectory)) {
          [void]$directories.Add($relativeDirectory)
          $relativeDirectory = [System.IO.Path]::GetDirectoryName($relativeDirectory.Replace('/', '\'))
          if ($null -ne $relativeDirectory) { $relativeDirectory = $relativeDirectory.Replace('\', '/') }
        }
      }
      else {
        $relativeParent = [System.IO.Path]::GetDirectoryName($name.Replace('/', '\'))
        while (-not [string]::IsNullOrEmpty($relativeParent)) {
          [void]$directories.Add($relativeParent.Replace('\', '/'))
          $relativeParent = [System.IO.Path]::GetDirectoryName($relativeParent)
        }
        [void][System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($target))
        $input = $entry.Open()
        $output = [IO.FileStream]::new($target, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::ReadWrite)
        $intermediate = $null
        $strict = $null
        $hasher = $null
        try {
          $hasher = [Security.Cryptography.IncrementalHash]::CreateHash([Security.Cryptography.HashAlgorithmName]::SHA256)
          $buffer = [byte[]]::new(65536)
          $size = [long]0
          while (($count = $input.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $hasher.AppendData($buffer, 0, $count)
            $output.Write($buffer, 0, $count)
            $size += $count
          }
          $expectedDigest = [Convert]::ToHexString($hasher.GetHashAndReset()).ToLowerInvariant()
          $hasher.Dispose(); $hasher = $null
          $output.Flush($true)
          $intermediate = [IO.FileStream]::new($target, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
          if (-not [AOIVDirectoryLease]::IsSameFile($output.SafeFileHandle, $target)) { throw 'extracted member identity differs' }
          $output.Dispose(); $output = $null
          $strict = [IO.FileStream]::new($target, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
          if (-not [AOIVDirectoryLease]::IsSameFile($intermediate.SafeFileHandle, $target)) { throw 'extracted member identity differs' }
          $intermediate.Dispose(); $intermediate = $null
          [AOIVDirectoryLease]::ValidateRegularSingleLink($strict.SafeFileHandle)
          $actualDigest = [Convert]::ToHexString([Security.Cryptography.SHA256]::Create().ComputeHash($strict)).ToLowerInvariant()
          if ($strict.Length -ne $size -or $actualDigest -cne $expectedDigest) { throw 'extracted member bytes differ' }
          $strict.Position = 0
          $identities[$name] = [pscustomobject]@{ size = $size; sha256 = $expectedDigest; lease = $strict }
          $leases.Add($strict)
          $strict = $null
        }
        finally {
          $input.Dispose()
          if ($null -ne $output) { $output.Dispose() }
          if ($null -ne $intermediate) { $intermediate.Dispose() }
          if ($null -ne $strict) { $strict.Dispose() }
          if ($null -ne $hasher) { $hasher.Dispose() }
        }
      }
    }
  }
  catch {
    foreach ($lease in $leases) { $lease.Dispose() }
    throw
  }
  finally {
    $zip.Dispose()
  }
  return [pscustomobject]@{ members = $identities; directories = $directories; leases = $leases }
}

function Assert-ExtractedTree {
  param([string]$Root, [object]$ArchiveTree)
  $seenFiles = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
  $seenDirectories = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
  foreach ($item in Get-ChildItem -LiteralPath $Root -Force -Recurse) {
    $relative = [IO.Path]::GetRelativePath($Root, $item.FullName).Replace('\', '/')
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'extracted tree contains a reparse point' }
    if ($item.PSIsContainer) {
      if (-not $ArchiveTree.directories.Contains($relative) -or -not $seenDirectories.Add($relative)) {
        throw 'extracted directory set differs'
      }
    }
    else {
      if (-not $ArchiveTree.members.ContainsKey($relative) -or -not $seenFiles.Add($relative)) {
        throw 'extracted file set differs'
      }
    }
  }
  if ($seenFiles.Count -ne $ArchiveTree.members.Count -or $seenDirectories.Count -ne $ArchiveTree.directories.Count) {
    throw 'extracted member set differs'
  }
  foreach ($name in $ArchiveTree.members.Keys) {
    $record = $ArchiveTree.members[$name]
    [AOIVDirectoryLease]::ValidateRegularSingleLink($record.lease.SafeFileHandle)
    $path = Join-Path $Root $name.Replace('/', '\')
    if (-not [AOIVDirectoryLease]::IsSameFile($record.lease.SafeFileHandle, $path)) { throw 'extracted member identity differs' }
    $record.lease.Position = 0
    $digest = [Convert]::ToHexString([Security.Cryptography.SHA256]::Create().ComputeHash($record.lease)).ToLowerInvariant()
    $record.lease.Position = 0
    if ($record.lease.Length -ne [long]$record.size -or $digest -cne [string]$record.sha256) {
      throw 'extracted member bytes differ'
    }
  }
}

function Open-VerifiedMember {
  param([string]$Path, [object]$Expected)
  $stream = [IO.FileStream]::new($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
  try {
    [AOIVDirectoryLease]::ValidateRegularSingleLink($stream.SafeFileHandle)
    $digest = [Convert]::ToHexString([Security.Cryptography.SHA256]::Create().ComputeHash($stream)).ToLowerInvariant()
    if ($stream.Length -ne [long]$Expected.size -or $digest -cne [string]$Expected.sha256) {
      throw 'extracted member identity differs'
    }
    $stream.Position = 0
    return $stream
  }
  catch { $stream.Dispose(); throw }
}

function Get-ExpectedInstalledMembers {
  param([hashtable]$Members)
  $manifestName = 'developer-preview-manifest.json'
  if (-not $Members.ContainsKey($manifestName)) { throw 'archive has no preview manifest' }
  $record = $Members[$manifestName]
  $record.lease.Position = 0
  $bytes = [byte[]]::new($record.lease.Length)
  if ($record.lease.Read($bytes, 0, $bytes.Length) -ne $bytes.Length) { throw 'preview manifest read is incomplete' }
  $record.lease.Position = 0
  try { $manifest = ([Text.UTF8Encoding]::new($false, $true).GetString($bytes) | ConvertFrom-Json) }
  catch { throw 'preview manifest is invalid' }
  if ($null -eq $manifest -or $manifest -isnot [pscustomobject]) { throw 'preview manifest is invalid' }
  $properties = @($manifest.PSObject.Properties.Name | Sort-Object)
  if (($properties -join ',') -cne 'architecture,files,label,runtime_version,schema_version' -or
      -not (Test-ExactJsonInteger $manifest.schema_version) -or [long]$manifest.schema_version -ne 1 -or
      $manifest.label -isnot [string] -or $manifest.label -cne 'developer-preview' -or
      $manifest.architecture -isnot [string] -or $manifest.architecture -cne 'windows-x86_64' -or
      $manifest.runtime_version -isnot [string] -or [string]::IsNullOrWhiteSpace($manifest.runtime_version) -or
      $manifest.files -isnot [System.Array]) {
    throw 'preview manifest is invalid'
  }
  $expected = @{$manifestName = $record}
  $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  [void]$seen.Add($manifestName)
  foreach ($file in $manifest.files) {
    if ($null -eq $file -or $file -isnot [pscustomobject]) { throw 'preview manifest contains an invalid member' }
    $fileProperties = @($file.PSObject.Properties.Name | Sort-Object)
    if (($fileProperties -join ',') -cne 'path,sha256,size' -or
        $file.path -isnot [string] -or [string]::IsNullOrWhiteSpace($file.path) -or
        $file.sha256 -isnot [string] -or
        -not (Test-ExactJsonInteger $file.size) -or [long]$file.size -lt 0) {
      throw 'preview manifest contains an invalid member'
    }
    $relative = $file.path
    if ($relative.Contains('\') -or
        $relative.Contains(':') -or $relative.StartsWith('/') -or
        @($relative.Split('/') | Where-Object { $_ -in @('', '.', '..') }).Count -ne 0 -or
        -not $seen.Add($relative) -or $file.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        -not $Members.ContainsKey($relative)) {
      throw 'preview manifest contains an invalid member'
    }
    $member = $Members[$relative]
    if ([long]$member.size -ne [long]$file.size -or [string]$member.sha256 -cne [string]$file.sha256) {
      throw 'preview manifest member identity differs'
    }
    $expected[$relative] = $member
  }
  return $expected
}

function Open-VerifiedInstalledArchiveMembers {
  param([string]$Root, [hashtable]$ExpectedMembers)
  $leases = [System.Collections.Generic.List[System.IO.FileStream]]::new()
  try {
    foreach ($name in $ExpectedMembers.Keys) {
      $path = Join-Path $Root $name.Replace('/', '\')
      $leases.Add((Open-VerifiedMember $path $ExpectedMembers[$name]))
    }
    return [pscustomobject]@{ leases = $leases }
  }
  catch {
    foreach ($lease in $leases) { $lease.Dispose() }
    throw
  }
}

function Invoke-LauncherJson {
  param([string]$Launcher, [string[]]$Arguments)
  $global:LASTEXITCODE = 0
  $output = & $Launcher @Arguments 2>$null
  if ($LASTEXITCODE -ne 0) { throw 'lifecycle command failed' }
  try { return (($output -join "`n") | ConvertFrom-Json) }
  catch { throw 'lifecycle command returned invalid JSON' }
}

function Assert-AllFreeStatus {
  param([object]$Status)
  $expected = @('O1','O2','O3','O4','O5')
  $actual = @($Status.offices)
  if ($Status.command -cne 'status' -or $Status.status -cne 'ok' -or
      $actual.Count -ne 5 -or
      (@($actual.office_id) -join ',') -cne ($expected -join ',') -or
      @($actual | Where-Object status -CNE 'free').Count -ne 0) {
    throw 'office-status-not-all-free'
  }
}

function Get-ExactTestControl {
  param([string]$Name)
  if ([Environment]::GetEnvironmentVariable('AO_OFFICE_POOL_TEST_MODE') -cne '1') { return '' }
  return [Environment]::GetEnvironmentVariable($Name)
}

function Invoke-AclBoundaryTestHook {
  param([string]$Name, [string]$Path)
  if ((Get-ExactTestControl 'AO_OFFICE_POOL_INSTALL_VERIFY_TEST_HOOK') -cne $Name) { return }
  $acl = Get-Acl -LiteralPath $Path
  $everyone = [Security.Principal.SecurityIdentifier]::new('S-1-1-0')
  $rule = [Security.AccessControl.FileSystemAccessRule]::new(
    $everyone,
    [Security.AccessControl.FileSystemRights]::FullControl,
    [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
    [Security.AccessControl.PropagationFlags]::None,
    [Security.AccessControl.AccessControlType]::Allow)
  [void]$acl.AddAccessRule($rule)
  Set-Acl -LiteralPath $Path -AclObject $acl
}

function Invoke-IdentityTestHook {
  param([string]$Name)
  $hook = Get-ExactTestControl 'AO_OFFICE_POOL_INSTALL_VERIFY_TEST_HOOK'
  if ($hook -cne $Name) { return }
  if ($Name -ceq 'replace-contract-after-read') {
    Move-Item -LiteralPath $contract -Destination "$contract.replaced"
  }
  elseif ($Name -ceq 'replace-assets-after-acquisition') {
    Move-Item -LiteralPath $archive -Destination "$archive.replaced"
    Move-Item -LiteralPath $sidecar -Destination "$sidecar.replaced"
    Copy-Item -LiteralPath (Get-ExactTestControl 'AO_OFFICE_POOL_INSTALL_VERIFY_TEST_REPLACEMENT_PAIR_ARCHIVE') -Destination $archive
    Copy-Item -LiteralPath (Get-ExactTestControl 'AO_OFFICE_POOL_INSTALL_VERIFY_TEST_REPLACEMENT_PAIR_SIDECAR') -Destination $sidecar
    return
  }
  elseif ($Name -ceq 'replace-archive-after-hash') {
    Move-Item -LiteralPath $archive -Destination "$archive.replaced"
    Copy-Item -LiteralPath (Get-ExactTestControl 'AO_OFFICE_POOL_INSTALL_VERIFY_TEST_REPLACEMENT_ARCHIVE') -Destination $archive
  }
  elseif ($Name -ceq 'replace-sidecar-after-validation') {
    Move-Item -LiteralPath $sidecar -Destination "$sidecar.replaced"
  }
  elseif ($Name -ceq 'replace-installer-after-extract') {
    Move-Item -LiteralPath $installScript -Destination "$installScript.replaced"
    Copy-Item -LiteralPath (Get-ExactTestControl 'AO_OFFICE_POOL_INSTALL_VERIFY_TEST_REPLACEMENT_INSTALLER') -Destination $installScript
  }
  elseif ($Name -ceq 'replace-launcher-after-extract') {
    $source = Join-Path $extractRoot 'bin\ao-office-pool.ps1'
    Move-Item -LiteralPath $source -Destination "$source.replaced"
    Copy-Item -LiteralPath (Get-ExactTestControl 'AO_OFFICE_POOL_INSTALL_VERIFY_TEST_REPLACEMENT_LAUNCHER') -Destination $source
    return
  }
  elseif ($Name -ceq 'replace-helper-after-extract') {
    $source = Join-Path $extractRoot 'bin\helper.txt'
    Move-Item -LiteralPath $source -Destination "$source.replaced"
    Copy-Item -LiteralPath (Get-ExactTestControl 'AO_OFFICE_POOL_INSTALL_VERIFY_TEST_REPLACEMENT_HELPER') -Destination $source
    return
  }
  elseif ($Name -ceq 'remove-installed-helper-after-verify') {
    [IO.File]::Delete((Join-Path $installStage 'bin\helper.txt'))
    return
  }
  elseif ($Name -ceq 'replace-install-stage-before-publish') {
    Move-Item -LiteralPath $installStage -Destination "$installStage.replaced"
  }
  elseif ($Name -ceq 'inject-install-stage-before-publish') {
    [IO.File]::WriteAllText((Join-Path $installStage 'unexpected.txt'), 'unexpected')
    return
  }
  throw 'identity race detected'
}

function Remove-OwnedTemporaryRoot {
  param([string]$Path, [AOIVDirectoryLease]$Lease)
  if ($null -eq $Lease -or [string]::IsNullOrEmpty($Path)) { return }
  if (-not $Lease.IsSamePath($Path)) { return }
  $replacementHook = Get-ExactTestControl 'AO_OFFICE_POOL_INSTALL_VERIFY_TEST_HOOK'
  if ((($replacementHook -ceq 'replace-extract-root-before-cleanup' -and $Path -ceq $extractRoot) -or
       ($replacementHook -ceq 'replace-download-run-before-cleanup' -and $Path -ceq $downloadRun))) {
    $Lease.RenameTo("$Path.unowned")
    [void][IO.Directory]::CreateDirectory($Path)
    [IO.File]::WriteAllText((Join-Path $Path 'keep.txt'), 'keep')
    if ($replacementHook -ceq 'replace-extract-root-before-cleanup') {
      Add-Content -LiteralPath (Get-ExactTestControl 'AO_T4_EVENT_LOG') -Value 'cleanup-replacement-preserved'
    }
    if (-not $Lease.IsSamePath($Path)) { throw 'identity race detected' }
  }
  $quarantine = Join-Path ([IO.Path]::GetDirectoryName($Path)) ('.ao-office-pool-cleanup-' + [Guid]::NewGuid().ToString('N'))
  $Lease.RenameTo($quarantine)
  if (-not $Lease.IsSamePath($quarantine)) { throw 'cleanup identity differs' }
  $raceBlocked = $false
  if ((Get-ExactTestControl 'AO_OFFICE_POOL_INSTALL_VERIFY_TEST_HOOK') -ceq 'replace-cleanup-quarantine-before-delete' -and
      $Path -ceq $extractRoot) {
    try { Move-Item -LiteralPath $quarantine -Destination "$quarantine.unowned" -ErrorAction Stop }
    catch {
      $raceBlocked = $true
      Add-Content -LiteralPath (Get-ExactTestControl 'AO_T4_EVENT_LOG') -Value 'cleanup-delete-race-blocked'
    }
    if (-not $raceBlocked) { throw 'cleanup identity race succeeded' }
  }
  foreach ($child in Get-ChildItem -LiteralPath $quarantine -Force) {
    Remove-Item -LiteralPath $child.FullName -Recurse -Force
  }
  $Lease.DeleteOnClose()
  $Lease.Dispose()
  if ($raceBlocked) { throw 'identity race detected' }
}

$caught = $null
try {
  $prerequisiteTest = Get-ExactTestControl 'AO_OFFICE_POOL_INSTALL_VERIFY_TEST_PREREQUISITE'
  $failureCode = 'prerequisite-platform'
  if ($prerequisiteTest -ceq 'platform' -or $PSVersionTable.PSVersion.Major -lt 7 -or
      -not [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([Runtime.InteropServices.OSPlatform]::Windows) -or
      [Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne [Runtime.InteropServices.Architecture]::X64) {
    throw 'unsupported platform'
  }
  $failureCode = 'prerequisite-git'
  if ($prerequisiteTest -ceq 'git' -or $null -eq (Get-Command git.exe -ErrorAction SilentlyContinue)) { throw 'Git is unavailable' }
  $failureCode = 'prerequisite-python'
  if ($prerequisiteTest -ceq 'python') { throw 'Python is unavailable' }
  $python = (Get-Command python.exe -ErrorAction Stop).Source
  & $python -c "import sys; raise SystemExit(0 if sys.version_info[:2] == (3, 12) else 1)" 2>$null
  if ($LASTEXITCODE -ne 0) { throw 'Python version differs' }
  $failureCode = 'prerequisite-vcruntime'
  if ($prerequisiteTest -ceq 'vcruntime' -or -not (Test-Path -LiteralPath (Join-Path ([Environment]::SystemDirectory) 'VCRUNTIME140.dll') -PathType Leaf)) { throw 'VC runtime unavailable' }
  $failureCode = 'prerequisite-path'
  if ($prerequisiteTest -ceq 'path') { throw 'install path is unavailable' }
  $safeLocalAppData = Assert-SafeNtfsBase $env:LOCALAPPDATA 'local application data' -NoCreate
  $privateAnchor = Join-Path $safeLocalAppData '.ao-office-pool-private'
  $safeInstallRoot = Assert-DirectPrivateChildPath $InstallRoot $privateAnchor 'install root'
  $safeDownloadRoot = Assert-DirectPrivateChildPath $DownloadRoot $privateAnchor 'download root'
  $safeLocalAppData = Assert-SafeNtfsBase $safeLocalAppData 'local application data'
  if (Test-Path -LiteralPath $privateAnchor) {
    $privateAnchorLease = [AOIVDirectoryLease]::new($privateAnchor)
    Assert-PrivateDirectoryAcl $privateAnchor $true
  }
  else { $privateAnchorLease = New-PrivateDirectoryLease $privateAnchor }
  if (-not $privateAnchorLease.IsSamePath($privateAnchor)) { throw 'private application root identity differs' }
  $safeInstallRoot = Assert-SafeNewNtfsRoot $safeInstallRoot 'install root'
  if (Test-Path -LiteralPath $safeDownloadRoot) {
    $safeDownloadRoot = Assert-SafeNtfsBase $safeDownloadRoot 'download root'
    $downloadBaseLease = [AOIVDirectoryLease]::new($safeDownloadRoot)
    Assert-PrivateDirectoryAcl $safeDownloadRoot $true
  }
  else {
    $safeDownloadRoot = Assert-SafeNewNtfsRoot $safeDownloadRoot 'download root'
    $downloadBaseLease = New-PrivateDirectoryLease $safeDownloadRoot
  }
  if (-not $downloadBaseLease.IsSamePath($safeDownloadRoot)) { throw 'download root identity differs' }

  $failureCode = 'archive-invalid'
  $contract = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\manifests\public-release.json'))
  $trustedContract = Read-TrustedPublicContract $contract
  $contractLease = $trustedContract.lease
  $contractIdentities = @($trustedContract.identities)
  Invoke-IdentityTestHook 'replace-contract-after-read'

  $downloadRun = Join-Path $safeDownloadRoot ('.ao-office-pool-download-' + [Guid]::NewGuid().ToString('N'))
  $downloadRunLease = New-PrivateDirectoryLease $downloadRun
  Invoke-AclBoundaryTestHook 'replace-download-run-before-lease' $downloadRun
  Assert-PrivateDirectoryAcl $downloadRun $true
  if (-not $downloadRunLease.IsSamePath($downloadRun)) { throw 'download run identity differs' }
  $downloadDestination = Join-Path $downloadRun 'assets'

  $failureCode = 'acquisition-failed'
  $acquireScript = Join-Path $PSScriptRoot '..\packaging\Get-AOOfficePoolPublicRelease.ps1'
  $fixtureAcquire = Get-ExactTestControl 'AO_OFFICE_POOL_INSTALL_VERIFY_ACQUIRE_SCRIPT'
  if (-not [string]::IsNullOrEmpty($fixtureAcquire)) { $acquireScript = $fixtureAcquire }
  & $acquireScript -Contract $contract -Destination $downloadDestination 2>&1 | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'public acquisition failed' }
  Assert-PrivateTreeAcl $downloadRun $true

  $failureCode = 'archive-invalid'
  $archive = Join-Path $downloadDestination $ArchiveName
  $sidecar = Join-Path $downloadDestination $SidecarName
  Invoke-IdentityTestHook 'replace-assets-after-acquisition'
  $validatedAssets = Assert-ArchiveSidecar $archive $sidecar $contractIdentities
  $archiveLease = $validatedAssets.archive
  $sidecarLease = $validatedAssets.sidecar
  Invoke-IdentityTestHook 'replace-archive-after-hash'
  Invoke-IdentityTestHook 'replace-sidecar-after-validation'

  $failureCode = 'extraction-failed'
  $workingParent = $privateAnchor
  $extractRoot = Join-Path $workingParent ('.ao-office-pool-extract-' + [Guid]::NewGuid().ToString('N'))
  $installContainer = Join-Path ([IO.Path]::GetDirectoryName($safeInstallRoot)) ('.ao-office-pool-install-' + [Guid]::NewGuid().ToString('N'))
  $installStage = Join-Path $installContainer 'root'
  $projectRoot = Join-Path $workingParent ('.ao-office-pool-project-' + [Guid]::NewGuid().ToString('N'))
  if ($extractRoot.Length -gt 180 -or $installStage.Length -gt 180 -or $projectRoot.Length -gt 180) { throw 'working path budget exceeded' }
  $extractRootLease = New-PrivateDirectoryLease $extractRoot
  Invoke-AclBoundaryTestHook 'weaken-extract-root-before-lease' $extractRoot
  Assert-PrivateDirectoryAcl $extractRoot $true
  $archiveTree = Expand-SafeArchive $archiveLease $extractRoot
  Assert-PrivateTreeAcl $extractRoot $true
  $members = $archiveTree.members
  $expectedInstalledMembers = Get-ExpectedInstalledMembers $members
  $memberLeases = @($archiveTree.leases)
  $installScript = Join-Path $extractRoot 'packaging\Install-AOOfficePool.ps1'
  $verifyScript = Join-Path $extractRoot 'packaging\Verify-AOOfficePool.ps1'
  Assert-ExtractedTree $extractRoot $archiveTree
  Invoke-IdentityTestHook 'replace-installer-after-extract'
  Invoke-IdentityTestHook 'replace-launcher-after-extract'
  Invoke-IdentityTestHook 'replace-helper-after-extract'

  $failureCode = 'installation-failed'
  $installContainerLease = New-PrivateDirectoryLease $installContainer
  Invoke-AclBoundaryTestHook 'replace-install-container-before-lease' $installContainer
  Assert-PrivateDirectoryAcl $installContainer $true
  Assert-ExtractedTree $extractRoot $archiveTree
  & $installScript -Action Install -Archive $archive -ChecksumFile $sidecar -InstallRoot $installStage 2>&1 | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'installation failed' }
  Invoke-AclBoundaryTestHook 'replace-install-stage-before-lease' $installStage
  $installStageLease = [AOIVDirectoryLease]::new($installStage)
  Protect-PrivateDirectoryRoot $installStage $installStageLease
  $failureCode = 'verification-failed'
  Assert-ExtractedTree $extractRoot $archiveTree
  & $verifyScript -InstallRoot $installStage -Archive $archive -ChecksumFile $sidecar 2>&1 | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'verification failed' }
  Invoke-IdentityTestHook 'remove-installed-helper-after-verify'
  $installedTree = Open-VerifiedInstalledArchiveMembers $installStage $expectedInstalledMembers
  $installedMemberLeases = @($installedTree.leases)

  $failureCode = 'prerequisite-git'
  $projectRootLease = New-PrivateDirectoryLease $projectRoot
  Invoke-AclBoundaryTestHook 'replace-project-before-lease' $projectRoot
  Assert-PrivateDirectoryAcl $projectRoot $true
  $projectRootLease.Dispose(); $projectRootLease = $null
  & git -C $projectRoot init --quiet 2>$null
  if ($LASTEXITCODE -ne 0) { throw 'Git initialization failed' }
  $projectRootLease = [AOIVDirectoryLease]::new($projectRoot)
  if (-not $projectRootLease.IsSamePath($projectRoot)) { throw 'project root identity differs' }
  Assert-PrivateTreeAcl $projectRoot $true
  $failureCode = 'lifecycle-failed'
  $launcher = Join-Path $installStage 'bin\ao-office-pool.ps1'
  $launcherLease = Open-VerifiedMember $launcher $members['bin/ao-office-pool.ps1']
  Assert-ExtractedTree $extractRoot $archiveTree
  Assert-AllFreeStatus (Invoke-LauncherJson $launcher @('status'))
  $claim = Invoke-LauncherJson $launcher @('claim', '--owner', 'install-smoke', '--task', 'installation verification', '--project', $projectRoot, '--mode', 'conversation')
  if ($claim.command -ceq 'claim' -and $claim.status -ceq 'ok' -and
      -not [string]::IsNullOrWhiteSpace([string]$claim.authority_path)) {
    $receipt = [string]$claim.authority_path
    $claimedOffice = [string]$claim.office_id
    $claimSucceeded = $true
  }
  if ($claim.command -cne 'claim' -or $claim.status -cne 'ok' -or $claim.office_id -cne 'O1' -or
      [string]::IsNullOrWhiteSpace([string]$claim.authority_path)) { throw 'O1 claim verification failed' }
  $resume = Invoke-LauncherJson $launcher @('resume', '--receipt', $receipt)
  if ($resume.command -cne 'resume' -or $resume.status -cne 'ok' -or $resume.office_id -cne 'O1' -or
      [string]$resume.authority_path -cne $receipt) { throw 'O1 resume verification failed' }
  $release = Invoke-LauncherJson $launcher @('release', '--receipt', $receipt)
  if ($release.command -cne 'release' -or $release.status -cne 'ok') { throw 'O1 release verification failed' }
  $releaseSucceeded = $true
  $postReleaseStatusChecked = $true
  Assert-AllFreeStatus (Invoke-LauncherJson $launcher @('status'))
  $terminalFree = $true

  $launcherLease.Dispose(); $launcherLease = $null
  foreach ($lease in $installedMemberLeases) { $lease.Dispose() }
  $installedMemberLeases = @()
  $failureCode = 'publication-failed'
  Invoke-IdentityTestHook 'replace-install-stage-before-publish'
  Invoke-IdentityTestHook 'inject-install-stage-before-publish'
  if (-not $installStageLease.IsSamePath($installStage)) { throw 'install staging identity differs' }
  $installStageLease.RenameTo($safeInstallRoot)
  $installStage = $safeInstallRoot
  if (-not $installStageLease.IsSamePath($installStage)) { throw 'published install identity differs' }
  Invoke-AclBoundaryTestHook 'weaken-final-root-before-acl-validation' $installStage
  Assert-PrivateTreeAcl $installStage $true

  $failureCode = 'verification-failed'
  Assert-ExtractedTree $extractRoot $archiveTree
  $installedTree = Open-VerifiedInstalledArchiveMembers $safeInstallRoot $expectedInstalledMembers
  $installedMemberLeases = @($installedTree.leases)
  & $verifyScript -InstallRoot $safeInstallRoot -Archive $archive -ChecksumFile $sidecar 2>&1 | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'published verification failed' }
  $launcher = Join-Path $safeInstallRoot 'bin\ao-office-pool.ps1'
  $launcherLease = Open-VerifiedMember $launcher $members['bin/ao-office-pool.ps1']
  Assert-ExtractedTree $extractRoot $archiveTree
  Assert-AllFreeStatus (Invoke-LauncherJson $launcher @('status'))
  $launcherLease.Dispose(); $launcherLease = $null
  foreach ($lease in $installedMemberLeases) { $lease.Dispose() }
  $installedMemberLeases = @()

  $failureCode = 'cleanup-failed'
  foreach ($lease in $memberLeases) { $lease.Dispose() }
  $memberLeases = @()
  Remove-OwnedTemporaryRoot $extractRoot $extractRootLease
  $extractRoot = $null; $extractRootLease = $null
  Remove-OwnedTemporaryRoot $projectRoot $projectRootLease
  $projectRoot = $null; $projectRootLease = $null
  Remove-OwnedTemporaryRoot $installContainer $installContainerLease
  $installContainer = $null; $installContainerLease = $null
  $installStageLease.Dispose(); $installStageLease = $null
  $installStage = $null
  $downloadRunLease.Dispose(); $downloadRunLease = $null
  $downloadRun = $null
  Write-Output "Install location: $safeInstallRoot"
  Write-Output ('Launcher: & "' + (Join-Path $safeInstallRoot 'bin\ao-office-pool.ps1') + '" status')
  Write-Output 'Commands: status, claim, resume, run, release, recover'
  Write-Output 'READY FOR USE'
}
catch { $caught = $_ }
finally {
  if ($claimSucceeded -and -not $terminalFree -and $null -ne $launcher -and $null -ne $receipt) {
    if (-not $releaseSucceeded) {
      try {
        $cleanupRelease = Invoke-LauncherJson $launcher @('release', '--receipt', $receipt)
        $releaseSucceeded = $cleanupRelease.command -ceq 'release' -and $cleanupRelease.status -ceq 'ok'
      }
      catch { $releaseSucceeded = $false }
    }
    if ($releaseSucceeded -and -not $postReleaseStatusChecked) {
      $postReleaseStatusChecked = $true
      try {
        Assert-AllFreeStatus (Invoke-LauncherJson $launcher @('status'))
        $terminalFree = $true
      }
      catch { $terminalFree = $false }
    }
    if (-not $terminalFree) {
      try {
        if ($ExpectedOffices -cnotcontains $claimedOffice) { throw 'claimed office is invalid' }
        $generation = if ($claim.PSObject.Properties.Match('generation').Count -eq 1) { [string]$claim.generation } else { throw 'claim generation is missing' }
        $recoveryKey = Join-Path $installStage "operator-secrets\recovery-key-$claimedOffice"
        $recovered = Invoke-LauncherJson $launcher @('recover', '--key', $recoveryKey, '--office', $claimedOffice, '--generation', $generation)
        if ($recovered.command -cne 'recover' -or $recovered.status -cne 'ok') { throw 'recovery response differs' }
        Assert-AllFreeStatus (Invoke-LauncherJson $launcher @('status'))
        $terminalFree = $true
      }
      catch { $terminalFree = $false; $failureCode = 'recovery-failed' }
    }
    if (-not $terminalFree) { $failureCode = 'recovery-failed' }
  }
  $receipt = $null; $claim = $null; $resume = $null
  if ($null -ne $launcherLease) { $launcherLease.Dispose() }
  if ($null -ne $installerLease) { $installerLease.Dispose() }
  if ($null -ne $verifierLease) { $verifierLease.Dispose() }
  foreach ($lease in $installedMemberLeases) { $lease.Dispose() }
  $installedMemberLeases = @()
  foreach ($lease in $memberLeases) { $lease.Dispose() }
  $memberLeases = @()
  if ($null -ne $archiveLease) { $archiveLease.Dispose() }
  if ($null -ne $sidecarLease) { $sidecarLease.Dispose() }
  if ($null -ne $contractLease) { $contractLease.Dispose() }
  try { Remove-OwnedTemporaryRoot $installStage $installStageLease } catch { if ($null -eq $caught) { $failureCode = 'cleanup-failed'; $caught = $_ } }
  try { Remove-OwnedTemporaryRoot $installContainer $installContainerLease } catch { if ($null -eq $caught) { $failureCode = 'cleanup-failed'; $caught = $_ } }
  try { Remove-OwnedTemporaryRoot $extractRoot $extractRootLease } catch { if ($null -eq $caught) { $failureCode = 'cleanup-failed'; $caught = $_ } }
  try { Remove-OwnedTemporaryRoot $projectRoot $projectRootLease } catch { if ($null -eq $caught) { $failureCode = 'cleanup-failed'; $caught = $_ } }
  try { Remove-OwnedTemporaryRoot $downloadRun $downloadRunLease } catch { if ($null -eq $caught) { $failureCode = 'cleanup-failed'; $caught = $_ } }
  if ($null -ne $downloadBaseLease) { $downloadBaseLease.Dispose() }
  if ($null -ne $privateAnchorLease) { $privateAnchorLease.Dispose() }
}
if ($null -ne $caught) {
  [Console]::Error.WriteLine("HOLD [$failureCode]")
  exit 1
}
