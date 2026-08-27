#Requires -Version 5.1
<#
.SYNOPSIS
  Installs or updates Merlin Guild from the Cloudflare-distributed release.

.DESCRIPTION
  1. Fetches manifest.json + .sig from dl.merlinguild.com.
  2. Verifies RSA-2048 signature in-process via RSACng with RSA-PSS.
  3. Checks expiry and anti-rollback sequence.
  4. Reads or prompts for the JWT license.
  5. Sends license to the Worker, follows 302 redirect to R2 presigned URL.
  6. Verifies MSI SHA-256 and runs msiexec.

.PARAMETER Channel
  Release channel (stable, beta, ...). Default: stable.

.PARAMETER BackupPath
  Path to a local .msi file. Bypasses all network and verification checks (dev only).

.PARAMETER BackupUrl
  URL to download a .msi file from. Bypasses manifest verification (dev only).

.PARAMETER SkipInstall
  Skip MSI installation (for testing or verification-only scenarios).

.NOTES
  The anti-rollback minimum sequence is an **embedded constant** in this
  script, not a CLI parameter. It is intentionally not user-tunable so an
  attacker (or unwary operator) cannot downgrade the floor and replay an
  old manifest. To raise the floor after a security event, edit
  $Script:MinimumSequence in the Constants block and re-publish `install.ps1`
  with a fresh manifest signature.
#>
[CmdletBinding()]
param(
  [string] $Channel = 'stable',
  [string] $BackupPath = $env:BACKUP_PATH,
  [string] $BackupUrl  = $env:BACKUP_URL,
  [switch] $SkipInstall
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# BEGIN_BOOTSTRAP_HOST [do not remove: integration tests replace between markers]
$Script:BootstrapHost   = 'dl.merlinguild.com'
# END_BOOTSTRAP_HOST

$Script:LicensePath     = Join-Path $env:USERPROFILE '.merlinguild\license'
$Script:SequencePath    = Join-Path $env:USERPROFILE '.merlinguild\.sequence'
$Script:UserAgent       = 'merlinguild-installer'

# BEGIN_MINIMUM_SEQUENCE [do not remove: integration tests replace between markers]
$Script:MinimumSequence = 1
# END_MINIMUM_SEQUENCE

# BEGIN_TRUSTED_KEYS [do not remove: integration tests replace between markers]
$Script:TrustedManifestKeys = @(
  @{ Modulus = 'v1SdtqeXrZWOhWPuPMeRX0xuunXcoNKbpWUrG5ppXKoSBxVbThUxJAcl3frPFl675cYAyGF0m/VOg3a3aAdo5z43zFf4iXc9Ci6naDTVxls/oIgJ8WeHA/rRyJ4KqFv9+Ds24zybEBfC0LpUR0gP54AFnD/T1s8UkxfNC0CEHOeMvLoESoA+3Irj44qgX2YBs3AhSe+bJxCKUzJcFtvrySD/rhQOxc387KaQyd3qIXJLcBJm7K6Qbbsin4i7uLZ4ZcMn2UB0WvquVfU/I2VxgCHjTYYJ6BiYAVU6HKACikDGb+3ywm4R3HJMyj/OfPcE6glJMvt32BeKTlJ5QfAayQ=='; Exponent = 'AQAB' }
)
# END_TRUSTED_KEYS

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

function Write-Info { param([string]$Message) Write-Host "[info]  $Message" -ForegroundColor Cyan }
function Write-Ok   { param([string]$Message) Write-Host "[ok]    $Message" -ForegroundColor Green }
function Write-Fail { param([string]$Message) Write-Host "[error] $Message" -ForegroundColor Red }

# ---------------------------------------------------------------------------
# Manifest fetch and verification
# ---------------------------------------------------------------------------

function Get-Manifest {
  $tmpManifest = Join-Path $env:TEMP ('mg-manifest-' + [Guid]::NewGuid().ToString('N'))
  $tmpSig      = "$tmpManifest.sig"
  try {
    try {
      Invoke-WebRequest -Uri "https://$Script:BootstrapHost/manifest.json" -OutFile $tmpManifest -UseBasicParsing -TimeoutSec 15
      Invoke-WebRequest -Uri "https://$Script:BootstrapHost/manifest.json.sig" -OutFile $tmpSig -UseBasicParsing -TimeoutSec 15
    } catch [System.Net.WebException] {
      throw "Error: Could not reach $Script:BootstrapHost. Check your internet connection and try again."
    }
    return @{
      JsonPath = $tmpManifest
      SigPath  = $tmpSig
    }
  } catch {
    Remove-Item $tmpManifest -Force -ErrorAction SilentlyContinue
    Remove-Item $tmpSig -Force -ErrorAction SilentlyContinue
    throw
  }
}

function Assert-ManifestSignature {
  param([byte[]]$ManifestBytes, [string]$SigB64url)
  $hash = [System.Security.Cryptography.SHA256]::Create().ComputeHash($ManifestBytes)

  $b64 = $SigB64url.Trim().Replace('-', '+').Replace('_', '/')
  switch ($b64.Length % 4) {
    2 { $b64 += '==' }
    3 { $b64 += '=' }
  }
  $sigBytes = [Convert]::FromBase64String($b64)
  if ($sigBytes.Length -ne 256) {
    throw "Invalid manifest signature length: $($sigBytes.Length) bytes (expected 256 for RSA-2048)."
  }

  $verified = $false
  foreach ($key in $Script:TrustedManifestKeys) {
    $modulus = [Convert]::FromBase64String($key.Modulus)
    $exponent = [Convert]::FromBase64String($key.Exponent)
    if ($modulus.Length -ne 256) {
      throw "Corrupt trusted key material (Modulus must be 256 bytes for RSA-2048)."
    }
    
    $rsaParams = New-Object System.Security.Cryptography.RSAParameters
    $rsaParams.Modulus = $modulus
    $rsaParams.Exponent = $exponent
    $rsa = [System.Security.Cryptography.RSACng]::new(2048)
    try {
      $rsa.ImportParameters($rsaParams)

      $pss = [System.Security.Cryptography.RSASignaturePadding]::Pss
      $hashAlgorithm = [System.Security.Cryptography.HashAlgorithmName]::SHA256
      if ($rsa.VerifyHash($hash, $sigBytes, $hashAlgorithm, $pss)) {
        $verified = $true
        break
      }
    } finally {
      $rsa.Dispose()
    }
  }

  if (-not $verified) {
    throw "Manifest signature verification failed against all trusted keys."
  }
  Write-Ok "Manifest signature verified."
}

function Assert-NotExpired {
  param([string]$ExpiresAt)
  $now = (Get-Date).ToUniversalTime()
  $exp = [datetime]::Parse($ExpiresAt, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind)
  $skew = New-TimeSpan -Hours 24
  if (($now - $exp) -gt $skew) {
    throw "Manifest expired. A new release is pending; try again later."
  }
}

# ---------------------------------------------------------------------------
# Anti-rollback
# ---------------------------------------------------------------------------

function Read-Sequence {
  param([string]$Channel)
  if (-not (Test-Path $Script:SequencePath)) { return $null }
  foreach ($line in [IO.File]::ReadAllLines($Script:SequencePath)) {
    $trimmed = $line.Trim()
    if ($trimmed -match '^(\w+)=(\d+)$') {
      if ($Matches[1] -eq $Channel) { return [int]$Matches[2] }
    }
  }
  return $null
}

function Write-Sequence {
  param([string]$Channel, [int]$Sequence)
  $dir = [IO.Path]::GetDirectoryName($Script:SequencePath)
  if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
  $tmp = Join-Path $dir ('.sequence.tmp.' + [Guid]::NewGuid().ToString('N'))
  $lines = @()
  if (Test-Path $Script:SequencePath) {
    $existing = [IO.File]::ReadAllLines($Script:SequencePath)
    $found = $false
    foreach ($line in $existing) {
      $trimmed = $line.Trim()
      if ($trimmed -match '^(\w+)=(\d+)$' -and $Matches[1] -eq $Channel) {
        $lines += "$Channel=$Sequence"
        $found = $true
      } else {
        $lines += $line
      }
    }
    if (-not $found) { $lines += "$Channel=$Sequence" }
  } else {
    $lines = @("format 1", "$Channel=$Sequence")
  }
  [IO.File]::WriteAllLines($tmp, $lines, [System.Text.Encoding]::UTF8)
  Move-Item -LiteralPath $tmp -Destination $Script:SequencePath -Force
}

function Assert-NotRollback {
  param([int]$ManifestSequence, [string]$Channel)
  if ($ManifestSequence -lt $Script:MinimumSequence) {
    throw "Rollback blocked: manifest sequence $ManifestSequence is below the embedded minimum ($Script:MinimumSequence)."
  }
  $stored = Read-Sequence -Channel $Channel
  if ($stored -and ($ManifestSequence -le $stored)) {
    throw "Rollback blocked: manifest sequence $ManifestSequence is not greater than the stored sequence $stored for channel '$Channel'."
  }
}

# ---------------------------------------------------------------------------
# License
# ---------------------------------------------------------------------------

function Get-License {
  if (-not (Test-Path $Script:LicensePath)) { return $null }
  return [IO.File]::ReadAllText($Script:LicensePath).Trim()
}

function Save-License {
  param([string]$Jwt)
  $dir = [IO.Path]::GetDirectoryName($Script:LicensePath)
  if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
  [IO.File]::WriteAllText($Script:LicensePath, $Jwt, [System.Text.Encoding]::UTF8)
}

function Read-License {
  Write-Host ""
  Write-Host "A valid license JWT is required to download Merlin Guild." -ForegroundColor Yellow
  $jwt = Read-Host "Paste your license JWT"
  if (-not $jwt) { throw "No license provided. Installation aborted." }
  return $jwt.Trim()
}

# ---------------------------------------------------------------------------
# MSI download and install
# ---------------------------------------------------------------------------

function Receive-Msi {
  param([string]$Url, [string]$Jwt, [string]$OutPath)

  $workerRequest = [System.Net.HttpWebRequest]::Create($Url)
  $workerRequest.Method = 'GET'
  $workerRequest.Headers.Add('Authorization', "Bearer $Jwt")
  $workerRequest.AllowAutoRedirect = $false
  $workerRequest.UserAgent = $Script:UserAgent
  $workerRequest.Timeout = 30000

  try {
    $workerResponse = $workerRequest.GetResponse()
  } catch [System.Net.WebException] {
    $ex = $_.Exception
    if ($ex.Response) {
      $status = [int]$ex.Response.StatusCode
      if ($status -eq 401 -or $status -eq 403) {
        throw "Worker rejected the license ($status). The JWT may be expired, revoked, or invalid."
      }
      throw "Error: Download service returned HTTP $status for the installer. Try again later."
    }
    throw "Error: Could not reach $Script:BootstrapHost. Check your internet connection and try again."
  }

  if ([int]$workerResponse.StatusCode -eq 302) {
    $redirectUrl = $workerResponse.Headers['Location']
    $workerResponse.Close()

    $r2Request = [System.Net.HttpWebRequest]::Create($redirectUrl)
    $r2Request.Method = 'GET'
    $r2Request.UserAgent = $Script:UserAgent
    $r2Request.AllowAutoRedirect = $true
    $r2Request.Timeout = 300000

    try {
      $r2Response = $r2Request.GetResponse()
    } catch [System.Net.WebException] {
      throw "Error: Could not download the MSI from the presigned URL. Check your internet connection and try again."
    }

    $stream = $r2Response.GetResponseStream()
    $fileStream = [System.IO.File]::Create($OutPath)
    try {
      $stream.CopyTo($fileStream)
    } finally {
      $fileStream.Close()
      $stream.Close()
      $r2Response.Close()
    }
  } else {
    $stream = $workerResponse.GetResponseStream()
    $fileStream = [System.IO.File]::Create($OutPath)
    try {
      $stream.CopyTo($fileStream)
    } finally {
      $fileStream.Close()
      $stream.Close()
      $workerResponse.Close()
    }
  }
}

function Assert-MsiHash {
  param([string]$MsiPath, [string]$ExpectedSha256)
  $actual = (Get-FileHash -Algorithm SHA256 -Path $MsiPath).Hash.ToLower()
  if ($actual -ne $ExpectedSha256) {
    throw "MSI hash mismatch: expected $ExpectedSha256, got $actual."
  }
  Write-Ok "MSI SHA-256 matches manifest."
}

function Install-Msi {
  param([string]$MsiPath)
  if ($SkipInstall) {
    Write-Info 'Skipping MSI installation (SkipInstall flag set).'
    return
  }
  Unblock-File -Path $MsiPath -ErrorAction SilentlyContinue
  Write-Info 'Launching msiexec (expect a single UAC prompt)...'
  $proc = Start-Process -FilePath msiexec.exe -ArgumentList @('/i', "`"$MsiPath`"", '/qb', '/norestart') -Wait -PassThru
  if ($proc.ExitCode -ne 0) {
    throw "msiexec exited with code $($proc.ExitCode)."
  }
  Write-Ok 'Installation complete.'
}

# ---------------------------------------------------------------------------
# Local modes
# ---------------------------------------------------------------------------

function Invoke-BackupPathMode {
  param([string]$Path = $BackupPath)
  $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).ProviderPath
  if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
    throw "MSI not found: $resolved"
  }
  Install-Msi -MsiPath $resolved
}

function Invoke-BackupUrlMode {
  param([string]$Url = $BackupUrl)
  $msiPath = Join-Path $env:TEMP ('mg-' + [Guid]::NewGuid().ToString('N') + '.msi')
  try {
    Write-Info "Downloading MSI from $Url ..."
    Invoke-WebRequest -Uri $Url -OutFile $msiPath -UseBasicParsing
    Install-Msi -MsiPath $msiPath
  } finally {
    Remove-Item -LiteralPath $msiPath -Force -ErrorAction SilentlyContinue
  }
}

# ---------------------------------------------------------------------------
# Main install flow
# ---------------------------------------------------------------------------

function Invoke-MainFlow {
  $manifest = Get-Manifest
  $manifestBytes = [IO.File]::ReadAllBytes($manifest.JsonPath)
  $sigText       = [IO.File]::ReadAllText($manifest.SigPath).Trim()

  Assert-ManifestSignature -ManifestBytes $manifestBytes -SigB64url $sigText

  $json = [System.Text.Encoding]::UTF8.GetString($manifestBytes) | ConvertFrom-Json
  if (-not $json.channels.$Channel) {
    throw "Channel '$Channel' not found in manifest."
  }
  $channelData = $json.channels.$Channel
  $artifact = $channelData.artifacts.windows_x64
  if (-not $artifact) {
    throw "No windows_x64 artifact found for channel '$Channel'."
  }

  Assert-NotExpired -ExpiresAt $json.expires_at
  Assert-NotRollback -ManifestSequence $channelData.sequence -Channel $Channel

  $jwt = Get-License
  if (-not $jwt) {
    if ($SkipInstall) {
      throw "license JWT is required"
    }
    $jwt = Read-License
  }

  $msiPath = Join-Path $env:TEMP ('mg-' + [Guid]::NewGuid().ToString('N') + '.msi')
  try {
    try {
      Receive-Msi -Url $artifact.url -Jwt $jwt -OutPath $msiPath
    } catch {
      $errMsg = $_.Exception.Message
      if ($errMsg -match 'Worker rejected the license') {
        Write-Fail $errMsg
        if (-not $SkipInstall) {
          $jwt = Read-License
          Save-License -Jwt $jwt
          Receive-Msi -Url $artifact.url -Jwt $jwt -OutPath $msiPath
        } else {
          throw
        }
      } else {
        throw
      }
    }

    if (-not (Get-License)) {
      Save-License -Jwt $jwt
    }

    Assert-MsiHash -MsiPath $msiPath -ExpectedSha256 $artifact.sha256

    Install-Msi -MsiPath $msiPath

    Write-Sequence -Channel $Channel -Sequence $channelData.sequence
  } finally {
    Remove-Item -LiteralPath $msiPath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $manifest.JsonPath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $manifest.SigPath -Force -ErrorAction SilentlyContinue
  }
}

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

# Tests dot-source this script with MG_INSTALL_SKIP_ENTRYPOINT=1 to exercise
# the functions without running the install flow.
if (-not $env:MG_INSTALL_SKIP_ENTRYPOINT) {
try {
  if ($BackupPath) {
    Invoke-BackupPathMode
  } elseif ($BackupUrl) {
    Invoke-BackupUrlMode
  } else {
    Invoke-MainFlow
  }
  Write-Host ''
  Write-Ok 'Merlin Guild is ready. Launch it from the start menu.'
  Write-Host ''
} catch {
  Write-Host ''
  Write-Fail $_.Exception.Message
  Write-Host ''
  exit 1
}
}
