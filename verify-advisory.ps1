#Requires -Version 5.1
<#
.SYNOPSIS
  Verifies a detached RSA-PSS / SHA-256 signature for a transparency artifact.

.DESCRIPTION
  Reads the payload file (e.g. advisories.json), the detached signature file
  (.sig, base64url text), and the advisory public key (PEM SPKI), then
  verifies the signature using .NET RSACng.

.PARAMETER PayloadPath
  Path to the payload file. Default: advisories.json

.PARAMETER SigPath
  Path to the detached signature file. Default: <PayloadPath>.sig

.PARAMETER KeyPath
  Path to the RSA-2048 / SPKI public-key PEM file.
  Default: auto-discover merlinguild-advisory-*.pub in the repo root

.EXAMPLE
  .\verify-advisory.ps1
  .\verify-advisory.ps1 -PayloadPath advisories.json -KeyPath merlinguild-advisory-2026-05.pub
#>

[CmdletBinding()]
param(
  [string]$PayloadPath = "advisories.json",
  [string]$SigPath = "",
  [string]$KeyPath = ""
)

$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

function ConvertFrom-Base64Url {
  param([string]$Value)
  $s = $Value.Replace('-', '+').Replace('_', '/')
  $pad = 4 - ($s.Length % 4)
  if ($pad -ne 4) { $s += '=' * $pad }
  return [System.Convert]::FromBase64String($s)
}

# --- PS 5.1-compatible SPKI import (RSACng.ImportSubjectPublicKeyInfo does not
# --- exist on .NET Framework): walk the DER and import modulus/exponent.
function Read-DerElement {
  param([byte[]]$Data, [ref]$Offset)
  $tag = $Data[$Offset.Value]; $Offset.Value += 1
  $len = [int]$Data[$Offset.Value]; $Offset.Value += 1
  if ($len -band 0x80) {
    $n = $len -band 0x7f
    $len = 0
    for ($i = 0; $i -lt $n; $i++) {
      $len = ($len -shl 8) + [int]$Data[$Offset.Value]
      $Offset.Value += 1
    }
  }
  $value = New-Object byte[] $len
  [Array]::Copy($Data, $Offset.Value, $value, 0, $len)
  $Offset.Value += $len
  return @{ Tag = $tag; Value = $value }
}

function ConvertTo-RsaPublicKeyParameters {
  param([byte[]]$Spki)
  $o = 0
  $outer = Read-DerElement -Data $Spki -Offset ([ref]$o)
  $i = 0
  $null = Read-DerElement -Data $outer.Value -Offset ([ref]$i)   # algorithm identifier
  $bitString = Read-DerElement -Data $outer.Value -Offset ([ref]$i)
  if ($bitString.Tag -ne 0x03) { throw "Corrupt trusted key material (no BIT STRING in SPKI)." }
  $rsaKeyDer = $bitString.Value[1..($bitString.Value.Length - 1)]  # skip unused-bits byte
  $j = 0
  $rsaSeq = Read-DerElement -Data $rsaKeyDer -Offset ([ref]$j)
  $k = 0
  $modInt = Read-DerElement -Data $rsaSeq.Value -Offset ([ref]$k)
  $expInt = Read-DerElement -Data $rsaSeq.Value -Offset ([ref]$k)

  $modulus = $modInt.Value
  if ($modulus.Length -gt 1 -and $modulus[0] -eq 0) { $modulus = $modulus[1..($modulus.Length - 1)] }
  $exponent = $expInt.Value
  if ($exponent.Length -gt 1 -and $exponent[0] -eq 0) { $exponent = $exponent[1..($exponent.Length - 1)] }

  $params = New-Object System.Security.Cryptography.RSAParameters
  $params.Modulus = $modulus
  $params.Exponent = $exponent
  return $params
}

function Resolve-RepoRoot {
  # The script lives in the repository root, next to the public keys.
  $scriptDir = Split-Path -Parent $MyInvocation.ScriptName
  if (-not $scriptDir) { $scriptDir = $PSScriptRoot }
  if (-not $scriptDir) { $scriptDir = (Get-Location).Path }
  return Resolve-Path $scriptDir
}

function Get-AdvisoryKeyPath {
  param([string]$RepoRoot)
  # Keys live in the repo root; public-keys/ is kept as a legacy fallback.
  $keys = Get-ChildItem -Path $RepoRoot -Filter "merlinguild-advisory-*.pub" -ErrorAction SilentlyContinue
  if (-not $keys) {
    $pubDir = Join-Path $RepoRoot "public-keys"
    $keys = Get-ChildItem -Path $pubDir -Filter "merlinguild-advisory-*.pub" -ErrorAction SilentlyContinue
  }
  $sorted = $keys | Sort-Object Name
  if (-not $sorted) { throw "No advisory public key found in $RepoRoot" }
  return $sorted[0].FullName
}

# ---------------------------------------------------------------------------
# Resolve paths
# ---------------------------------------------------------------------------

$PayloadPath = Resolve-Path $PayloadPath

if (-not $SigPath) {
  $SigPath = $PayloadPath + ".sig"
}
$SigPath = Resolve-Path $SigPath

if (-not $KeyPath) {
  $repoRoot = Resolve-RepoRoot
  $KeyPath = Get-AdvisoryKeyPath -RepoRoot $repoRoot
}
$KeyPath = Resolve-Path $KeyPath

Write-Verbose "Payload : $PayloadPath"
Write-Verbose "Sig     : $SigPath"
Write-Verbose "Key     : $KeyPath"

# ---------------------------------------------------------------------------
# Read files
# ---------------------------------------------------------------------------

$payloadBytes = [System.IO.File]::ReadAllBytes($PayloadPath)

$sigB64url = [System.IO.File]::ReadAllText($SigPath, [System.Text.UTF8Encoding]::new($false)).Trim()
if (-not $sigB64url) { throw "Signature file is empty: $SigPath" }
$sigBytes = ConvertFrom-Base64Url -Value $sigB64url

$pemText = [System.IO.File]::ReadAllText($KeyPath, [System.Text.UTF8Encoding]::new($false))
$pemLines = $pemText -split "`r?`n" | Where-Object { -not $_.StartsWith("-----") } | Where-Object { $_.Trim() -ne "" }
$spkiB64 = $pemLines -join ""
$spkiBytes = [System.Convert]::FromBase64String($spkiB64)

# ---------------------------------------------------------------------------
# Verify RSA-PSS (SHA-256, salt length = hash length = 32 bytes)
# ---------------------------------------------------------------------------

# RSACng exists only on Windows; the RSA.Create() fallback keeps the script
# runnable on Linux CI runners (pwsh without the CNG assembly).
if ($env:OS -eq 'Windows_NT') {
  $rsa = New-Object System.Security.Cryptography.RSACng
} else {
  $rsa = [System.Security.Cryptography.RSA]::Create()
}
try {
  $rsa.ImportParameters((ConvertTo-RsaPublicKeyParameters -Spki $spkiBytes))

  $valid = $rsa.VerifyData(
    $payloadBytes,
    $sigBytes,
    [System.Security.Cryptography.HashAlgorithmName]::SHA256,
    [System.Security.Cryptography.RSASignaturePadding]::Pss
  )

  if ($valid) {
    Write-Host "Signature VALID." -ForegroundColor Green
    exit 0
  }
  else {
    Write-Error "Signature INVALID."
    exit 1
  }
}
catch {
  Write-Error "Verification failed: $_"
  exit 2
}
finally {
  $rsa.Dispose()
}
