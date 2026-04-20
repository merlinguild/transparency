Describe 'verify-advisory.ps1 on Windows PowerShell 5.1' {
    BeforeAll {
        $RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '..\..')
        Import-Module (Join-Path $RepoRoot 'packages\signing-tools\mg-signing.psm1') -Force
        $script:VerifyScript = Join-Path $RepoRoot 'packages\transparency\verify-advisory.ps1'

        $script:FixtureDir = New-Item -ItemType Directory -Path (Join-Path $TestDrive 'verify-advisory') -Force
        $script:Key = [System.Security.Cryptography.RSACng]::new(2048)

        $script:PubPath = Join-Path $script:FixtureDir 'advisory-test.pub'
        [System.IO.File]::WriteAllText($script:PubPath, (Export-MgPublicKeyPem -Key $script:Key))

        $script:PayloadPath = Join-Path $script:FixtureDir 'advisories.json'
        [System.IO.File]::WriteAllText($script:PayloadPath, '[]')
        $sig = New-MgDataSignature -Key $script:Key -Data ([System.IO.File]::ReadAllBytes($script:PayloadPath)) -Format base64url
        [System.IO.File]::WriteAllText("$($script:PayloadPath).sig", $sig)
    }

    AfterAll {
        if ($script:Key) { $script:Key.Dispose() }
    }

    It 'Verifies a known-good detached signature (exit 0)' {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $script:VerifyScript -PayloadPath $script:PayloadPath -KeyPath $script:PubPath | Out-Null
        $LASTEXITCODE | Should -Be 0
    }

    It 'Rejects a tampered payload (exit 1)' {
        $tampered = Join-Path $script:FixtureDir 'tampered.json'
        [System.IO.File]::WriteAllText($tampered, '[{"advisory_id":"MG-SEC-2026-0001"}]')
        [System.IO.File]::Copy("$($script:PayloadPath).sig", "$tampered.sig")

        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $script:VerifyScript -PayloadPath $tampered -KeyPath $script:PubPath | Out-Null
        $LASTEXITCODE | Should -Be 1
    }
}
