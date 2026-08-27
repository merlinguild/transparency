Describe 'install.ps1 backup modes and license retry' {
    BeforeAll {
        $script:InstallScript = Join-Path $PSScriptRoot 'install.ps1'
        $env:MG_INSTALL_SKIP_ENTRYPOINT = '1'
        . $script:InstallScript

        $script:FixtureDir = New-Item -ItemType Directory -Path (Join-Path $TestDrive 'install') -Force
        # Redirect the script-scoped state into TestDrive
        $Script:LicensePath  = Join-Path $script:FixtureDir 'license'
        $Script:SequencePath = Join-Path $script:FixtureDir '.sequence'
    }

    AfterAll {
        Remove-Item Env:MG_INSTALL_SKIP_ENTRYPOINT -ErrorAction SilentlyContinue
    }

    Context 'Save-License' {
        It 'creates the directory and writes the JWT without a UTF-8 BOM' {
            $nested = Join-Path $script:FixtureDir ('save-' + [Guid]::NewGuid().ToString('N'))
            $Script:LicensePath = Join-Path $nested 'license'

            Save-License -Jwt 'test.jwt.value'

            Test-Path $Script:LicensePath | Should -BeTrue
            $bytes = [IO.File]::ReadAllBytes($Script:LicensePath)
            $bytes[0] | Should -Be 116
            [IO.File]::ReadAllText($Script:LicensePath) | Should -Be 'test.jwt.value'
        }
    }

    Context 'Invoke-BackupPathMode' {
        It 'installs the resolved local MSI path' {
            $msi = Join-Path $script:FixtureDir 'local.msi'
            [IO.File]::WriteAllText($msi, 'fake msi')
            Mock Install-Msi {}

            Invoke-BackupPathMode -Path $msi

            Should -Invoke Install-Msi -Times 1 -Exactly
            Should -Invoke Install-Msi -ParameterFilter { $MsiPath -eq $msi }
        }

        It 'throws when the backup path resolves to a directory' {
            Mock Install-Msi {}

            { Invoke-BackupPathMode -Path $script:FixtureDir } | Should -Throw 'MSI not found*'
            Should -Invoke Install-Msi -Times 0
        }
    }

    Context 'Invoke-BackupUrlMode' {
        It 'downloads to a temp MSI, installs it, and removes the temp file' {
            $script:downloadedPath = $null
            Mock Invoke-WebRequest {
                $script:downloadedPath = $OutFile
                [IO.File]::WriteAllText($OutFile, 'fake msi bytes')
            }
            Mock Install-Msi {}

            Invoke-BackupUrlMode -Url 'https://backup.example.com/app.msi'

            Should -Invoke Invoke-WebRequest -Times 1 -ParameterFilter {
                $Uri -eq 'https://backup.example.com/app.msi'
            }
            Should -Invoke Install-Msi -Times 1 -ParameterFilter {
                $MsiPath -eq $script:downloadedPath
            }
            $script:downloadedPath | Should -Not -BeNullOrEmpty
            Test-Path $script:downloadedPath | Should -BeFalse
        }

        It 'propagates a download failure without installing' {
            Mock Invoke-WebRequest { throw '404' }
            Mock Install-Msi {}

            { Invoke-BackupUrlMode -Url 'https://backup.example.com/app.msi' } | Should -Throw '404'
            Should -Invoke Install-Msi -Times 0
        }
    }

    Context 'Invoke-MainFlow license re-prompt retry' {
        BeforeAll {
            $script:FakeMsi = Join-Path $script:FixtureDir 'payload.msi'
            [IO.File]::WriteAllText($script:FakeMsi, 'fake msi payload')
            $script:FakeHash = (Get-FileHash -Algorithm SHA256 -Path $script:FakeMsi).Hash.ToLower()

            $script:ManifestPath = Join-Path $script:FixtureDir 'manifest.json'
            $manifest = @{
                expires_at = '2099-01-01T00:00:00Z'
                channels   = @{
                    stable = @{
                        sequence  = 1
                        artifacts = @{
                            windows_x64 = @{
                                url    = 'https://dl.test/releases/app.msi'
                                sha256 = $script:FakeHash
                            }
                        }
                    }
                }
            }
            [IO.File]::WriteAllText($script:ManifestPath, ($manifest | ConvertTo-Json -Depth 6))
            $script:SigPath = "$($script:ManifestPath).sig"
            [IO.File]::WriteAllText($script:SigPath, 'ZmFrZS1zaWc')
        }

        BeforeEach {
            Remove-Item $Script:LicensePath -Force -ErrorAction SilentlyContinue
            Remove-Item $Script:SequencePath -Force -ErrorAction SilentlyContinue
            $script:receiveJwts = @()
            $script:readCount = 0
        }

        It 're-prompts and retries with the new license after a 401 rejection' {
            Mock Get-Manifest { @{ JsonPath = $script:ManifestPath; SigPath = $script:SigPath } }
            Mock Assert-ManifestSignature {}
            Mock Read-License {
                $script:readCount++
                if ($script:readCount -eq 1) { return 'jwt-first' }
                return 'jwt-second'
            }
            Mock Receive-Msi {
                $script:receiveJwts += $Jwt
                if ($script:receiveJwts.Count -eq 1) {
                    throw 'Worker rejected the license (401). The JWT may be expired, revoked, or invalid.'
                }
                Copy-Item $script:FakeMsi $OutPath
            }
            Mock Install-Msi {}

            Invoke-MainFlow

            # initial prompt + re-prompt after the rejection
            Should -Invoke Read-License -Times 2 -Exactly
            # retry used the second license
            $script:receiveJwts | Should -Be @('jwt-first', 'jwt-second')
            # the winning license is persisted
            (Get-License) | Should -Be 'jwt-second'
            # install proceeded and the sequence marker was written
            Should -Invoke Install-Msi -Times 1
            (Get-Content $Script:SequencePath) -contains 'stable=1' | Should -BeTrue
            # manifest temp files are cleaned up
            Test-Path $script:ManifestPath | Should -BeFalse
            Test-Path $script:SigPath | Should -BeFalse
        }

        It 'uses the stored license without prompting' {
            [IO.File]::WriteAllText($Script:LicensePath, 'jwt-stored')
            Mock Get-Manifest { @{ JsonPath = $script:ManifestPath; SigPath = $script:SigPath } }
            Mock Assert-ManifestSignature {}
            Mock Read-License { throw 'must not prompt' }
            Mock Receive-Msi {
                $script:receiveJwts += $Jwt
                Copy-Item $script:FakeMsi $OutPath
            }
            Mock Install-Msi {}

            # manifest was cleaned by the previous test; recreate fixtures
            if (-not (Test-Path $script:ManifestPath)) {
                $manifest = @{
                    expires_at = '2099-01-01T00:00:00Z'
                    channels   = @{ stable = @{ sequence = 1; artifacts = @{ windows_x64 = @{ url = 'https://dl.test/releases/app.msi'; sha256 = $script:FakeHash } } } }
                }
                [IO.File]::WriteAllText($script:ManifestPath, ($manifest | ConvertTo-Json -Depth 6))
                [IO.File]::WriteAllText($script:SigPath, 'ZmFrZS1zaWc')
            }

            Invoke-MainFlow

            Should -Invoke Read-License -Times 0
            $script:receiveJwts | Should -Be @('jwt-stored')
        }
    }
}
