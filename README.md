# transparency

This repository hosts the Merlin Guild installer and its signed transparency artifacts: the release manifest, the security advisory feed, and the public signing keys that verify them.

- **install.ps1**: Windows (PowerShell 5.1+).

## Audit documentation

This repository also contains public audit artifacts:

- **Public keys**: RSA-2048 / RSA-PSS license, advisory, and manifest signing keys.
- **Compliance artifacts**: security advisories, ENISA reports (future).

See the main project documentation for details on the supply chain architecture.

## Transparency artifacts

This repository is the canonical mirror of the signed advisory feed also published on dl.merlinguild.com:

| File | Purpose | Signing key | Schema |
| --- | --- | --- | --- |
| advisories.json | Security advisories | Advisory key | advisories.schema.json |

Each artifact is paired with an RSA-2048 / RSA-PSS detached signature (<file>.sig). Verify with the corresponding public key (merlinguild-<role>-<date>.pub) in the repo root.

> [!IMPORTANT]
> SBOM (sbom.cdx.json) and VEX (vex.json) are not published in this repository. They are stored in the manufacturer-controlled repository and provided to regulators or enterprise deployers on authenticated request.

### Verifying advisories.json

Run `verify-advisory.ps1` from the repository root; it auto-discovers the advisory public key:

```powershell
./verify-advisory.ps1 -PayloadPath advisories.json
```

### Per-advisory details

Long-form advisories live in `advisories/MG-SEC-YYYY-NNNN.md` and are referenced from each
record's `details_url` field.

## How it works

The installers use a **manifest-based supply chain** with cryptographic verification:

1. **Bootstrap:** the installer downloads manifest.json + manifest.json.sig from dl.merlinguild.com.
2. **Verification:** the manifest signature is verified in-process using RSA-2048 / RSA-PSS (Windows).
3. **License:** the installer prompts for a JWT license and validates it with the download service.
4. **Download:** the download service returns a short-lived URL for the installer.
5. **Install:** the installer verifies the MSI SHA-256 against the manifest, then runs the platform-native installer.

## Install

### One-liner (recommended)

```powershell
iwr https://dl.merlinguild.com/install.ps1 -UseBasicParsing | iex
```

The installer will prompt you for your license JWT.

### Local file mode

```powershell
.\install.ps1 -BackupPath .\merlinguild_26.8.0_x64_en-US.msi
```

Bypasses network and verification checks. Used for smoke-testing a fresh
`cargo tauri build` on the developer's own machine.

### Break-glass mode

```powershell
$env:BACKUP_URL = 'https://share.example.com/mg-26.8.0.msi'
iwr https://dl.merlinguild.com/install.ps1 -UseBasicParsing | iex
```

> [!WARNING]
> This path bypasses license verification, the signed manifest flow, and rollback protection. Use only with URLs received over a verified channel (signed Telegram message, in-person USB, etc.).

### Parameters

| Flag | Purpose |
|------------|---------|
| `-Channel <name>` or `$env:CHANNEL` | Release channel (default: stable). |
| `-BackupPath <msi>` or `$env:BACKUP_PATH` | Install a local file. |
| `-BackupUrl <url>` or `$env:BACKUP_URL` | Install from any URL (break-glass). |
| `-MinimumSequence <int>` or `$env:MINIMUM_SEQUENCE` | Embedded anti-rollback floor. |
