# Security policy

This policy covers Merlin Guild and its distribution infrastructure: the bootstrap installer, the signed release manifest, the download service, and the advisory feed.

## Reporting a vulnerability

We welcome reports from security researchers, integrators, and users.

### Contact

- **Email:** `security@merlinguild.com`. PGP-encrypted reports are preferred.
- **PGP key:** [merlinguild-security-pgp-2026-05.pub.asc](merlinguild-security-pgp-2026-05.pub.asc) (Ed25519 / Curve25519) in the repository root.
- **security.txt:** per RFC 9116, available at [merlinguild.com/.well-known/security.txt](https://merlinguild.com/.well-known/security.txt).
- **Fallback:** if the primary contact is unavailable for more than 7 days, use the contact listed in security.txt.
- Please do not open public issues or discuss report details publicly before the coordinated disclosure window closes.

### What to include

A useful report contains:

- Affected version (CalVer, e.g. `26.4.1`).
- Affected component (cryptographic core, distribution pipeline, license verification, advisory feed, etc.).
- Reproduction steps or proof-of-concept.
- Impact assessment.
- Suggested remediation, if any.
- Whether you intend to publish; preferred coordinated disclosure timeline.

### Response targets

These are targets for a solo maintainer, not contractual SLAs. There is no paid bug bounty at this time.

| Stage | Target |
| --- | --- |
| Acknowledge receipt. | 72 hours. |
| Triage and severity assessment. | 7 days. |
| Fix for CRITICAL or HIGH. | 7 days from triage, best effort. |
| Fix for MEDIUM. | Next scheduled release. |
| Fix for LOW. | Best effort, next feature release. |
| Coordinated disclosure window. | 90 days from initial report. |

If a vulnerability is actively exploited in the wild, the timeline collapses: fix and notification within 24 to 72 hours.

### Safe harbour

We will not pursue legal action against researchers acting in good faith who:

- Do not access user data beyond what is necessary to demonstrate the vulnerability.
- Do not modify or destroy data.
- Do not disrupt service for other users.
- Disclose responsibly per the timeline above.

## Supported versions

Merlin Guild ships an evergreen rolling release: a single current build, no maintenance branches, no backports.

| Status | Definition | Support |
| --- | --- | --- |
| Current | Latest release. | Full security and feature support. |
| Older | Any earlier release. | No dedicated fixes; install the latest release, which stays free for security updates. |

## Vulnerability handling process

1. **Receipt and acknowledgement:** within 72 hours.
2. **Triage:** within 7 days; severity per CVSS 3.1 and exploit status.
3. **Fix development:** root cause analysis, regression test, and a VEX statement for affected dependency CVEs where applicable.
4. **CVE assignment:** for HIGH and CRITICAL, via GitHub Security Advisory.
5. **Release and signing:** the fix ships in the next release; all artifacts are signed.
6. **User notification:** an entry is added to the signed advisories.json feed, published simultaneously to the download host and to this repository. Critical advisories surface as a blocking dialog in-app.
7. **Public disclosure:** the full advisory is published in advisories/MG-SEC-YYYY-NNNN.md after the coordinated disclosure window, or earlier if mutually agreed.
8. **Reporter acknowledgement:** credit in the advisory, with consent.

## Verifying releases

The installer verifies before it executes: install.ps1 checks the detached signature of manifest.json against the pinned manifest public key, then the SHA-256 of the downloaded installer against the manifest. Release public keys (license, advisory, manifest) live in the repository root. The advisory feed can be verified with verify-advisory.ps1.

## Out of scope

- Defects in the operating system or hardware that bypass application-level cryptography.
- Active malware, keyloggers, or screen capture on the device while the vault is unlocked.
- Theft of the master password through social engineering.
- Loss of the recovery key combined with loss of the original device.
- Findings in third-party dependencies declared not_affected in our VEX document.
- Findings in test infrastructure, the marketing site, or internal tooling not shipped to users.
- Attacks that already require arbitrary code execution on the device.

These reports are still welcome: they inform hardening guidance, but they do not trigger the response targets above.
