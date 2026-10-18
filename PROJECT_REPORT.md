# CheatGuard Central — v1.8 Project Report

## Scope

This report records the current implementation, security hardening, verification status, and release artifacts for CheatGuard Central v1.8. It replaces historical implementation notes that no longer describe the repository.

## Product summary

CheatGuard Central is a Windows Java desktop application for supervised online exams. The application controls approved processes, restricts network access to approved websites, monitors removable devices, limits access to files outside the exam workspace, and creates protected session records.

## Implemented controls

### Session enforcement

- Starts with a clean process state and closes unauthorized applications.
- Monitors process identity using PID and process start time to avoid PID-reuse errors.
- Detects hidden or headless processes launched from student-writable locations.
- Enforces exam-folder boundaries for supported applications and interpreters.
- Records routine enforcement, blocked actions, and security alerts separately.

### Network enforcement

- Provides DNS-layer website allowlisting for IPv4 and IPv6 adapters.
- Disables browser DNS-over-HTTPS paths and blocks common bypass routes.
- Applies proxy/PAC restrictions during active sessions and restores the prior state.
- Blocks common VPN, tunnel, remote-control, RDP, VNC, QUIC, and IPsec ports.
- Uses an outbound web policy tied to addresses resolved through the approved filter.
- Refuses unsafe IPv6 configurations instead of silently filtering only IPv4.
- Falls back safely when full egress enforcement cannot be established and records the active mode.

### File and device controls

- Applies session-scoped NTFS restrictions outside the approved exam workspace.
- Restores file permissions when the session ends or is recovered.
- Monitors USB storage, portable devices, and network-adapter changes.
- Clears recent-file surfaces and clipboard history at session start.

### Security and integrity

- Stores sensitive state under `C:\ProgramData\CheatGuard` rather than the student profile.
- Uses PBKDF2-HMAC-SHA256 administrator credential protection with escalating lockout.
- Uses authenticated AES-256-GCM for new vaults.
- Reads legacy CBC vaults and migrates them when they are sealed again.
- Uses ACL hardening for protected logs and control files.
- Sanitizes log input to prevent forged audit entries.
- Uses nonce-based HMAC challenge-response authentication for central-monitor events.
- Prevents student tampering with the elevated helper, allowlist, credential store, and stop marker.

### Recovery and operations

- Detects stale sessions and performs controlled recovery.
- Provides emergency network restoration and diagnostics utilities.
- Keeps UAC, sealing, log operations, and diagnostics off the UI thread.
- Clears dashboard password fields after sensitive operations.

## Verification

The repository was tested outside the user's installed application environment using isolated build and test directories.

Verified checks:

- Main Java source compilation.
- Test source compilation.
- `CoreFlowTest` — session, credential, vault, DNS, and scanner flow.
- `SecurityUpgradeTest` — AES-GCM integrity and central HMAC authentication.
- `UpdateCheckerTest` — updater URL, checksum, and release verification behavior.
- PowerShell helper syntax validation.
- Installer packaging with WiX Toolset 3.x.
- Installer checksum generation and independent SHA-256 verification.
- `git diff --check`.

All checks passed for the v1.8 release build.

## Release artifacts

| Artifact | Location | Status |
| --- | --- | --- |
| Installer | `dist\CheatGuardCentral-Setup.exe` | Built and published |
| Checksum | `dist\CheatGuardCentral-Setup.exe.sha256` | Built and published |
| Release | GitHub `v1.8` | Public and marked latest |

Installer SHA-256:

```text
0eb9c5d2086390e4acdf79957c5d0e96a7e8ffa3b894838e5551ce684e0654ad
```

## Known boundaries

The client cannot reliably distinguish every HTTPS proxy or tunnel that shares an approved CDN address. It cannot prevent screen capture, photography, or activity performed using a separate device. A local administrator can override client-side controls. These are deployment limitations, not unreported test failures.

## Maintenance rules

- Keep installer filenames and checksum references synchronized across `README.md`, `build-installer.bat`, and release assets.
- Update the version in `UpdateChecker.java` and `build-installer.bat` together.
- Run the isolated test suite before every release.
- Publish the installer and its matching `.sha256` asset together.
- Do not commit WiX binaries, generated build directories, test data, or release installers unless explicitly required.
