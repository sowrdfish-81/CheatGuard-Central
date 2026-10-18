# CheatGuard Central

CheatGuard Central is a Windows desktop application for supervised online exams. It provides process control, website allowlisting, file-access restrictions, device monitoring, protected audit logs, and authenticated central monitoring.

## Current release

Version: **1.8**
Release: [v1.8](https://github.com/sowrdfish-81/CheatGuard-Central/releases/tag/v1.8)

Release assets:

- `CheatGuardCentral-Setup.exe`
- `CheatGuardCentral-Setup.exe.sha256`

Installer SHA-256:

```text
0eb9c5d2086390e4acdf79957c5d0e96a7e8ffa3b894838e5551ce684e0654ad
```

## Features

- Process monitoring with startup cleanup and unauthorized-process enforcement.
- DNS-layer website allowlisting with IPv4/IPv6 handling and DoH restrictions.
- Exam-folder boundaries for supported applications and interpreters.
- NTFS-based file-access restrictions during an active session.
- USB, network-adapter, and portable-device monitoring.
- Protected audit logs with authenticated AES-256-GCM encryption for new vaults.
- Backward-compatible reading and migration support for legacy vaults.
- PBKDF2-HMAC-SHA256 administrator credentials with lockout protection.
- HMAC challenge-response authentication for central monitor events.
- Proxy, VPN, remote-control, tunnel-port, and raw-egress protections.
- Recovery support for interrupted sessions and abnormal shutdowns.
- Non-blocking UI handling for UAC, sealing, diagnostics, and log operations.

## Requirements

- Windows 10 or later.
- JDK 17 or later for development and packaging.
- WiX Toolset 3.x for installer packaging. `build-installer.bat` automatically detects a repository-local copy under `tools\wix` or a WiX installation on `PATH`.
- Administrator privileges for installer execution and protected session operations.

## Build the installer

From the repository root, run:

```bat
build-installer.bat
```

The build produces:

```text
dist\CheatGuardCentral-Setup.exe
dist\CheatGuardCentral-Setup.exe.sha256
```

The installer contains the application and its bundled runtime. WiX binaries are build tooling and are intentionally not committed to the repository.

## Run the tests

The test suite runs headlessly with an isolated data directory:

```powershell
$sources = Get-ChildItem src -Recurse -Filter *.java | ForEach-Object FullName
New-Item -ItemType Directory -Force bin, testbin | Out-Null
javac -encoding UTF-8 -d bin $sources
javac -encoding UTF-8 -cp bin -d testbin test\CoreFlowTest.java test\SecurityUpgradeTest.java test\UpdateCheckerTest.java
java -Djava.awt.headless=true -Dcheatguard.data.dir="$PWD\test-data" -cp "bin;testbin" CoreFlowTest
java -Djava.awt.headless=true -Dcheatguard.data.dir="$PWD\test-data" -cp "bin;testbin" SecurityUpgradeTest
java -Djava.awt.headless=true -Dcheatguard.data.dir="$PWD\test-data" -cp "bin;testbin" UpdateCheckerTest
```

The tests cover core session flow, credential persistence, vault encryption and tamper rejection, central-monitor authentication, updater verification, and recovery behavior. Test data is isolated from the user profile.

## Repository layout

```text
src\com\cheatguard\       Application source
  config\                  Configuration and update handling
  core\                    Sessions, logs, and violations
  gui\                     Desktop UI and workflows
  security\                Credentials, vaults, and integrity controls
  watchdog\                Process, network, and device enforcement
resources\                 Elevated PowerShell helpers and resources
support\                   Recovery and diagnostics utilities
test\                      Headless verification tests
build-installer.bat        Installer build and checksum generation
PROJECT_REPORT.md          Current implementation and verification report
```

## Operational workflow

1. Install `CheatGuardCentral-Setup.exe` with administrator privileges.
2. Set the administrator password on first launch.
3. Configure approved applications and exam websites.
4. Start a session with the course and student information.
5. End the session and seal the audit log from the dashboard.

If a session ends unexpectedly, use the installed recovery utility or relaunch the application as an administrator. Diagnostics are available through the installed `diagnostics.bat` utility.

## Security boundaries

CheatGuard is designed to enforce policy against a signed-in standard student account. It cannot protect against a person who has the local administrator password, physical access to another device, or a communication path that cannot be distinguished from an approved endpoint. These limitations are documented so deployment decisions remain explicit.

## License

No license file is currently published in this repository. All rights are reserved unless a separate license is provided by the project owner.
