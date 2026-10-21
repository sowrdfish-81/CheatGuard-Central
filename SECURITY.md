# Security Policy

## Supported version

| Version | Supported |
|---|---|
| 1.9.x | yes |
| < 1.9 | upgrade - the auto-updater or the latest release installer |

## Reporting a vulnerability

Email the maintainer via GitHub (sowrdfish-81) or open a GitHub **private
security advisory** on this repository ("Security" tab → "Report a
vulnerability"). Do NOT open a public issue for anything exploitable.

Include: affected version, what an attacker could achieve, and how you
confirmed it. You will get an acknowledgement within 7 days and a fix or a
mitigation plan within 30 days for accepted reports.

## What is in scope

- Bypassing or weakening the exam lockdown (process, network/DNS, file-wall,
  device monitoring) without the administrator password.
- Breaking the sealed-vault guarantees: reading a vault without the admin
  password, tampering without detection, deleting protected logs.
- Defeating central-monitor transport security: TLS validation, the HMAC
  challenge-response, exam-code isolation between simultaneous exams.
- Privilege escalation through the elevated helper scripts or fail-safe
  mechanisms.

## Out of scope

- Physical attacks (photographing the screen, using a second device beside
  the keyboard).
- A student who owns the machine's ADMINISTRATOR account pre-exam; the threat
  model is a standard-user exam PC supervised by an invigilator. Machine
  preparation guidance is documented in the README.
- Denial of service against the invigilator's monitor from off-LAN.

## Security model summary

- Machine state lives under `%ProgramData%\CheatGuard`, owned by
  Administrators; the exam-time user is a standard user.
- Session logs are sealed to AES-256-GCM vaults with a signature file; new
  vaults are authenticated-encrypted, legacy vaults remain readable.
- Admin credentials are PBKDF2-HMAC-SHA256 with lockout; passwords are
  handled as `char[]` and wiped.
- Central monitoring: TLS 1.2/1.3 with full certificate validation
  (PKCS12 keystore on the monitor, truststore on clients, SAN check) plus
  HMAC challenge-response keyed by the per-exam code. Plaintext transport
  requires an explicit dev flag and shows a persistent warning.
- A permanent fail-safe task self-heals leftover lockdown at boot/logon.

Secrets policy: no certificate, password or key material is ever committed;
CI receives the signing certificate only as base64 secrets, decodes it in the
runner temp folder, and deletes it in a `finally` block.
