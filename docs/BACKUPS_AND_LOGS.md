# Backups, retention and log rotation

## What gets backed up, and where

Every time a session log is **sealed** (`.dat` -> AES-256-GCM `.vault` +
`.vault.sig`), `VaultBackupManager` copies the sealed pair into the dedicated
backup directory:

```
%ProgramData%\CheatGuard\vault-backup\
```

Hard guarantees:

- **Only encrypted material is ever copied.** A plaintext `.dat` is refused
  with a log line; the plaintext never leaves the vault directory.
- **Atomic writes.** Each copy goes to a uniquely named `.part-*.tmp` file
  and is moved into place with an atomic move. A power cut mid-copy leaves a
  `.part-` leftover, never a half-written "real" backup; stale leftovers are
  removed on the next backup run.
- **The active vault is never touched.** Pruning only ever deletes files
  inside `vault-backup\`; the live vault directory and current logs are never
  candidates.
- **Failures never crash an exam.** Disk-full, permission denied and
  file-locked errors are logged through `AppLog` and swallowed; the seal
  itself has already succeeded before the backup starts.

## Retention (configurable)

Config values in `whitelist.properties`:

| Key | Default | Meaning |
|---|---|---|
| `backup.retention.count` | `30` | keep the newest N vault backups (`0` = unlimited) |
| `backup.retention.days` | `90` | delete backups older than N days (`0` = no age limit) |

Both limits apply together; expired vault backups take their `.sig` files
with them. Re-running a backup for the same vault is idempotent (it replaces
the previous copy instead of accumulating duplicates).

## Diagnostic log rotation

`AppLog` diagnostics (development/support logs - separate from sealed audit
vaults) live in `%ProgramData%\CheatGuard\logs\`:

- one file per day, `cheatguard-YYYY-MM-DD.log`
- a day file that grows past the size limit rolls into
  `cheatguard-YYYY-MM-DD.1.log`, `.2.log`, ... (newest roll has the lowest
  number)
- files older than 14 days are pruned

Tuning via system properties (defaults in parentheses):

| Property | Meaning |
|---|---|
| `cheatguard.logs.max.bytes` (5 MiB) | roll size for a day file |
| `cheatguard.logs.roll.count` (3) | rolls kept per day |

Audit material (sealed `.vault` files) and diagnostics (`logs\`) are separate
directories and never mixed.

## Tests

`test/BackupRotationTest.java` (headless, part of CI) covers: backup
creation, decryption of the backup copy (integrity), plaintext refusal,
duplicate-safe re-backup, retention by count and by age, active-vault
safety, interrupted-backup recovery and diagnostic rotation.
