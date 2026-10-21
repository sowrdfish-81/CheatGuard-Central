## What does this PR do?

<!-- One paragraph: the problem and the change. -->

## Motivation / linked issue

<!-- Link the issue, or explain why this change is needed. -->

## Type of change

- [ ] Bug fix (no behavior change beyond the fix)
- [ ] New feature
- [ ] Security hardening
- [ ] Documentation only
- [ ] Refactor (no behavior change)

## Security checklist

- [ ] No secrets, certificates, keystores, installers or build output committed
- [ ] Certificate validation and HMAC authentication untouched (or strengthened)
- [ ] No new plaintext transport path; no trust-all / disabled validation
- [ ] Plaintext passwords never logged, printed, or passed on command lines
- [ ] Existing sealed vaults and configs remain readable (backward compatible)

## Verification

<!-- Report what you ACTUALLY ran and the result. CI must be green. -->

- [ ] `build-installer.bat` completes; installer + `.sha256` produced
- [ ] All five headless suites pass (`CoreFlowTest`, `SecurityUpgradeTest`,
      `UpdateCheckerTest`, `CentralTlsTest`, `BackupRotationTest`)
- [ ] `test\ps1-syntax-check.ps1` passes
- [ ] `git diff --check` clean
- [ ] Integration tests on the Windows VM runner (only if this touches
      installer / lockdown / restore behavior - otherwise mark N/A)

## Screenshots / output

<!-- If UI or log output changed, paste before/after. -->
