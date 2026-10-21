package com.cheatguard.security;

import java.io.File;
import java.io.FileWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Arrays;

/**
 * Encryption/tamper facade for sealed logs plus admin-gated access/deletion.
 *
 * <p>Every method takes the administrator password as a {@code char[]} and wipes
 * its working copy before returning, so the plaintext password does not outlive
 * the call in a String or a leaked buffer.
 */
public class SecurityVault {
    private final FileLockManager lockManager = new FileLockManager();
    private final AesEncryptor encryptor = new AesEncryptor();
    private final Sha256Signer signer = new Sha256Signer();
    private final AdminAuth adminAuth;

    public SecurityVault(AdminAuth adminAuth) { this.adminAuth = adminAuth; }

    public boolean beginProtection(File plaintextLogFile) { return lockManager.lockFile(plaintextLogFile); }

    /** Release an in-progress log lock when session startup is rolled back. */
    public void abortProtection() { lockManager.releaseLock(); }

    public void sealVault(File plaintextLogFile, char[] adminPassword) throws Exception {
        lockManager.releaseLock();
        seal(plaintextLogFile, adminPassword);
    }

    /**
     * Seals an unsealed .dat left behind by a force-stopped session (power cut,
     * crash, task kill). Same protection as a normal seal; the dashboard offers
     * this so interrupted sessions still end up as tamper-evident vaults.
     */
    public void sealExisting(File plaintextLogFile, char[] adminPassword) throws Exception {
        requireAdmin(adminPassword);
        if (plaintextLogFile == null || !plaintextLogFile.getName().toLowerCase().endsWith(".dat")) {
            throw new IllegalArgumentException("Select an unsealed session log (.dat).");
        }
        seal(plaintextLogFile, adminPassword);
    }

    private void seal(File plaintextLogFile, char[] adminPassword) throws Exception {
        if (!plaintextLogFile.exists()) throw new IllegalStateException("Session log file is missing.");

        File vaultFile = new File(plaintextLogFile.getParent(), plaintextLogFile.getName().replace(".dat", ".vault"));
        encryptor.encryptFile(plaintextLogFile, vaultFile, adminPassword);
        String signature = AesEncryptor.isAuthenticatedFormat(vaultFile)
                ? "gcm-v2"
                : signer.generateSignature(vaultFile);
        File sigFile = new File(vaultFile.getAbsolutePath() + ".sig");
        try (FileWriter fw = new FileWriter(sigFile)) { fw.write(signature); }

        if (!plaintextLogFile.delete()) plaintextLogFile.deleteOnExit();
        hideFile(vaultFile);
        hideFile(sigFile);
        // Off-machine insurance: copy the sealed (still encrypted) vault to the
        // backup directory. Failures are logged, never thrown - the seal itself
        // has already succeeded and an exam must not stall on a backup.
        try {
            VaultBackupManager.createDefault().backupVault(vaultFile);
        } catch (Exception backupFailure) {
            com.cheatguard.core.AppLog.warn("Vault backup after seal failed: "
                    + backupFailure.getMessage());
        }
    }

    /** Opens a sealed .vault or an unsealed .dat left by a forced termination. */
    public String openLog(File file, char[] adminPassword) throws Exception {
        requireAdmin(adminPassword);
        if (file == null || !file.exists()) throw new IllegalArgumentException("Log file does not exist.");
        if (file.getName().toLowerCase().endsWith(".dat")) {
            return new String(Files.readAllBytes(file.toPath()), StandardCharsets.UTF_8);
        }
        return openVault(file, adminPassword);
    }

    public String openVault(File vaultFile, char[] adminPassword) throws Exception {
        requireAdmin(adminPassword);
        File sigFile = new File(vaultFile.getAbsolutePath() + ".sig");
        if (!sigFile.exists()) throw new SecurityException("Signature file is missing.");
        String expectedSig = new String(Files.readAllBytes(sigFile.toPath()), StandardCharsets.UTF_8).trim();
        boolean authenticated = "gcm-v2".equals(expectedSig)
                && AesEncryptor.isAuthenticatedFormat(vaultFile);
        if (!authenticated && !signer.verify(vaultFile, expectedSig)) {
            throw new SecurityException("WARNING: log signature mismatch; file may have been tampered with.");
        }
        byte[] plain = encryptor.decryptFile(vaultFile, adminPassword);
        String content = new String(plain, StandardCharsets.UTF_8);
        Arrays.fill(plain, (byte) 0);
        return content;
    }

    /**
     * Delete a session log after checking the administrator password.
     *
     * <p>Sealed logs are owned by the Administrators group and are read-only for the
     * desktop account, so an ordinary delete is refused by Windows — that is exactly
     * what stops them being removed from Explorer. When the plain delete fails, the
     * request is repeated through an elevated helper, so deleting a log needs both the
     * administrator password here and a Windows permission prompt.
     */
    public void deleteLog(File file, char[] adminPassword) throws Exception {
        requireAdmin(adminPassword);
        if (file == null) return;

        java.util.List<File> targets = new java.util.ArrayList<>();
        targets.add(file);
        if (file.getName().toLowerCase().endsWith(".vault")) {
            File sig = new File(file.getAbsolutePath() + ".sig");
            if (sig.exists()) targets.add(sig);
        }

        boolean allGone = true;
        for (File target : targets) {
            if (target.exists() && !target.delete()) allGone = false;
        }
        if (allGone) return;

        if (!LogProtection.deleteElevated(targets)) {
            throw new IllegalStateException(
                    "Windows did not grant permission to delete this protected log.");
        }
        for (File target : targets) {
            if (target.exists()) {
                throw new IllegalStateException("The protected log could not be deleted.");
            }
        }
    }

    private void requireAdmin(char[] password) {
        // check() wipes the array it is given, so it must receive a copy - the
        // caller's array is still needed unchanged for the actual encryption.
        char[] probe = password == null ? new char[0] : password.clone();
        if (!adminAuth.check(probe).success()) {
            throw new SecurityException("Incorrect admin password.");
        }
    }

    /**
     * Re-encrypt every sealed vault with a new password, so changing the admin
     * password never makes past session logs unreadable. Files that cannot be
     * decrypted with the old password (already re-encrypted, or sealed during an
     * aborted change) are skipped, not destroyed - the original stays on disk.
     *
     * @return the number of vaults converted
     */
    public int reencryptVaults(char[] oldPassword, char[] newPassword) throws Exception {
        File[] vaults = com.cheatguard.config.AppPaths.getVaultDirectory()
                .listFiles((dir, name) -> name.toLowerCase().endsWith(".vault"));
        if (vaults == null) return 0;
        int converted = 0;
        for (File vault : vaults) {
            byte[] plain;
            try {
                plain = encryptor.decryptFile(vault, oldPassword);
            } catch (Exception notOldPassword) {
                continue; // sealed with another password; leave it untouched
            }
            File staged = new File(vault.getAbsolutePath() + ".new");
            try {
                File plainStaged = File.createTempFile("cg-reseal", ".dat", vault.getParentFile());
                try {
                    java.nio.file.Files.write(plainStaged.toPath(), plain);
                    encryptor.encryptFile(plainStaged, staged, newPassword);
                } finally {
                    plainStaged.delete();
                }
                if (!vault.delete() || !staged.renameTo(vault)) {
                    staged.delete();
                    throw new IllegalStateException("Could not replace vault " + vault.getName());
                }
                // The new vault is AES-GCM authenticated; the signature marker must
                // say so, or a legacy SHA-256 .sig would fail verification on open.
                File sigFile = new File(vault.getAbsolutePath() + ".sig");
                try (FileWriter fw = new FileWriter(sigFile)) { fw.write("gcm-v2"); }
                hideFile(vault);
                hideFile(sigFile);
                converted++;
            } finally {
                Arrays.fill(plain, (byte) 0);
            }
        }
        return converted;
    }

    private void hideFile(File file) {
        try {
            new ProcessBuilder("attrib", "+h", file.getAbsolutePath()).start().waitFor();
        } catch (Exception ignored) {
        }
    }
}
