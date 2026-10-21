package com.cheatguard.watchdog;

import com.cheatguard.config.AppConfig;
import com.cheatguard.config.AppPaths;
import com.cheatguard.core.AppLog;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

/**
 * TLS transport for the central monitor link (invigilator server + student
 * clients), layered UNDER the existing HMAC challenge-response: TLS encrypts
 * and authenticates the channel, CentralAuth still proves the exam code.
 *
 * <p>Production mode (the default) only ever speaks TLS 1.2/1.3 with real
 * certificate validation — no trust-all managers, no disabled checks. The
 * invigilator PC presents a certificate from a PKCS12 keystore; student PCs
 * verify it against a PKCS12 truststore that contains exactly that
 * certificate, and the name/IP they typed must appear in the certificate's
 * Subject Alternative Names. Plaintext TCP remains available ONLY as an
 * explicit development opt-in ({@code -Dcheatguard.central.plaintext=true} or
 * config {@code central.plaintext=true}) and every side then shows a warning.
 *
 * <p>Keystore password sources (first wins; never logged): the system property
 * {@code cheatguard.central.tls.storepass}, the environment variable
 * {@code CHEATGUARD_CENTRAL_TLS_STOREPASS}, or the admin-owned config value
 * {@code central.tls.storepass}. See docs/CENTRAL_TLS.md for generation.
 */
public final class CentralTls {

    public static final String KEYSTORE_CONFIG = "central.tls.keystore";
    public static final String TRUSTSTORE_CONFIG = "central.tls.truststore";
    public static final String STOREPASS_CONFIG = "central.tls.storepass";
    public static final String PLAINTEXT_CONFIG = "central.plaintext";
    public static final String STOREPASS_SYSTEM_PROPERTY = "cheatguard.central.tls.storepass";
    public static final String STOREPASS_ENVIRONMENT = "CHEATGUARD_CENTRAL_TLS_STOREPASS";
    public static final String PLAINTEXT_SYSTEM_PROPERTY = "cheatguard.central.plaintext";
    private static final String DEFAULT_TRUSTSTORE_PASSWORD = "changeit";

    static final int CONNECT_TIMEOUT_MS = 3000;
    static final int HANDSHAKE_TIMEOUT_MS = 15000;

    private static final String[] TLS_PROTOCOLS = {"TLSv1.2", "TLSv1.3"};

    private CentralTls() {
    }

    // ------------------------------------------------------------- mode ----

    /**
     * True only when plaintext TCP was explicitly opted in for development.
     * Production default is false: TLS is mandatory on both ends.
     */
    public static boolean plaintextDevModeEnabled() {
        String flag = System.getProperty(PLAINTEXT_SYSTEM_PROPERTY, "");
        if (flag.isBlank()) flag = AppConfig.getInstance().getConfigValue(PLAINTEXT_CONFIG) == null
                ? "" : AppConfig.getInstance().getConfigValue(PLAINTEXT_CONFIG);
        return "true".equalsIgnoreCase(flag.trim());
    }

    public static String plaintextWarning() {
        return "WARNING: central monitor link is PLAINTEXT (development mode). "
                + "Enable TLS for real exams - see docs/CENTRAL_TLS.md.";
    }

    // --------------------------------------------------------- locations ----

    public static File defaultKeystoreFile() {
        return new File(AppPaths.getConfigDirectory(), "central-monitor-keystore.p12");
    }

    public static File defaultTruststoreFile() {
        return new File(AppPaths.getConfigDirectory(), "central-monitor-truststore.p12");
    }

    /** Keystore path from config, or the default location. */
    public static File configuredKeystoreFile() {
        String path = AppConfig.getInstance().getConfigValue(KEYSTORE_CONFIG);
        if (path != null && !path.isBlank()) return new File(path.trim());
        return defaultKeystoreFile();
    }

    /** Truststore path from config, or the default location. */
    public static File configuredTruststoreFile() {
        String path = AppConfig.getInstance().getConfigValue(TRUSTSTORE_CONFIG);
        if (path != null && !path.isBlank()) return new File(path.trim());
        return defaultTruststoreFile();
    }

    // ----------------------------------------------------------- server ----

    /**
     * A bound TLS server socket on {@code port} (port 0 = ephemeral, used by
     * tests). Throws with an actionable message when the keystore is missing
     * or unreadable — the monitor must not fall back to plaintext.
     */
    public static SSLServerSocket newServerSocket(int port) throws IOException {
        if (plaintextDevModeEnabled()) {
            throw new IllegalStateException(
                    "TLS was requested but plaintext development mode is enabled");
        }
        File keystoreFile = configuredKeystoreFile();
        if (!keystoreFile.isFile()) {
            throw new IOException("Central monitor keystore not found: " + keystoreFile
                    + ". Generate one with support/generate-central-tls.ps1"
                    + " (see docs/CENTRAL_TLS.md).");
        }
        char[] password = storePassword(true);
        try {
            KeyStore keyStore = loadKeyStore(keystoreFile, password);
            if (keyStore.size() == 0) {
                throw new IOException("Central monitor keystore is empty: " + keystoreFile);
            }
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(
                    KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keyStore, password);
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(kmf.getKeyManagers(), null, null);
            SSLServerSocket socket = (SSLServerSocket)
                    ((SSLServerSocketFactory) context.getServerSocketFactory())
                            .createServerSocket();
            socket.setReuseAddress(true);
            socket.setEnabledProtocols(enabledProtocols(socket.getSupportedProtocols()));
            socket.setNeedClientAuth(false); // students authenticate via the HMAC layer
            socket.bind(new InetSocketAddress(InetAddress.getByName("0.0.0.0"), port), 50);
            return socket;
        } catch (IOException | RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("Central monitor TLS setup failed: " + e.getMessage(), e);
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    // ----------------------------------------------------------- client ----

    /**
     * A connected, handshaken TLS client socket to the monitor at
     * {@code host}:{@code port}. The certificate must chain to the configured
     * truststore and contain {@code host} (name or IP) in its SANs. Throws —
     * never silently downgrades — when the truststore is missing or the
     * certificate fails validation.
     */
    public static SSLSocket newClientSocket(String host, int port) throws IOException {
        if (plaintextDevModeEnabled()) {
            throw new IllegalStateException(
                    "TLS was requested but plaintext development mode is enabled");
        }
        File truststoreFile = configuredTruststoreFile();
        if (!truststoreFile.isFile()) {
            throw new IOException("Central monitor truststore not found: " + truststoreFile
                    + ". Copy the invigilator's truststore to this PC"
                    + " (see docs/CENTRAL_TLS.md).");
        }
        try {
            KeyStore trustStore = loadKeyStore(truststoreFile, storePassword(false));
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(
                    TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustStore);
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, tmf.getTrustManagers(), null);
            SSLSocket socket = (SSLSocket) context.getSocketFactory().createSocket();
            socket.setEnabledProtocols(enabledProtocols(socket.getSupportedProtocols()));
            SSLParameters parameters = socket.getSSLParameters();
            parameters.setEndpointIdentificationAlgorithm("HTTPS");
            socket.setSSLParameters(parameters);
            socket.connect(new InetSocketAddress(host, port), CONNECT_TIMEOUT_MS);
            socket.setSoTimeout(HANDSHAKE_TIMEOUT_MS);
            socket.startHandshake();
            verifyPeerName(socket, host);
            return socket;
        } catch (IOException | RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("Central monitor TLS setup failed: " + e.getMessage(), e);
        }
    }

    /**
     * A plain client socket for development mode only; production callers must
     * use {@link #newClientSocket(String, int)}.
     */
    public static Socket newDevelopmentClientSocket() {
        if (!plaintextDevModeEnabled()) {
            throw new IllegalStateException(
                    "Plaintext central transport is not allowed outside development mode");
        }
        return new Socket();
    }

    /**
     * Explicit SAN check of the handshake peer against the host the student
     * typed. Complements JSSE's endpoint identification; both must pass.
     */
    private static void verifyPeerName(SSLSocket socket, String host) throws IOException {
        String wanted = host == null ? "" : host.trim();
        if (wanted.isEmpty()) throw new IOException("Central host is empty");
        Certificate[] chain;
        try {
            chain = socket.getSession().getPeerCertificates();
        } catch (Exception e) {
            throw new IOException("Central monitor certificate could not be read", e);
        }
        if (chain == null || chain.length == 0 || !(chain[0] instanceof X509Certificate cert)) {
            throw new IOException("Central monitor did not present a certificate");
        }
        List<String> names = new ArrayList<>();
        try {
            Collection<List<?>> sans = cert.getSubjectAlternativeNames();
            if (sans != null) {
                for (List<?> san : sans) {
                    // type 2 = dNSName, 7 = iPAddress (RFC 5280)
                    if (san.size() >= 2 && (san.get(0).equals(2) || san.get(0).equals(7))
                            && san.get(1) instanceof String value) {
                        names.add(value.toLowerCase(java.util.Locale.ROOT));
                    }
                }
            }
        } catch (Exception e) {
            throw new IOException("Central monitor certificate has no readable SANs", e);
        }
        String expected = wanted.toLowerCase(java.util.Locale.ROOT);
        boolean ip = expected.matches("\\d{1,3}(\\.\\d{1,3}){3}|[0-9a-f:]*:[0-9a-f:]+");
        for (String name : names) {
            if (name.equals(expected)) return;
            if (!ip && (name.startsWith("*.") && expected.endsWith(name.substring(1)))) return;
        }
        throw new IOException("Central monitor certificate does not cover '" + wanted
                + "'; its SAN entries are " + names
                + ". Regenerate the certificate with this address (docs/CENTRAL_TLS.md).");
    }

    // ----------------------------------------------------------- helpers ----

    private static KeyStore loadKeyStore(File file, char[] password) throws IOException {
        try (InputStream in = Files.newInputStream(file.toPath())) {
            KeyStore store = KeyStore.getInstance("PKCS12");
            store.load(in, password.length == 0 ? null : password);
            return store;
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("Could not read PKCS12 store " + file + ": " + e.getMessage(), e);
        }
    }

    /**
     * Store password without ever logging it: system property, then environment
     * variable, then the admin-owned config file. A truststore of certificates
     * needs no password, so empty is allowed there but not for the keystore.
     */
    private static char[] storePassword(boolean required) {
        String value = System.getProperty(STOREPASS_SYSTEM_PROPERTY, "");
        if (value.isBlank()) {
            value = System.getenv(STOREPASS_ENVIRONMENT);
        }
        if (value == null || value.isBlank()) {
            value = AppConfig.getInstance().getConfigValue(STOREPASS_CONFIG) == null
                    ? "" : AppConfig.getInstance().getConfigValue(STOREPASS_CONFIG);
        }
        if ((value == null || value.isBlank()) && !required) {
            return DEFAULT_TRUSTSTORE_PASSWORD.toCharArray();
        }
        if ((value == null || value.isBlank()) && required) {
            throw new IllegalStateException("Central TLS store password is not set. Provide "
                    + STOREPASS_SYSTEM_PROPERTY + ", the " + STOREPASS_ENVIRONMENT
                    + " environment variable, or the " + STOREPASS_CONFIG
                    + " config value (see docs/CENTRAL_TLS.md).");
        }
        return value == null ? new char[0] : value.toCharArray();
    }

    /** The store password for tests; production code uses storePassword(). */
    static char[] storePasswordForTest() {
        return storePassword(false);
    }

    private static String[] enabledProtocols(String[] supported) {
        List<String> enabled = new ArrayList<>();
        for (String protocol : TLS_PROTOCOLS) {
            for (String candidate : supported) {
                if (candidate.equalsIgnoreCase(protocol)) enabled.add(candidate);
            }
        }
        if (enabled.isEmpty()) {
            throw new IllegalStateException("No TLS 1.2/1.3 support in this runtime");
        }
        return enabled.toArray(new String[0]);
    }

    /** Best-effort one-time warning for development plaintext, client side. */
    public static void warnPlaintextOnce() {
        AppLog.warn(plaintextWarning());
    }
}
