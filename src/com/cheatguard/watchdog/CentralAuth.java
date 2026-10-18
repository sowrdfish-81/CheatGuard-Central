package com.cheatguard.watchdog;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

/** Challenge-response primitives for the central monitor protocol. */
public final class CentralAuth {
    private static final SecureRandom RANDOM = new SecureRandom();

    private CentralAuth() { }

    public static String newNonce() {
        byte[] nonce = new byte[32];
        RANDOM.nextBytes(nonce);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(nonce);
    }

    public static String response(String examCode, String nonce,
                                  String hostPc, String studentId, String courseCode) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(examCode.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            String message = nonce + "@@@" + hostPc + "@@@" + studentId + "@@@" + courseCode;
            return Base64.getUrlEncoder().withoutPadding().encodeToString(
                    mac.doFinal(message.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException("Central authentication is unavailable", e);
        }
    }

    public static boolean constantTimeEquals(String expected, String actual) {
        return MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.UTF_8),
                actual.getBytes(StandardCharsets.UTF_8));
    }
}
