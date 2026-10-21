package com.cheatguard.watchdog;

import com.cheatguard.core.AppLog;
import com.cheatguard.core.ExamSession;
import com.cheatguard.core.Violation;
import com.cheatguard.config.AppPaths;

import java.io.File;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;

/**
 * Streams this student's audit events to the invigilator's central monitor over
 * the exam LAN.
 *
 * <p>The student types TWO things on the session setup card: the invigilator's
 * IP and the exam code he shared. This client keeps a TLS connection (plaintext
 * TCP only in explicit development mode) to that IP on port 47821 and forwards
 * every violation, plus the session start and end, as one text line. The
 * invigilator's certificate is validated against a truststore before any byte
 * of exam data leaves the machine; the HMAC challenge-response then proves the
 * exam code on the encrypted channel. When the monitor is unreachable the
 * events queue (bounded) and are flushed on reconnect - nothing here can ever
 * block or break the exam itself. There is NO auto-discovery: without the IP
 * and code the alerts stay on the student's own PC.
 *
 * <p>Mice and keyboards never appear in the feed (they are not device-monitored);
 * everything the watchdog flags locally is what the invigilator sees.
 */
public final class CentralReporter {

    public static final int CENTRAL_TCP_PORT = 47821;
    public static final int DISCOVERY_UDP_PORT = 47822;
    private static final String BEACON_PREFIX = "CHEATGUARD-CENTRAL@@@";
    private static final int MAX_QUEUED = 1000;

    private final ExamSession session;
    private final String hostPc;
    private final ArrayDeque<String> queue = new ArrayDeque<>();
    private volatile String centralHost = "";
    /** The invigilator's IP, typed on the setup card. */
    private final String manualHost;
    /** The exam code the invigilator shared; the monitor rejects connections with other codes. */
    private final String examCode;
    private volatile boolean running;
    private volatile boolean stopping;
    /** The live connection, closed by stop() for a clean immediate shutdown. */
    private volatile Socket currentSocket;
    private Thread worker;

    public CentralReporter(ExamSession session) {
        this(session, "", "");
    }

    public CentralReporter(ExamSession session, String manualHost, String examCode) {
        this.session = session;
        this.manualHost = manualHost == null ? "" : manualHost.trim();
        this.examCode = examCode == null ? "" : examCode.trim();
        if (!this.manualHost.isEmpty()) {
            centralHost = this.manualHost;
            persistCentralIp(this.manualHost);
        }
        String pc = "PC";
        try {
            pc = InetAddress.getLocalHost().getHostName().trim();
        } catch (Exception ignored) {
        }
        this.hostPc = pc.isEmpty() ? "PC" : pc;
    }

    /** Start the sender loop. Best effort, never throws. */
    public void start() {
        if (running) return;
        stopping = false;
        running = true;
        worker = new Thread(this::sendLoop, "CheatGuard-CentralSender");
        worker.setDaemon(true);
        worker.start();
        // announce the session itself
        report(new Violation("SESSION_START",
                "Course=" + session.getCourseCode() + " | StudentID=" + session.getStudentId()
                        + " | PC=" + hostPc + " | ExamFolder=" + session.getExamFolder().getAbsolutePath(),
                Violation.Severity.INFO));
    }

    public void stop() {
        if (!running) return;
        report(new Violation("SESSION_END",
                "Course=" + session.getCourseCode() + " | StudentID=" + session.getStudentId()
                        + " | PC=" + hostPc,
                Violation.Severity.INFO));
        stopping = true;
        running = false;
        Socket live = currentSocket;
        if (live != null) {
            try {
                live.close(); // unblock the sender so the final batch drains and exits
            } catch (Exception ignored) {
            }
        }
        if (worker != null) worker.interrupt();
    }

    /** Queue one violation for the invigilator; drops the oldest when overflowing. */
    public void report(Violation v) {
        if (!running || v == null) return;
        String line = System.currentTimeMillis()
                + "@@@" + hostPc
                + "@@@" + session.getStudentId()
                + "@@@" + session.getCourseCode()
                + "@@@" + v.getSeverity().name()
                + "@@@" + v.getType()
                + "@@@" + sanitize(v.getDescription())
                + "@@@" + sanitize(LogDisplayHelper.display(v));
        synchronized (queue) {
            while (queue.size() >= MAX_QUEUED) queue.pollFirst();
            queue.addLast(line);
        }
    }

    /** Tell the firewall helper which IP to let through on TCP 47821. */
    private static void persistCentralIp(String addr) {
        try {
            java.nio.file.Files.write(
                    new File(AppPaths.getNetworkDirectory(), "central-ip.txt").toPath(),
                    addr.getBytes(StandardCharsets.UTF_8));
        } catch (Exception ignored) {
        }
    }

    private static String sanitize(String s) {
        return s == null ? "" : s.replace("@@@", " @ ").replace("\n", " ").replace("\r", " ");
    }

    /** Connect/reconnect to the central monitor and drain the queue. */
    private void sendLoop() {
        List<String> batch = new ArrayList<>();
        boolean developmentPlaintext = CentralTls.plaintextDevModeEnabled();
        if (developmentPlaintext) CentralTls.warnPlaintextOnce();
        boolean warnedUnreachable = false;
        while (running || stopping) {
            String host = centralHost;
            if (host.isEmpty()) break;
            try (Socket socket = developmentPlaintext
                    ? CentralTls.newDevelopmentClientSocket()
                    : CentralTls.newClientSocket(host, CENTRAL_TCP_PORT)) {
                currentSocket = socket;
                if (developmentPlaintext) {
                    socket.connect(new InetSocketAddress(host, CENTRAL_TCP_PORT), 3000);
                }
                OutputStream out = socket.getOutputStream();
                BufferedReader in = new BufferedReader(
                        new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
                String challenge = in.readLine();
                if (challenge == null || !challenge.startsWith("CHALLENGE@@@")) {
                    throw new java.io.IOException("Central monitor did not issue a challenge");
                }
                String nonce = challenge.substring("CHALLENGE@@@".length()).trim();
                String hello = "HELLO@@@" + hostPc + "@@@" + session.getStudentId()
                        + "@@@" + session.getCourseCode();
                String auth = "AUTH@@@" + CentralAuth.response(examCode, nonce, hostPc,
                        session.getStudentId(), session.getCourseCode());
                out.write((hello + "\n" + auth + "\n").getBytes(StandardCharsets.UTF_8));
                out.flush();
                while (running || hasQueuedEvents()) {
                    synchronized (queue) {
                        batch.clear();
                        while (!queue.isEmpty() && batch.size() < 50) batch.add(queue.pollFirst());
                    }
                    for (String line : batch) {
                        out.write((line + "\n").getBytes(StandardCharsets.UTF_8));
                    }
                    if (!batch.isEmpty()) out.flush();
                    if (batch.isEmpty()) sleepQuiet(700);
                }
                out.flush();
                stopping = false;
            } catch (Exception e) {
                // monitor down, bad TLS certificate, or lockdown blocking: retry
                if (stopping) break;
                // A wrong IP or a monitor that never started otherwise looks like a
                // working session: leave one row in the sealed log so it is visible.
                if (!warnedUnreachable && !manualHost.isEmpty()) {
                    warnedUnreachable = true;
                    session.getLogManager().record(new Violation("CENTRAL_MONITOR_UNREACHABLE",
                            "Could not reach the invigilator's monitor at " + host
                                    + " (port " + CENTRAL_TCP_PORT + "). Alerts stay on this PC until it reconnects.",
                            Violation.Severity.INFO));
                }
                sleepQuiet(2000);
            } finally {
                currentSocket = null;
            }
        }
        stopping = false;
    }

    private boolean hasQueuedEvents() {
        synchronized (queue) {
            return !queue.isEmpty();
        }
    }

    private static void sleepQuiet(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
        }
    }

    /** Tiny formatter so the reporter does not depend on the Swing gui package. */
    private static final class LogDisplayHelper {
        static String display(Violation v) {
            return v.getType() + ": " + v.getDescription();
        }
    }
}
