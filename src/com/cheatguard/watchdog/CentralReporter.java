package com.cheatguard.watchdog;

import com.cheatguard.core.AppLog;
import com.cheatguard.core.ExamSession;
import com.cheatguard.core.Violation;

import java.io.File;
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
 * IP and the exam code he shared. This client keeps a TCP connection to that
 * IP on port 47821 and forwards every violation, plus the session start and
 * end, as one text line. When the monitor is unreachable the events queue
 * (bounded) and are flushed on reconnect - nothing here can ever block or
 * break the exam itself. There is NO auto-discovery: without the IP and code
 * the alerts stay on the student's own PC.
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
    /** The exam code sir shared; the monitor rejects connections with other codes. */
    private final String examCode;
    private volatile boolean running;
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
        report(new Violation("SESSION_END",
                "Course=" + session.getCourseCode() + " | StudentID=" + session.getStudentId()
                        + " | PC=" + hostPc,
                Violation.Severity.INFO));
        running = false;
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
                    java.nio.file.Paths.get(System.getenv("ProgramData"),
                            "CheatGuard", "network", "central-ip.txt"),
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
        while (running) {
            String host = centralHost;
            if (host.isEmpty()) { sleepQuiet(1000); continue; }
            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress(host, CENTRAL_TCP_PORT), 3000);
                OutputStream out = socket.getOutputStream();
                // announce who we are as the very first line
                String hello = "HELLO@@@" + hostPc + "@@@" + session.getStudentId()
                        + "@@@" + session.getCourseCode() + "@@@" + examCode;
                out.write((hello + "\n").getBytes(StandardCharsets.UTF_8));
                while (running) {
                    synchronized (queue) {
                        batch.clear();
                        while (!queue.isEmpty() && batch.size() < 50) batch.addLast(queue.pollFirst());
                    }
                    for (String line : batch) {
                        out.write((line + "\n").getBytes(StandardCharsets.UTF_8));
                    }
                    if (!batch.isEmpty()) out.flush();
                    if (batch.isEmpty()) sleepQuiet(700);
                }
                out.flush();
            } catch (Exception e) {
                // monitor down or lockdown blocking: retry after a pause
                sleepQuiet(2000);
            }
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
