package com.cheatguard.watchdog;

import com.cheatguard.core.AppLog;
import com.cheatguard.core.ExamSession;
import com.cheatguard.core.Violation;

import java.io.File;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.Socket;
import java.net.StandardSocketOptions;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;

/**
 * Streams this student's audit events to the invigilator's central monitor over
 * the exam LAN.
 *
 * <p>The invigilator's Cheat.Guard (central-monitor mode) broadcasts its presence
 * on UDP 47822; this client listens for that beacon, remembers the address and
 * keeps a TCP connection to it on port 47821. Every violation, plus the session
 * start and end, is forwarded as one text line. When the monitor is unreachable
 * the events queue (bounded) and are flushed on reconnect - nothing here can
 * ever block or break the exam itself.
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
    /** Manually typed invigilator IP - wins over the beacon while set. */
    private final String manualHost;
    /** The exam code sir shared; only a beacon/monitor with this code is joined. */
    private final String examCode;
    private volatile boolean running;
    private Thread worker;
    private Thread beaconListener;

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

    /** Start the beacon listener and the sender loop. Best effort, never throws. */
    public void start() {
        if (running) return;
        running = true;
        beaconListener = new Thread(this::beaconLoop, "CheatGuard-CentralBeacon");
        beaconListener.setDaemon(true);
        beaconListener.start();
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
        if (beaconListener != null) beaconListener.interrupt();
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

    /** Listen for the invigilator's UDP beacon; remember the newest address. */
    private void beaconLoop() {
        try (DatagramSocket socket = new DatagramSocket(null)) {
            socket.setOption(StandardSocketOptions.SO_REUSEADDR, true);
            socket.bind(new InetSocketAddress(InetAddress.getByName("0.0.0.0"), DISCOVERY_UDP_PORT));
            byte[] buf = new byte[256];
            while (running) {
                DatagramPacket packet = new DatagramPacket(buf, buf.length);
                try {
                    socket.receive(packet);
                    String text = new String(packet.getData(), packet.getOffset(), packet.getLength(),
                            StandardCharsets.UTF_8).trim();
                    if (text.startsWith(BEACON_PREFIX)) {
                        String rest = text.substring(BEACON_PREFIX.length()).trim();
                        String addr = rest;
                        String beaconCode = "";
                        int sep = rest.indexOf("@@@");
                        if (sep >= 0) {
                            addr = rest.substring(0, sep).trim();
                            beaconCode = rest.substring(sep + 3).trim();
                        }
                        if (!examCode.isEmpty()) {
                            // join only the monitor whose exam code matches ours
                            if (beaconCode.equalsIgnoreCase(examCode) && !addr.isEmpty()) {
                                centralHost = addr;
                                persistCentralIp(addr);
                            }
                        } else if (!addr.isEmpty() && manualHost.isEmpty()) {
                            // a manually typed IP is intentional and wins over beacons
                            centralHost = addr;
                            // the helper's firewall rule allows this IP on TCP 47821
                            persistCentralIp(addr);
                        }
                    }
                } catch (Exception e) {
                    if (running) sleepQuiet(500);
                    else return;
                }
            }
        } catch (Exception e) {
            AppLog.warn("Central discovery listener unavailable: " + e.getMessage());
        }
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
