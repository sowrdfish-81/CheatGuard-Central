package com.cheatguard.gui;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.InputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Enumeration;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * The invigilator's central screen: listens on the exam LAN for every student
 * PC running a Cheat.Guard session and shows their alerts live in one table.
 *
 * <p>Server side of {@link com.cheatguard.watchdog.CentralReporter}: it broadcasts
 * a UDP beacon (so student PCs find this machine automatically), accepts their
 * TCP connections, and renders each forwarded event as a table row - RED rows
 * for critical alerts. Every event is also appended to a CSV on the Desktop for
 * the exam record.
 */
public class CentralMonitorPanel extends JPanel {

    private static final int CENTRAL_TCP_PORT = 47821;
    private static final int DISCOVERY_UDP_PORT = 47822;
    private static final String BEACON_PREFIX = "CHEATGUARD-CENTRAL@@@";

    private final DefaultTableModel model = new DefaultTableModel(
            new Object[]{"Time", "PC", "Student", "Course", "Level", "Event"}, 0) {
        @Override public boolean isCellEditable(int r, int c) { return false; }
    };
    private final JTable table = new JTable(model);
    private final JLabel statusLabel = new JLabel("Monitor stopped.");
    private final JLabel counters = new JLabel("PCs: 0   Alerts: 0");
    private final java.util.Set<String> knownPcs = java.util.Collections.synchronizedSet(new java.util.HashSet<>());
    private final java.util.concurrent.atomic.AtomicLong alertCount = new java.util.concurrent.atomic.AtomicLong();
    private final CopyOnWriteArrayList<java.io.Closeable> closables = new CopyOnWriteArrayList<>();

    private volatile boolean running;
    private ServerSocket serverSocket;
    private Thread acceptThread;
    private Thread beaconThread;
    private BufferedWriter csvWriter;
    private File csvFile;

    public CentralMonitorPanel(Runnable onBack) {
        setLayout(new BorderLayout(14, 14));
        setBackground(UITheme.BG_DARK);
        setBorder(UITheme.padding(20, 22, 20, 22));

        // header
        JLabel title = UITheme.title("Invigilator central monitor");
        JLabel subtitle = UITheme.muted("Live alerts from every exam PC on this network. "
                + "Start here first, then start the sessions on the students' PCs.");
        JPanel titles = new JPanel();
        titles.setLayout(new BoxLayout(titles, BoxLayout.Y_AXIS));
        titles.setOpaque(false);
        titles.add(title);
        titles.add(Box.createVerticalStrut(4));
        titles.add(subtitle);

        JButton back = UITheme.ghost("Back");
        back.addActionListener(e -> {
            stopMonitor();
            onBack.run();
        });
        JPanel header = new JPanel(new BorderLayout(12, 0));
        header.setOpaque(false);
        header.add(titles, BorderLayout.WEST);
        header.add(back, BorderLayout.EAST);
        add(header, BorderLayout.NORTH);

        // table
        table.setRowHeight(26);
        table.setFont(UITheme.FONT_BODY);
        table.getTableHeader().setFont(UITheme.FONT_SECTION);
        ((DefaultTableCellRenderer) table.getTableHeader().getDefaultRenderer())
                .setHorizontalAlignment(SwingConstants.LEFT);
        table.setAutoCreateRowSorter(true);
        JScrollPane scroll = UITheme.scroll(table);
        scroll.getViewport().setBackground(UITheme.BG_INPUT);

        // controls + status
        JButton start = UITheme.primary("Start monitor");
        start.addActionListener(e -> startMonitor());
        JButton stop = UITheme.ghost("Stop");
        stop.addActionListener(e -> stopMonitor());
        JButton clear = UITheme.ghost("Clear rows");
        clear.addActionListener(e -> model.setRowCount(0));
        JPanel controls = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        controls.setOpaque(false);
        controls.add(start);
        controls.add(stop);
        controls.add(clear);
        controls.add(Box.createHorizontalStrut(12));
        counters.setFont(UITheme.FONT_SECTION);
        controls.add(counters);

        JPanel statusCard = UITheme.card();
        statusCard.setLayout(new BorderLayout(10, 10));
        statusCard.add(controls, BorderLayout.NORTH);
        statusLabel.setFont(UITheme.FONT_BODY);
        statusLabel.setForeground(UITheme.TEXT_MUTED);
        statusCard.add(statusLabel, BorderLayout.SOUTH);

        JPanel center = new JPanel(new BorderLayout(0, 14));
        center.setOpaque(false);
        center.add(statusCard, BorderLayout.NORTH);
        center.add(scroll, BorderLayout.CENTER);
        add(center, BorderLayout.CENTER);
    }

    // ------------------------------------------------------------- lifecycle --

    private synchronized void startMonitor() {
        if (running) return;
        try {
            openFirewall();
            serverSocket = new ServerSocket();
            serverSocket.setReuseAddress(true);
            serverSocket.bind(new InetSocketAddress(InetAddress.getByName("0.0.0.0"), CENTRAL_TCP_PORT));
            openCsv();
            running = true;
            acceptThread = new Thread(this::acceptLoop, "CheatGuard-CentralAccept");
            acceptThread.setDaemon(true);
            acceptThread.start();
            beaconThread = new Thread(this::beaconLoop, "CheatGuard-CentralBeaconSrv");
            beaconThread.setDaemon(true);
            beaconThread.start();
            statusLabel.setText("Listening on port " + CENTRAL_TCP_PORT
                    + " - student PCs on this network will connect automatically.");
            statusLabel.setForeground(UITheme.ACCENT_TEAL);
        } catch (Exception e) {
            statusLabel.setText("Could not start: " + e.getMessage()
                    + " (port already in use?)");
            statusLabel.setForeground(UITheme.ACCENT_RED);
            stopMonitor();
        }
    }

    private synchronized void stopMonitor() {
        running = false;
        try { if (serverSocket != null) serverSocket.close(); } catch (Exception ignored) {}
        serverSocket = null;
        for (java.io.Closeable c : closables) {
            try { c.close(); } catch (Exception ignored) {}
        }
        closables.clear();
        try { if (csvWriter != null) csvWriter.close(); } catch (Exception ignored) {}
        csvWriter = null;
        statusLabel.setText("Monitor stopped.");
        statusLabel.setForeground(UITheme.TEXT_MUTED);
    }

    private void acceptLoop() {
        while (running) {
            try {
                Socket socket = serverSocket.accept();
                closables.add(socket);
                Thread t = new Thread(() -> readClient(socket), "CheatGuard-CentralClient");
                t.setDaemon(true);
                t.start();
            } catch (Exception e) {
                if (running) sleepQuiet(300);
                else return;
            }
        }
    }

    private void readClient(Socket socket) {
        try (socket; InputStream in = socket.getInputStream()) {
            byte[] buf = new byte[8192];
            StringBuilder pending = new StringBuilder();
            int read;
            while (running && (read = in.read(buf)) != -1) {
                pending.append(new String(buf, 0, read, StandardCharsets.UTF_8));
                int nl;
                while ((nl = pending.indexOf("\n")) >= 0) {
                    String line = pending.substring(0, nl).trim();
                    pending.delete(0, nl + 1);
                    if (!line.isEmpty()) handleLine(line);
                }
            }
        } catch (Exception ignored) {
            // the student PC disconnected; its rows stay on screen
        }
    }

    /** Line format: millis@@@pc@@@student@@@course@@@severity@@@type@@@message@@@display */
    private void handleLine(String line) {
        String[] p = line.split("@@@", 8);
        String time;
        String pc = "PC", student = "—", course = "—", severity = "INFO", event = "";
        if (p.length >= 7) {
            try {
                time = new SimpleDateFormat("HH:mm:ss").format(new Date(Long.parseLong(p[0])));
            } catch (Exception e) {
                time = new SimpleDateFormat("HH:mm:ss").format(new Date());
            }
            pc = p[1].trim();
            student = p[2].trim();
            course = p[3].trim();
            severity = p[4].trim();
            String type = p[5].trim();
            String message = p.length >= 8 ? p[7].trim() : p[6].trim();
            event = message.startsWith(type + ":") ? message : type + ": " + message;
        } else if (p.length >= 4 && "HELLO".equals(p[0])) {
            time = new SimpleDateFormat("HH:mm:ss").format(new Date());
            pc = p[1].trim();
            student = p[2].trim();
            course = p[3].trim();
            severity = "INFO";
            event = "Session connected to central monitor";
        } else {
            return;
        }

        knownPcs.add(pc);
        boolean red = "CRITICAL".equalsIgnoreCase(severity) || "WARNING".equalsIgnoreCase(severity);
        if (red) alertCount.incrementAndGet();
        counters.setText("PCs: " + knownPcs.size() + "   Alerts: " + alertCount.get());
        String rowSeverity = red ? "RED FLAG" : "NOTICE".equalsIgnoreCase(severity) ? "BLOCKED" : severity;

        final String fTime = time, fPc = pc, fStudent = student, fCourse = course,
                fSev = rowSeverity, fEvent = event;
        SwingUtilities.invokeLater(() -> model.addRow(new Object[]{fTime, fPc, fStudent, fCourse, fSev, fEvent}));
        writeCsv(fTime, fPc, fStudent, fCourse, fSev, fEvent);
    }

    // -------------------------------------------------------------- beacon ----

    /** Announce this machine on every LAN interface so student PCs find it. */
    private void beaconLoop() {
        byte[] payload = (BEACON_PREFIX + firstLanIp()).getBytes(StandardCharsets.UTF_8);
        while (running) {
            try (DatagramSocket socket = new DatagramSocket()) {
                socket.setBroadcast(true);
                for (InetAddress broadcast : broadcastAddresses()) {
                    try {
                        socket.send(new DatagramPacket(payload, payload.length,
                                broadcast, DISCOVERY_UDP_PORT));
                    } catch (Exception ignored) {
                    }
                }
            } catch (Exception ignored) {
            }
            sleepQuiet(2000);
        }
    }

    private String firstLanIp() {
        try {
            Enumeration<NetworkInterface> ifs = NetworkInterface.getNetworkInterfaces();
            while (ifs.hasMoreElements()) {
                NetworkInterface ni = ifs.nextElement();
                if (!ni.isUp() || ni.isLoopback()) continue;
                Enumeration<InetAddress> addrs = ni.getInetAddresses();
                while (addrs.hasMoreElements()) {
                    InetAddress a = addrs.nextElement();
                    if (a.isSiteLocalAddress()) return a.getHostAddress();
                }
            }
        } catch (Exception ignored) {
        }
        return "127.0.0.1";
    }

    private java.util.List<InetAddress> broadcastAddresses() {
        java.util.List<InetAddress> out = new java.util.ArrayList<>();
        try {
            out.add(InetAddress.getByName("255.255.255.255"));
            Enumeration<NetworkInterface> ifs = NetworkInterface.getNetworkInterfaces();
            while (ifs.hasMoreElements()) {
                NetworkInterface ni = ifs.nextElement();
                if (!ni.isUp() || ni.isLoopback()) continue;
                Enumeration<InetAddress> addrs = ni.getInetAddresses();
                while (addrs.hasMoreElements()) {
                    InetAddress a = addrs.nextElement();
                    if (a.isSiteLocalAddress()) {
                        byte[] ip = a.getAddress();
                        ip[ip.length - 1] = (byte) 255;
                        out.add(InetAddress.getByAddress(ip));
                    }
                }
            }
        } catch (Exception ignored) {
        }
        return out;
    }

    // ------------------------------------------------------- firewall + csv ----

    /** Allow student PCs to reach this port (the app runs elevated, so no prompt). */
    private void openFirewall() {
        runQuiet("netsh", "advfirewall", "firewall", "add", "rule",
                "name=CheatGuard Central Monitor", "dir=in", "action=allow",
                "protocol=TCP", "localport=" + CENTRAL_TCP_PORT);
        runQuiet("netsh", "advfirewall", "firewall", "add", "rule",
                "name=CheatGuard Central Discovery", "dir=in", "action=allow",
                "protocol=UDP", "localport=" + DISCOVERY_UDP_PORT);
    }

    private static void runQuiet(String... command) {
        try {
            Process p = new ProcessBuilder(command).redirectErrorStream(true).start();
            p.getInputStream().readAllBytes();
            p.waitFor(10, java.util.concurrent.TimeUnit.SECONDS);
        } catch (Exception ignored) {
        }
    }

    private void openCsv() {
        try {
            File dir = new File(System.getProperty("user.desktop", System.getProperty("user.home")),
                    "CheatGuard-Central");
            if (!dir.exists()) dir.mkdirs();
            csvFile = new File(dir, "central-log-"
                    + new SimpleDateFormat("yyyyMMdd").format(new Date()) + ".csv");
            csvWriter = new BufferedWriter(new FileWriter(csvFile, true));
            csvWriter.write("time,pc,student,course,level,event\n");
        } catch (Exception e) {
            csvWriter = null;
        }
    }

    private void writeCsv(String time, String pc, String student, String course, String level, String event) {
        if (csvWriter == null) return;
        try {
            synchronized (this) {
                csvWriter.write(csv(time) + "," + csv(pc) + "," + csv(student) + ","
                        + csv(course) + "," + csv(level) + "," + csv(event) + "\n");
                csvWriter.flush();
            }
        } catch (Exception ignored) {
        }
    }

    private static String csv(String v) {
        String s = v == null ? "" : v.replace("\"", "'").replace("\n", " ").replace("\r", " ");
        return "\"" + s + "\"";
    }

    private static void sleepQuiet(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
        }
    }
}
