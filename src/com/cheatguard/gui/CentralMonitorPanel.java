package com.cheatguard.gui;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * The invigilator's central screen, organised the way an invigilator thinks:
 *
 * <p>STUDENT LIST - one row per exam PC, sorted so that anyone who triggered a
 * red alert sits at the TOP marked SUSPICIOUS (amber). Clicking a row opens that
 * student's FULL log; Back returns to the list. The invigilator reads the log
 * and decides - a red flag means the student TRIED something, and Cheat.Guard
 * can be wrong - so the row keeps saying SUSPICIOUS until the invigilator marks
 * it "Cheat confirmed" or "Cleared". Verdicts are recorded in the CSV too.
 */
public class CentralMonitorPanel extends JPanel {

    private static final int CENTRAL_TCP_PORT = 47821;

    /** One exam PC + student and everything they did. */
    private static final class StudentRecord {
        final String pc;
        String student = "—";
        String course = "—";
        final List<String[]> events = new ArrayList<>();   // {time, level, event}
        boolean suspicious;
        String verdict = "";                                // CHEAT CONFIRMED / CLEARED / ""
        long lastActivity;
        long lastRedAt;

        StudentRecord(String pc) { this.pc = pc; }

        String status() {
            if ("CHEAT CONFIRMED".equals(verdict)) return "CHEAT CONFIRMED";
            if (suspicious) return "SUSPICIOUS";
            if ("CLEARED".equals(verdict)) return "CLEARED";
            return "ACTIVE";
        }
    }

    private final Map<String, StudentRecord> students = new LinkedHashMap<>(); // key = student@pc

    private final DefaultTableModel studentModel = new DefaultTableModel(
            new Object[]{"Student ID", "PC", "Course", "Status", "Red flags", "Last seen"}, 0) {
        @Override public boolean isCellEditable(int r, int c) { return false; }
    };
    private final JTable studentTable = new JTable(studentModel);

    private final DefaultTableModel eventModel = new DefaultTableModel(
            new Object[]{"Time", "Level", "Event"}, 0) {
        @Override public boolean isCellEditable(int r, int c) { return false; }
    };
    private final JTable eventTable = new JTable(eventModel);

    private final JLabel statusLabel = new JLabel("Monitor stopped.");
    private final JLabel counters = new JLabel("PCs: 0   Alerts: 0");
    private final JLabel detailTitle = new JLabel();
    private StudentRecord detailStudent;
    private String selectedKey;
    private boolean showingDetail;

    private final java.util.concurrent.atomic.AtomicLong alertCount = new java.util.concurrent.atomic.AtomicLong();
    private final CopyOnWriteArrayList<java.io.Closeable> closables = new CopyOnWriteArrayList<>();

    private volatile boolean running;
    private ServerSocket serverSocket;
    private Thread acceptThread;
    private volatile String examCode = "";
    private BufferedWriter csvWriter;

    private JPanel centerHost;
    private JPanel listPanel;
    private JPanel detailPanel;
    private JButton markCheatBtn;
    private JButton markClearedBtn;
    private final JTextField codeField = new JTextField();

    public CentralMonitorPanel(Runnable onBack) {
        setLayout(new BorderLayout(14, 14));
        setBackground(UITheme.BG_DARK);
        setBorder(UITheme.padding(20, 22, 20, 22));

        // ------------------------------------------------------------- header
        JLabel title = UITheme.title("Invigilator central monitor");
        JLabel subtitle = UITheme.muted("Live alerts from every exam PC on this network. "
                + "Red = the student TRIED something - read their log before deciding. "
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

        // -------------------------------------------------------- list panel
        studentTable.setRowHeight(30);
        studentTable.setFont(UITheme.FONT_BODY);
        studentTable.getTableHeader().setFont(UITheme.FONT_SECTION);
        studentTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        studentTable.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
            @Override public Component getTableCellRendererComponent(JTable t, Object value,
                    boolean sel, boolean focus, int row, int col) {
                Component c = super.getTableCellRendererComponent(t, value, sel, focus, row, col);
                String status = row < t.getModel().getRowCount()
                        ? String.valueOf(t.getModel().getValueAt(row, 3)) : "";
                if ("CHEAT CONFIRMED".equals(status)) {
                    c.setForeground(new Color(0xFFB4BA));
                    c.setFont(UITheme.FONT_SECTION);
                } else if ("SUSPICIOUS".equals(status)) {
                    c.setForeground(new Color(0xFFF0A8));
                    c.setFont(UITheme.FONT_SECTION);
                } else if ("CLEARED".equals(status)) {
                    c.setForeground(UITheme.ACCENT_TEAL);
                } else {
                    c.setForeground(UITheme.TEXT_WHITE);
                }
                return c;
            }
        });
        studentTable.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override public void mouseClicked(java.awt.event.MouseEvent e) {
                openDetailOfSelected();
            }
        });
        JScrollPane studentScroll = UITheme.scroll(studentTable);
        studentScroll.getViewport().setBackground(UITheme.BG_INPUT);

        codeField.setFont(UITheme.FONT_SECTION);
        codeField.setPreferredSize(new Dimension(150, 34));
        codeField.setText(randomCode());
        JButton shuffle = UITheme.ghost("New code");
        shuffle.addActionListener(e -> codeField.setText(randomCode()));
        JButton start = UITheme.primary("Start monitor");
        start.addActionListener(e -> startMonitor());
        JButton stop = UITheme.ghost("Stop");
        stop.addActionListener(e -> stopMonitor());

        JPanel controls = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        controls.setOpaque(false);
        controls.add(new JLabel("Exam code:"));
        controls.add(codeField);
        controls.add(shuffle);
        controls.add(start);
        controls.add(stop);
        controls.add(Box.createHorizontalStrut(12));
        counters.setFont(UITheme.FONT_SECTION);
        controls.add(counters);

        statusLabel.setFont(UITheme.FONT_BODY);

        JPanel listCard = UITheme.card();
        listCard.setLayout(new BorderLayout(10, 10));
        JPanel top = new JPanel(new BorderLayout(0, 10));
        top.setOpaque(false);
        top.add(controls, BorderLayout.NORTH);
        top.add(statusLabel, BorderLayout.SOUTH);
        listCard.add(top, BorderLayout.NORTH);
        listCard.add(studentScroll, BorderLayout.CENTER);

        listPanel = new JPanel(new BorderLayout());
        listPanel.setOpaque(false);
        listPanel.add(listCard, BorderLayout.CENTER);

        // ------------------------------------------------------ detail panel
        JButton backToList = UITheme.secondary("← Back to students");
        backToList.addActionListener(e -> showList());
        markCheatBtn = new JButton("Mark: cheat confirmed");
        markCheatBtn.setBackground(new Color(0x3A1C23));
        markCheatBtn.setForeground(new Color(0xFF9CA5));
        markCheatBtn.setFocusPainted(false);
        markCheatBtn.setOpaque(true);
        markCheatBtn.setBorderPainted(false);
        markCheatBtn.setFont(UITheme.FONT_SECTION);
        markClearedBtn = UITheme.secondary("Mark: cleared");
        JPanel verdicts = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        verdicts.setOpaque(false);
        verdicts.add(markClearedBtn);
        verdicts.add(markCheatBtn);

        detailTitle.setFont(UITheme.FONT_SECTION);
        detailTitle.setForeground(UITheme.TEXT_WHITE);

        JPanel detailHeader = new JPanel(new BorderLayout(10, 0));
        detailHeader.setOpaque(false);
        detailHeader.add(backToList, BorderLayout.WEST);
        detailHeader.add(verdicts, BorderLayout.EAST);

        eventTable.setRowHeight(26);
        eventTable.setFont(UITheme.FONT_BODY);
        JScrollPane eventScroll = UITheme.scroll(eventTable);
        eventScroll.getViewport().setBackground(UITheme.BG_INPUT);

        JPanel detailCard = UITheme.card();
        detailCard.setLayout(new BorderLayout(10, 10));
        detailCard.add(detailHeader, BorderLayout.NORTH);
        JPanel detailCenter = new JPanel(new BorderLayout(0, 10));
        detailCenter.setOpaque(false);
        detailCenter.add(detailTitle, BorderLayout.NORTH);
        detailCenter.add(eventScroll, BorderLayout.CENTER);
        detailCard.add(detailCenter, BorderLayout.CENTER);

        detailPanel = new JPanel(new BorderLayout());
        detailPanel.setOpaque(false);
        detailPanel.add(detailCard, BorderLayout.CENTER);

        // host + start screen
        centerHost = new JPanel(new BorderLayout());
        centerHost.setOpaque(false);
        centerHost.add(listPanel, BorderLayout.CENTER);

        add(centerHost, BorderLayout.CENTER);
    }

    // ------------------------------------------------------------- lifecycle --

    private synchronized void startMonitor() {
        if (running) return;
        String code = codeField.getText().trim();
        if (!code.matches("[A-Za-z0-9]{3,12}")) {
            statusLabel.setText("The exam code needs 3-12 letters or numbers.");
            statusLabel.setForeground(UITheme.ACCENT_RED);
            return;
        }
        examCode = code;
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
            statusLabel.setText("Your IP: " + firstLanIp() + "  |  Exam code: " + code
                    + "  |  Students enter BOTH on their PC, then start the session.");
            statusLabel.setForeground(UITheme.ACCENT_TEAL);
        } catch (Exception e) {
            statusLabel.setText("Could not start: " + e.getMessage() + " (port already in use?)");
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

    // ----------------------------------------------------------- server I/O --

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
                    if (!line.isEmpty()) handleLine(line, socket);
                }
            }
        } catch (Exception ignored) {
            // the student PC disconnected; its rows stay on screen
        }
    }

    /** Line format: millis@@@pc@@@student@@@course@@@severity@@@type@@@message@@@display */
    private void handleLine(String line, Socket socket) {
        String[] p = line.split("@@@", 8);
        String time;
        String pc;
        String student;
        String course;
        String severity;
        String event;
        if (p.length >= 7 && !"HELLO".equals(p[0])) {
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
            String clientCode = p.length >= 5 ? p[4].trim() : "";
            if (!clientCode.equalsIgnoreCase(examCode)) {
                // wrong exam code: silently close - not this exam's student
                try { socket.close(); } catch (Exception ignored) {}
                final String rejTime = new SimpleDateFormat("HH:mm:ss").format(new Date());
                SwingUtilities.invokeLater(() -> {
                    statusLabel.setText("Rejected a connection with a wrong exam code.");
                    statusLabel.setForeground(UITheme.WARN);
                });
                writeCsv(rejTime, "-", "-", "-", "NOTICE",
                        "A PC tried to join with a wrong exam code (rejected)");
                return;
            }
            time = new SimpleDateFormat("HH:mm:ss").format(new Date());
            pc = p[1].trim();
            student = p[2].trim();
            course = p[3].trim();
            severity = "INFO";
            event = "Session joined with exam code " + examCode;
        } else {
            return;
        }

        StudentRecord rec = recordFor(pc, student, course);
        boolean red = "CRITICAL".equalsIgnoreCase(severity) || "WARNING".equalsIgnoreCase(severity);
        synchronized (rec) {
            if (!"—".equals(student)) rec.student = student;
            if (!"—".equals(course)) rec.course = course;
            rec.events.add(new String[]{time, rowSeverity(severity, red), event});
            rec.lastActivity = System.currentTimeMillis();
            if (red) {
                rec.suspicious = true;
                rec.lastRedAt = System.currentTimeMillis();
            }
        }
        if (red) alertCount.incrementAndGet();

        final String fTime = time, fSev = rowSeverity(severity, red), fEvent = event;
        final String fKey = keyOf(pc, student);
        SwingUtilities.invokeLater(() -> {
            if (showingDetail && detailStudent != null
                    && fKey.equals(keyOf(detailStudent.pc, detailStudent.student))) {
                eventModel.addRow(new Object[]{fTime, fSev, fEvent});
            }
            rebuildStudentTable();
            counters.setText("PCs: " + students.size() + "   Alerts: " + alertCount.get());
        });
        writeCsv(fTime, pc, student, course, fSev, fEvent);
    }

    private static String rowSeverity(String severity, boolean red) {
        return red ? "RED FLAG" : "NOTICE".equalsIgnoreCase(severity) ? "BLOCKED" : severity;
    }

    private static String keyOf(String pc, String student) {
        return student + "@" + pc;
    }

    private StudentRecord recordFor(String pc, String student, String course) {
        String key = keyOf(pc, student);
        synchronized (students) {
            StudentRecord rec = students.get(key);
            if (rec == null) {
                rec = new StudentRecord(pc);
                if (!"—".equals(student)) rec.student = student;
                if (!"—".equals(course)) rec.course = course;
                students.put(key, rec);
            }
            return rec;
        }
    }

    // -------------------------------------------------------------- detail ----

    private void openDetailOfSelected() {
        int row = studentTable.getSelectedRow();
        if (row < 0 || row >= studentModel.getRowCount()) return;
        String student = String.valueOf(studentModel.getValueAt(row, 0));
        String pc = String.valueOf(studentModel.getValueAt(row, 1));
        StudentRecord rec = students.get(keyOf(pc, student));
        if (rec == null) return;
        synchronized (rec) {
            detailStudent = rec;
            selectedKey = keyOf(pc, student);
            eventModel.setRowCount(0);
            for (String[] ev : rec.events) {
                eventModel.addRow(new Object[]{ev[0], ev[1], ev[2]});
            }
            detailTitle.setText("Student " + rec.student + "  ·  PC " + rec.pc
                    + "  ·  " + rec.course + "  —  " + rec.status());
            detailTitle.setForeground("CHEAT CONFIRMED".equals(rec.verdict) ? new Color(0xFFB4BA)
                    : rec.suspicious ? new Color(0xFFF0A8) : UITheme.ACCENT_TEAL);
            markCheatBtn.setEnabled(!"CHEAT CONFIRMED".equals(rec.verdict));
            markClearedBtn.setEnabled(true);
        }
        showingDetail = true;
        centerHost.removeAll();
        centerHost.add(detailPanel, BorderLayout.CENTER);
        centerHost.revalidate();
        centerHost.repaint();
    }

    private void showList() {
        showingDetail = false;
        detailStudent = null;
        rebuildStudentTable();
        centerHost.removeAll();
        centerHost.add(listPanel, BorderLayout.CENTER);
        centerHost.revalidate();
        centerHost.repaint();
    }

    private void applyVerdict(String verdict) {
        if (detailStudent == null) return;
        synchronized (detailStudent) {
            detailStudent.verdict = verdict;
        }
        writeCsv(new SimpleDateFormat("HH:mm:ss").format(new Date()), detailStudent.pc,
                detailStudent.student, detailStudent.course, "VERDICT",
                "Invigilator marked this student: " + verdict);
        openDetailOfSelected(); // refresh title + buttons
        rebuildStudentTable();
    }

    // ------------------------------------------------------- student table ----

    /** Rebuild the student list: cheat-confirmed first, then suspicious (most
     *  recent red first), then the rest by last activity. */
    private void rebuildStudentTable() {
        List<StudentRecord> sorted;
        synchronized (students) {
            sorted = new ArrayList<>(students.values());
        }
        sorted.sort((a, b) -> {
            int ra = rank(a);
            int rb = rank(b);
            if (ra != rb) return Integer.compare(ra, rb);
            return Long.compare(b.lastActivity, a.lastActivity);
        });
        studentModel.setRowCount(0);
        SimpleDateFormat fmt = new SimpleDateFormat("HH:mm:ss");
        for (StudentRecord rec : sorted) {
            long reds;
            long seen;
            synchronized (rec) {
                reds = rec.events.stream().filter(ev -> "RED FLAG".equals(ev[1])).count();
                seen = rec.lastActivity;
            }
            studentModel.addRow(new Object[]{
                    rec.student, rec.pc, rec.course, rec.status(), reds,
                    seen == 0 ? "—" : fmt.format(new Date(seen))});
        }
        if (selectedKey != null) {
            for (int i = 0; i < studentModel.getRowCount(); i++) {
                String k = keyOf(String.valueOf(studentModel.getValueAt(i, 1)),
                        String.valueOf(studentModel.getValueAt(i, 0)));
                if (k.equals(selectedKey)) {
                    studentTable.setRowSelectionInterval(i, i);
                    break;
                }
            }
        }
    }

    private static int rank(StudentRecord rec) {
        if ("CHEAT CONFIRMED".equals(rec.verdict)) return 0;
        if (rec.suspicious) return 1;
        return 2;
    }

    // ------------------------------------------------------- firewall + csv ----

    private void openFirewall() {
        runQuiet("netsh", "advfirewall", "firewall", "add", "rule",
                "name=CheatGuard Central Monitor", "dir=in", "action=allow",
                "protocol=TCP", "localport=" + CENTRAL_TCP_PORT);
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
            File dir = new File(System.getProperty("user.home"), "CheatGuard-Central");
            if (!dir.exists()) dir.mkdirs();
            File csvFile = new File(dir, "central-log-"
                    + new SimpleDateFormat("yyyyMMdd").format(new Date()) + ".csv");
            csvWriter = new BufferedWriter(new FileWriter(csvFile, true));
            csvWriter.write("time,pc,student,course,level,event\n");
        } catch (Exception e) {
            csvWriter = null;
        }
    }

    private void writeCsv(String time, String pc, String student, String course, String level, String event) {
        BufferedWriter writer = csvWriter;
        if (writer == null) return;
        try {
            synchronized (this) {
                writer.write(csv(time) + "," + csv(pc) + "," + csv(student) + ","
                        + csv(course) + "," + csv(level) + "," + csv(event) + "\n");
                writer.flush();
            }
        } catch (Exception ignored) {
        }
    }

    private static String csv(String v) {
        String s = v == null ? "" : v.replace("\"", "'").replace("\n", " ").replace("\r", " ");
        return "\"" + s + "\"";
    }

    /** This machine's LAN IP, shown so the invigilator can share it with students. */
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

    private static String randomCode() {
        StringBuilder sb = new StringBuilder();
        java.util.Random r = new java.util.Random();
        for (int i = 0; i < 6; i++) sb.append("0123456789".charAt(r.nextInt(10)));
        return sb.toString();
    }

    private static void sleepQuiet(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
        }
    }
}
