import com.cheatguard.watchdog.DnsAllowlistServer;
import com.cheatguard.watchdog.WatchdogEngine;

import java.util.List;

/** Ad-hoc verification for the fixed title-path rule and DNS answer bounds. */
public class SanityFixesTest {
    static int fail = 0;

    static void expect(String name, boolean ok) {
        System.out.println((ok ? "PASS " : "FAIL ") + name);
        if (!ok) fail++;
    }

    public static void main(String[] args) {
        String sep = java.io.File.separator;
        String exam = "C:" + sep + "Users" + sep + "t" + sep + "Desktop" + sep + "Exam_1";

        expect("https URL title clean",
                WatchdogEngine.titlePathOutside("spec https://example.org/handout - Editor", exam) == null);
        expect("http URL arg clean",
                WatchdogEngine.runtimeArgOutside(
                        new String[]{"submit.py", "https://exam-server/submit"}, exam) == null);
        expect("outside path flagged",
                WatchdogEngine.titlePathOutside("C:" + sep + "Users" + sep + "t" + sep + "notes.txt - Notepad++", exam) != null);
        expect("bare exam folder path clean",
                WatchdogEngine.titlePathOutside(exam + " - VS Code", exam) == null);
        expect("sibling folder Exam_10 still flagged",
                WatchdogEngine.titlePathOutside(exam + "0" + sep + "notes.txt - Editor", exam) != null);
        expect("sibling folder Exam_1-backup still flagged",
                WatchdogEngine.titlePathOutside(exam + "-backup" + sep + "notes.txt - Editor", exam) != null);
        expect("inside file still clean",
                WatchdogEngine.titlePathOutside(exam + sep + "main.cpp - Notepad++", exam) == null);

        // Truncated DNS answer: loop guard satisfied before skipName, then the
        // fixed RR header read must not run past the end of the message.
        byte[] msg = new byte[20];
        msg[4] = 0; msg[5] = 1; // QDCOUNT 1
        msg[6] = 0; msg[7] = 1; // ANCOUNT 1
        msg[12] = 0;            // question: root label -> QTYPE/QCLASS = 4 bytes... message ends here
        msg[16] = (byte) 0xC0; msg[17] = 0x0C; // answer owner: compression pointer
        List<String> ips = DnsAllowlistServer.parseAnswerIps(msg);
        expect("truncated answer no throw, empty", ips.isEmpty());
        expect("null message no throw", DnsAllowlistServer.parseAnswerIps(null).isEmpty());

        System.out.println(fail == 0 ? "SANITY OK" : fail + " FAILURES");
        if (fail > 0) System.exit(1);
    }
}
