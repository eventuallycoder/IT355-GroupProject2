import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.text.Normalizer;
import java.time.LocalDateTime;


public class AuditLogger {

    private static final String LOG_FILE = "audit.log";
    private static final int MAX_FIELD_LENGTH = 30;

    
    //logs login and signup events in audit.log file
    public static void log(String event, String username){ //this covers CWE-778 
      
        log(event, username, null);
      
    }

    public static void log(String event, String username, String detail)
    {

        //CWE-117: every field is neutralized before it is placed in the log line
        StringBuilder line = new StringBuilder();
        line.append(LocalDateTime.now().toString())
            .append(" | ").append(sanitize(event))
            .append(" | ").append(sanitize(username));

        // CWE-229: Treat blank/whitespace-only detail strings the same as null so empty columns are not written
        if(detail != null && !detail.isBlank())
        {
            line.append(" | ").append(sanitize(detail));
        }

        //CWE-117: the ONLY line terminator in the file is the one the logger adds itself
        line.append(System.lineSeparator());

        try {
            //CWE-22 / CWE-434: the log path is fixed and checked, never built from input
            Path logPath = SafePaths.resolveInside(SafePaths.APP_DIR, LOG_FILE);
 
            //one write call per entry so entries can't be interleaved or split
            Files.writeString(logPath, line.toString(), StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        }
        catch (IOException e) {
            System.out.println("\nWarning: could not write to audit log\n");
        }

    }

    //cleans up a string, so it won't clog the audit log, this covers CWE-779 and CWE-117
    private static String sanitize(String text)
    {
        //Covers CWE-233: Guard against null or blank input to prevent NullPointerException and empty log entries
        if(text == null || text.isBlank())
        {
            return "-";
        }

        //CWE-117: NFKC folds look-alike characters (like the fullwidth bar U+FF5C) into their plain ASCII
        //form so the replacements below can't be bypassed
        text = Normalizer.normalize(text, Normalizer.Form.NFKC);
 
        //CWE-117: replace ALL line-breaking/invisible characters, not just ASCII ones:
        //  Cc = control chars (\n, \r, \t, NUL, and C1 controls like U+0085 NEL)
        //  Zl/Zp = Unicode line/paragraph separators (U+2028, U+2029), which many log viewers treat as newlines
        //  Cf = format chars (bidi overrides like U+202E, zero-width chars) that can make an entry display differently than it is stored
        text = text.replaceAll("[\\p{Cc}\\p{Cf}\\p{Zl}\\p{Zp}]", " ");
 
        text = text.replace("|","/"); //makes it so no username can fake the column separator
 
        // CWE-229: Trim surrounding whitespace after control-character replacement to prevent blank or padded fields
        text = text.trim();
        if (text.isEmpty()) {
            return "-";
        }
 
        //cut down the text to MAX_FIELD_LENGTH characters. Counted in code points so a surrogate pair is never split in half
        if(text.codePointCount(0, text.length()) > MAX_FIELD_LENGTH)
        {
            text = text.substring(0, text.offsetByCodePoints(0, MAX_FIELD_LENGTH)).trim();
            if (text.isEmpty()) {
                return "-";
            }
        }
 
        return text;
    }

    //CWE-276: makes audit.log owner-only; called once from Main at startup (log() itself is unchanged)
    public static void secureLogFile()
    {
        java.nio.file.Path logFile = java.nio.file.Path.of("audit.log");
        try {
            java.nio.file.Files.createFile(logFile); //CWE-367: atomic, fails if the file already exists
        }
        catch (java.nio.file.FileAlreadyExistsException e) {
            //already exists: just tighten its permissions below
        }
        catch (IOException e) {
            System.out.println("\nWarning: could not restrict audit log permissions\n");
            return;
        }

        if(!DatabaseController.restrictToOwner(logFile))
            System.out.println("\nWarning: could not restrict audit log permissions\n");
    }
}
