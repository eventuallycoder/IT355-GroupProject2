import java.io.FileWriter;
import java.io.IOException;
import java.time.LocalDateTime;

public class AuditLogger {
    
    //logs login and signup events in audit.log file
    public static void log(String event, String username){ //this covers CWE-778 
      
        log(event, username, null);
      
    }

    public static void log(String event, String username, String detail)
    {
        event = sanitize(event);
        username = sanitize(username);

        // CWE-229: Treat blank/whitespace-only detail strings the same as null so empty columns are not written
        if(detail != null && !detail.isBlank())
        {
            detail = sanitize(detail);

            try(FileWriter writer = new FileWriter("audit.log", true)) {
                writer.write("\n" + LocalDateTime.now().toString() + " | " + event + " | " + username + " | " + detail);
            } 
            catch (IOException e) {
            System.out.println("\nWarning: could not write to audit log\n");
            }
        }
        else
        {
            try(FileWriter writer = new FileWriter("audit.log", true)) {
                writer.write("\n" + LocalDateTime.now().toString() + " | " + event + " | " + username);
            } 
            catch (IOException e) {
            System.out.println("\nWarning: could not write to audit log\n");
            }
        }
    }

    //cleans up a string, so it won't clog the audit log, this covers CWE-779
    private static String sanitize(String text)
    {
        if(text == null || text.isBlank())
        {
            return "-";
        }

        text = text.replaceAll("\\p{Cntrl}", " "); //replaces any control characters (tabs, carriage, returns, etc)

        text = text.replace("|","/"); //makes it so no username can fake the column separator

        // CWE-229: Trim surrounding whitespace after control-character replacement to prevent blank or padded fields
        text = text.trim();
        if (text.isEmpty()) {
            return "-";
        }

        if(text.length() > 30) //cut down the text so its less than 30 characters
        {
            text = text.substring(0,30);
        }

        return text;
    }
}
