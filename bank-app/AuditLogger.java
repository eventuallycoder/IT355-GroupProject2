import java.io.FileWriter;
import java.io.IOException;
import java.time.LocalDateTime;

public class AuditLogger {
    
    //logs login and signup events in audit.log file
    public static void log(String event, String username){
             
        
        try(FileWriter writer = new FileWriter("audit.log", true)) {
                writer.write("\n" + LocalDateTime.now().toString() + " | " + event + " | " + username);
        } 
        catch (IOException e) {
            System.out.println("\nWarning: could not write to audit log\n");
        }
    }
}
