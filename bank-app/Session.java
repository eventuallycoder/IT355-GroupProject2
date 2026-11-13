import java.util.Locale;

//stores the current user (the one using the application) 
//This is used for CWE-306/CWE-841/CWE-178/CWE-229 
public class Session {
    
    private static String currentUser = null; //set to null when nobody is logged in

    //CWE-425: the session itself expires, so a protected call made after the user has gone idle is denied
    //even if it never passes through the menu loop in Main (every protected DatabaseController method asks Session)
    private static final long SESSION_TIMEOUT_NANOS = 5L * 60L * 1_000_000_000L; //5 minutes, same as Main
    private static long lastActivityNanos = 0;


    //sets the currentUser to null
    public static void end()
    {
        currentUser = null;
        lastActivityNanos = 0;
    }

    //sets currentUser to the normalized canonical username
    public static void start(String username)
    {
        // CWE-229: Reject null or blank usernames so an empty session cannot be marked active
        if (username == null || username.isBlank()) {
            throw new IllegalArgumentException("Cannot start session with null or blank username");
        }
        // CWE-178 & CWE-229: Normalize whitespace and casing with Locale.ROOT for consistent session/audit records
        currentUser = username.trim().toLowerCase(Locale.ROOT);
        lastActivityNanos = System.nanoTime();
    }

    //CWE-425: call whenever the logged in user does something, restarts the idle timer
    public static void touch()
    {
        if (currentUser != null) {
            lastActivityNanos = System.nanoTime();
        }
    }


    /**
     * 
     * @return true if currentUser is not null (meaning someone is actively using the application)
     */
    public static boolean isActive()
    {
        // CWE-229: Ensure currentUser is neither null nor blank
        if(currentUser != null && !currentUser.isBlank()){
            //CWE-425: an expired session is ended and treated as nobody being logged in
            if(System.nanoTime() - lastActivityNanos > SESSION_TIMEOUT_NANOS)
            {
                end();
                return false;
            }
    
            return true;
        }
        return false;

    }

    /**
     * 
     * @param username a given username
     * @return true if currentUser is not null and matches the username
     */
    public static boolean isUser(String username)
    {
        // CWE-229: Guard against null or blank username before comparison to prevent NullPointerException
        if (username == null || username.isBlank()) {
            return false;
        }

        // CWE-178: Use Locale.ROOT instead of equalsIgnoreCase to avoid locale-specific case bugs (e.g., Turkish-I)
        if(isActive()) {
            String normalizedInput = username.trim().toLowerCase(Locale.ROOT);
            if(currentUser.equals(normalizedInput))
                return true;
        }
    
        return false;
    }
}
