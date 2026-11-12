//stores the current user (the one using the application) //This is used for CWE-306 and CWE-841
public class Session {
    
    private static String currentUser = null; //set to null when nobody is logged in

    //sets the currentUser to null
    public static void end()
    {
        currentUser = null;
    }

    //sets currentUser to the username
    public static void start(String username)
    {
        // CWE-229: Reject null or blank usernames so an empty session cannot be marked active
        if (username == null || username.isBlank()) {
            throw new IllegalArgumentException("Cannot start session with null or blank username");
        }
        // CWE-229: Normalize surrounding whitespace to match database user records
        currentUser = username.trim();
    }

    /**
     * 
     * @return true if currentUser is not null (meaning someone is actively using the application)
     */
    public static boolean isActive()
    {
        // CWE-229: Ensure currentUser is neither null nor blank
        if(currentUser != null && !currentUser.isBlank())
            return true;

        return false;

    }

    /**
     * 
     * @param username a give username
     * @return true if currentUser is not null and matches the username
     */
    public static boolean isUser(String username)
    {
        // CWE-229: Guard against null or blank username before comparison to prevent NullPointerException
        if (username == null || username.isBlank()) {
            return false;
        }

        if(isActive())
            if(currentUser.equalsIgnoreCase(username.trim())) // CWE-229: Normalize whitespace on comparison
                return true;
    
        return false;
    }
}
