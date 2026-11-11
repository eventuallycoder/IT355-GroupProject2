//stores the current user (the one using the application)
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
        currentUser = username;
    }

    /**
     * 
     * @return true if currentUser is not null (meaning someone is actively using the application)
     */
    public static boolean isActive()
    {
        if(currentUser != null)
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
        if(isActive())
            if(username.equalsIgnoreCase(currentUser))
                return true;
    
        return false;
    }

    
}
