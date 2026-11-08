public class PasswordValidator {
    
    /**
     * 
     * @param password must be >= 12
     * @return trye if password is at appropriate length, false if it is less than 12
     */
    public static boolean isValid(String password)
    {
        if(password.length() >= 12)
            return true;

        return false;
    }
}
