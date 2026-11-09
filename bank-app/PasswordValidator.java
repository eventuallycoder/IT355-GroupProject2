public class PasswordValidator {
    
    private static final String[] commonPasswords = {"Password1234!","Welcome12345!","Qwerty123456!", "Letmein12345","Admin1234567!", "12345678910!","Mypassword12!", "passwordOkay!", "QWERTYUIOP1!"};
    
    /**
     * @param password must be >= 12, contain at least one uppercase character, lowercase character, and digit
     * @param username must not be contained within password
     * @return trye if password is at appropriate length with appropriate characters, false if it is less than 12 with without adding appropriate characters
     */
    public static boolean isValid(String password, String username)
    {
        //check if the password is any common password
        for(String pass : commonPasswords)
        {
            if(pass.equalsIgnoreCase(password))
                return false;
        }

        //check if the username is inside the password
        if(password.toLowerCase().contains(username.toLowerCase()))
            return false;
        
        //validate the password is appropriate length, containing the appropriate characters and digits
        if(password.length() >= 12)
        {
            boolean hasUpper = false, hasLower = false, hasDigit = false, hasSpecial = false;

            for(int i = 0; i < password.length(); i++)
            {
                char c = password.charAt(i);
                if(Character.isUpperCase(c))
                    hasUpper = true;
                if(Character.isLowerCase(c))
                    hasLower = true;
                if(Character.isDigit(c))
                    hasDigit = true;
                if(!Character.isLetterOrDigit(c))
                    hasSpecial = true;
            }

            if(hasUpper && hasLower && hasDigit && hasSpecial)
                return true;
        }
        return false;
    }
}
