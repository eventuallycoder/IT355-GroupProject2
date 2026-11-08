public class PasswordValidator {
    
    /**
     * 
     * @param password must be >= 12
     * @return trye if password is at appropriate length, false if it is less than 12
     */
    public static boolean isValid(String password)
    {
        if(password.length() >= 12)
        {
            boolean hasUpper = false, hasLower = false, hasDigit = false;

            for(int i = 0; i < password.length(); i++)
            {
                char c = password.charAt(i);
                if(Character.isUpperCase(c))
                    hasUpper = true;
                if(Character.isLowerCase(c))
                    hasLower = true;
                if(Character.isDigit(c))
                    hasDigit = true;
            }

            if(hasUpper && hasLower && hasDigit)
                return true;
        }

        return false;
    }
}
