import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

public class PasswordValidator {
    
    // SHA-256 hashes of the lowercase common passwords
    //Example of CWE-256
    private static final String[] commonPasswordHashes = {
        "870266392ce3ae61c88f44857828f2dca6095f2ebe9c12b7bf1af4a21b6fa260",
        "753aa85b30558ef4566834fe8f5791ed435dfbd9e54b5ccfba6194817d49994b",
        "0414d5f0e3c119243d9a966910e3242321c11788437592fac4f8a3a604e6f251",
        "3a4e404777ea37936b9821670c5d04391855d4d1f9cf5ab4ba45ff5c926d10c9",
        "622ea2348c2366f88c0d0eb6d65cd98e1b65e820ec930ed3cbbebf33625d166a",
        "7aab3ef7f302bb05220c01bf9d97cf3b22ae03995e4470cfe0f48d4ce1b72e56",
        "78b2ab8f76c808e1f1cec06f967bd3d2be9973acce50fb640946e176bd3ff60d",
        "9c798008ec5fefb300ff3bb0bbc7b86d709bde94ed134a6d701d4f727c47752f",
        "477623a90c6841c9412673de2be09fbb1086b6cebbff96a248636b35ad1ff871"
    };
    
    /**
     * @param password must be >= 12, contain at least one uppercase character, lowercase character, and digit
     * @param username must not be contained within password
     * @return true if password is at appropriate length with appropriate characters, false if it is less than 12 with without adding appropriate characters
     */
        public static boolean isValid(String password, String username) //this covers CWE-521
    {
        // CWE-229: Reject null values, blank usernames (which cause .contains("") to always be true), and oversized inputs
        if (password == null || username == null || username.isBlank() || password.length() > 128) {
            return false;
        }

        // CWE-229: Use Locale.ROOT to prevent locale-dependent case conversion bugs
        String lowerPass = password.toLowerCase(java.util.Locale.ROOT);
        String lowerUser = username.trim().toLowerCase(java.util.Locale.ROOT);

        // Hash the lowercase input to preserve case-insensitive matching
        String hashedInput = sha256(lowerPass);

        // Check if the password is any common password
        for (String passHash : commonPasswordHashes) {
            if (passHash.equals(hashedInput)) {
                return false;
            }
        }

        // Check if the username is inside the password
        if (lowerPass.contains(lowerUser)) {
            return false;
        }
        
        // Validate the password is appropriate length, containing the appropriate characters and digits
        if (password.length() >= 12) {
            boolean hasUpper = false, hasLower = false, hasDigit = false, hasSpecial = false;

            for (int i = 0; i < password.length(); i++) {
                char c = password.charAt(i);
                // CWE-229: Reject control characters (like newlines/null bytes) in passwords
                if (Character.isISOControl(c)) {
                    return false;
                }
                if (Character.isUpperCase(c))
                    hasUpper = true;
                if (Character.isLowerCase(c))
                    hasLower = true;
                if (Character.isDigit(c))
                    hasDigit = true;
                if (!Character.isLetterOrDigit(c) && !Character.isWhitespace(c))
                    hasSpecial = true;
            }

            if (hasUpper && hasLower && hasDigit && hasSpecial) {
                return true;
            }
        }
        return false;
    }
    private static String sha256(String input) {
        // CWE-229: Guard helper method against null input
        if (input == null) {
            throw new IllegalArgumentException("Input cannot be null");
        }
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not found", e);
        }
    }
}