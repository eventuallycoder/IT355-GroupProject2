//This class is responsible for logging a user into their account or creating a user account

import java.util.Scanner;

public class UserLogin {

    //this logs in a user or creates a users account
        public static String login(Scanner scan)
    {
        UserInterface.printLoginMessage();
        
        String username, password;
        String loginChoice;

        // CWE-229: Guard against missing input stream lines (EOF) and normalize whitespace
        if (!scan.hasNextLine()) return "";
        loginChoice = scan.nextLine().trim();

        while(!(loginChoice.equals("0") || loginChoice.equals("1")))
        {
            System.out.print("\nEnter 0 or 1: ");
            // CWE-229: Guard against EOF inside retry loop
            if (!scan.hasNextLine()) return "";
            loginChoice = scan.nextLine().trim();
        }

        boolean auth = false;
        if(loginChoice.equals("1"))
        {
                System.out.print("Enter username: ");
                // CWE-229: Guard against EOF and strip surrounding whitespace from username
                if (!scan.hasNextLine()) return "";
                username = scan.nextLine().trim();
                password = UserInterface.readPassword(scan, "Enter password: "); //securely read password

                // CWE-229: Reject blank usernames or null/empty passwords before querying lockout or auth state
                if (username.isEmpty() || password == null || password.isEmpty()) {
                    System.out.println("Invalid username or password, or the account is temporarily locked.");
                    return "";
                }
                  
                if(DatabaseController.isLocked(username) == true) //checks if the user is locked, if they are don't let them login
                {
                    AuditLogger.log("LOGIN_BLOCKED", "-");
                    System.out.println("Invalid username or password, or the account is temporarily locked.");
                    return "";
                }

                if(DatabaseController.getFailedAttempts(username) >= 3) //account isn't locked now, but still has the old failed attempts amount
                {
                    DatabaseController.resetFailedLogins(username);
                    AuditLogger.log("ACCOUNT_UNLOCKED", username);
                }

                auth = DatabaseController.authenticate(username, password);
                if(auth == true)
                {
                    DatabaseController.resetFailedLogins(username); //Reset the failed login attempts (if there are any)
                    AuditLogger.log("LOGIN_SUCCESS", username);
                    return username;
                }
                else 
                {
                    AuditLogger.log("LOGIN_FAILURE", "-");
                    DatabaseController.recordFailedLogin(username);

                    if(DatabaseController.getFailedAttempts(username) >= 3) //user is locked out of their account for 15 minutes
                    {
                        DatabaseController.lockUser(username, 15); //15 minutes til they can use account again
                        AuditLogger.log("ACCOUNT_LOCKED", username);
                        System.out.println("Too many failed attempts, try again later. ");
                    }

                    return "";
                }
                    
        }      
        else
        {
                System.out.print("Enter username: ");
                // CWE-229: Guard against EOF and strip surrounding whitespace from username
                if (!scan.hasNextLine()) return "";
                username = scan.nextLine().trim();
                password = UserInterface.readPassword(scan, "Enter password: "); //securely read password

                // CWE-229: Reject blank usernames or null passwords before validation and signup
                if (username.isEmpty() || password == null) {
                    AuditLogger.log("SIGNUP_FAILURE", "-");
                    return "";
                }

                //check if the password is of valid length, if not the user signup will fail
                if(PasswordValidator.isValid(password, username) == false)
                {
                    UserInterface.printPasswordRules();
                    AuditLogger.log("SIGNUP_FAILURE", "-");
                    return "";
                }
                

                auth = DatabaseController.signUp(username, password);
                if(auth == true)
                {
                    AuditLogger.log("SIGNUP_SUCCESS", username);
                    return username;
                }
                else 
                {
                    AuditLogger.log("SIGNUP_FAILURE", "-");
                    return "";
                }
        }
    }
}