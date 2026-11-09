//This class is responsible for logging a user into their account or creating a user account

import java.util.Scanner;

public class UserLogin {

    //this logs in a user or creates a users account
    public static String login(Scanner scan)
    {
        UserInterface.printLoginMessage();
        
        String username, password;
        String loginChoice;

        loginChoice = scan.nextLine();
 
        while(!(loginChoice.equals("0") || loginChoice.equals("1")))
        {
            System.out.print("\nEnter 0 or 1: ");
            loginChoice = scan.nextLine();
        }

        boolean auth = false;
        if(loginChoice.equals("1"))
        {
                System.out.print("Enter username: ");
                username = scan.nextLine();
                System.out.print("Enter password: ");
                password = scan.nextLine();
                auth = DatabaseController.authenticate(username, password);
                if(auth == true)
                {
                    AuditLogger.log("LOGIN_SUCCESS", username);
                    return username;
                }
                else 
                {
                    AuditLogger.log("LOGIN_FAILURE", "-");
                    return "";
                }
                    
        }      
        else
        {
                System.out.print("Enter username: ");
                username = scan.nextLine();
                System.out.print("Enter password: ");
                password = scan.nextLine();

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
