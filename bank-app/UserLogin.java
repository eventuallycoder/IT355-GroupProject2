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
            System.out.print("Enter 0 or 1: ");
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
                    return username;
                else 
                    return "";
        }      
        else
        {
                System.out.print("Enter username: ");
                username = scan.nextLine();
                System.out.print("Enter password: ");
                password = scan.nextLine();
                auth = DatabaseController.signUp(username, password);
                if(auth == true)
                    return username;
                else 
                    return "";
        }

        
         
        
    }

     
}
