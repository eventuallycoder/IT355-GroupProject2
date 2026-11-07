//This class is responsible for logging a user into their account or creating a user account

import java.util.Scanner;

public class UserLogin {



    public static boolean login()
    {
        UserInterface.printLoginMessage();

        Scanner scan = new Scanner(System.in);   
        
        String username, password;
        String loginChoice;

        loginChoice = scan.nextLine();

        while(!(loginChoice.equals("0") || loginChoice.equals("1")))
        {
            System.out.print("Enter 0 or 1: ");
            loginChoice = scan.nextLine();
        }

        if(loginChoice.equals("1"))
        {
                System.out.print("Enter username: ");
                username = scan.nextLine();
                System.out.print("Enter password: ");
                password = scan.nextLine();
                return DatabaseController.authenticate(username, password);
        }      
        else
        {
                System.out.print("Enter username: ");
                username = scan.nextLine();
                System.out.print("Enter password: ");
                password = scan.nextLine();
                return DatabaseController.signUp(username, password);
        }

        
        
        
    }

     
}
