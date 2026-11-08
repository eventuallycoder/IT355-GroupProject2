import java.util.Scanner;

public class Main {

    public static Scanner scan = new Scanner(System.in);
    public static void main(String[] args) {
        
        DatabaseController.createTables();

        //log the user in (by either creating an account or logging into preexisitng account)
        String loggedInUsername = UserLogin.login(scan);
        
        if(!loggedInUsername.isBlank())
        {
            System.out.println("\nWelcome!\n");
        }
         else
        {
            System.out.println("Authentication could not complete, please try again.");
            System.exit(0);
        }

        //show the user the menu until they quit
        String userChoice = "";

        UserInterface.menu();

        userChoice = scan.nextLine();

        while(!userChoice.equals("4"))
        {
            switch(userChoice)
            {
                case "1":

                break;

                case "2":
                
                break;

                case "3":
                
                break;

                default:
                    System.out.println("Not an option, try entering \"1\", \"2\", or \"3\"");
                break;


            }


            UserInterface.menu();
            userChoice = scan.nextLine();
        }

        scan.close();
         
    }
}
