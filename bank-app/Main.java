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
            //amount to deposit or withdrawl
            long amount = 0;
            boolean actionRes = false;

            switch(userChoice)
            {
                case "1":
                    System.out.println("\nCurrent account balance: " + DatabaseController.getBalanceFormatted(loggedInUsername) + "\n");
                break;

                case "2":
                    System.out.print("Enter the amount to deposit (in dollars): ");
                    amount = scan.nextLong();
                    scan.nextLine();
                    actionRes = DatabaseController.deposit(loggedInUsername, amount * 100);
                    if(actionRes)
                        System.out.println("\nDeposited $" + amount + " in account successfully.\n");
                    else
                        System.out.println("\nTransaction could not complete, try again later.\n");
                break;

                case "3":
                    System.out.print("Enter the amount to withdrawl (in dollars): ");
                    amount = scan.nextLong();
                    scan.nextLine();
                    actionRes = DatabaseController.withdraw(loggedInUsername, amount * 100);

                    if(actionRes)
                        System.out.println("\nWithdrawed $" + amount + " from account successfully.\n");
                    else
                        System.out.println("\nTransaction could not complete, try again later.\n");
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
