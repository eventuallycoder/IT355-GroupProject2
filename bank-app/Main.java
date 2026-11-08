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
            String amount = "";

            boolean actionRes = false;
            long cents;

            switch(userChoice)
            {
                case "1":
                    System.out.println("\nCurrent account balance: " + DatabaseController.getBalanceFormatted(loggedInUsername) + "\n");
                break;

                case "2":
                    System.out.print("Enter the amount to deposit (in dollars): ");
                    amount = scan.nextLine();

                    cents = DatabaseController.dollarsToCents(amount);

                    if(cents == -1)
                    {
                        System.out.println("\nInvalid amount. Enter something like 25 or 25.50\n");
                        break;
                    }

                    actionRes = DatabaseController.deposit(loggedInUsername, cents);
                    if(actionRes)
                        System.out.println("\nDeposited $" + DatabaseController.formatCents(cents) + " in account successfully.\n");
                    else
                        System.out.println("\nTransaction could not complete, try again later.\n");
                break;

                case "3":
                    System.out.print("Enter the amount to withdrawl (in dollars): ");
                    amount = scan.nextLine();
                     
                    cents = DatabaseController.dollarsToCents(amount);


                    actionRes = DatabaseController.withdraw(loggedInUsername, cents);

                    if(actionRes)
                        System.out.println("\nWithdrawed $" + DatabaseController.formatCents(cents) + " from account successfully.\n");
                    else
                        System.out.println("\nTransaction could not complete, try again later.\n");
                break;

                default:
                    System.out.println("\nNot an option, try entering \"1\", \"2\", or \"3\"\n");
                break;
            }

            UserInterface.menu();
            userChoice = scan.nextLine();
        }

        scan.close();
         
    }
}
