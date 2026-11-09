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
                    AuditLogger.log("BALANCED_VIEWED", loggedInUsername); //log viewed account balance
                break;

                case "2":
                    System.out.print("Enter the amount to deposit (in dollars): ");
                    amount = scan.nextLine();

                    cents = DatabaseController.dollarsToCents(amount);

                    if(cents == -1)
                    {
                        System.out.println("\nInvalid amount. Enter something like 25 or 25.50\n");
                        AuditLogger.log("DEPOSIT_FAILURE", loggedInUsername); //log fail to deposit
                        break;
                    }

                    actionRes = DatabaseController.deposit(loggedInUsername, cents);
                    if(actionRes)
                    {
                        System.out.println("\nDeposited " + DatabaseController.formatCents(cents) + " in account successfully.\n");
                        AuditLogger.log("DEPOSIT_SUCCESS", loggedInUsername); //log deposit success
                    }
                    else
                    {
                        System.out.println("\nTransaction could not complete, try again later.\n");
                        AuditLogger.log("DEPOSIT_FAILURE", loggedInUsername);
                    }
                 break;

                case "3":
                    System.out.print("Enter the amount to withdraw (in dollars): ");
                    amount = scan.nextLine();
                     
                    cents = DatabaseController.dollarsToCents(amount);

                    if(cents == -1)
                    {
                        System.out.println("\nInvalid amount. Enter something like 25 or 25.50\n");
                        AuditLogger.log("WITHDRAWAL_FAILURE", loggedInUsername); //log fail to withdrawal b/c of invalid amount
                        break;
                    }

                    actionRes = DatabaseController.withdraw(loggedInUsername, cents);

                    if(actionRes)
                    {
                        System.out.println("\nWithdrawed " + DatabaseController.formatCents(cents) + " from account successfully.\n");
                        AuditLogger.log("WITHDRAWAL_SUCCESS", loggedInUsername); //log successful withdrawal
                    }
                    else
                    {
                        System.out.println("\nTransaction could not complete, try again later.\n");
                        AuditLogger.log("WITHDRAWAL_FAILURE", loggedInUsername); //log failure to withdraw
                    }
                 break;

                default:
                    System.out.println("\nNot an option, try entering \"1\", \"2\", or \"3\"\n");
                    AuditLogger.log("INVALID_MENU_CHOICE", loggedInUsername); //log a selecion of an invalid menu option
                break;
            }

            UserInterface.menu();
            userChoice = scan.nextLine();
        }

        AuditLogger.log("LOGOUT", loggedInUsername); //log when the user exits the application

        scan.close();
         
    }
}
