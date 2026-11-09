import java.util.Scanner;

public class Main {

    public static Scanner scan = new Scanner(System.in);
    public static void main(String[] args) {
        
        DatabaseController.createTables();

        //log the user in (by either creating an account or logging into preexisitng account)
        String loggedInUsername = "";
        int attempts = 0; //keeps track of the number of log in attempts (locks at 3)
        
        while(loggedInUsername.equals("") && attempts < 3)
        {
            loggedInUsername = UserLogin.login(scan);

            if(loggedInUsername.equals("")) //user failed to login/signup
            {
                attempts += 1;
                System.out.println("\nLogin failed. Attempts remaining: " + (3 - attempts) + "\n");
            }
        }

        if(!loggedInUsername.isBlank()) //successfully logged in/created account
        {
            System.out.println("\nWelcome!\n");
        }
         else //tried logging in too many times
        {
            System.out.println("Too many failed login attempts, please try again later.");
            AuditLogger.log("LOGIN_ATTEMPTS_EXCEEDED","-");
            System.exit(0);
        }

        final long TIMEOUT_MS = /*30 * 1000 */ 5 * 60 * 1000; //30 seconds vs 5 minutes
        long lastActivity = 0; //holds the time in milliseconds the last time the user entered input

        //show the user the menu until they quit
        String userChoice = "";

        lastActivity = System.currentTimeMillis(); //get the current time in milliseconds

        UserInterface.menu();

        userChoice = scan.nextLine();
        
        while(!userChoice.equals("4"))
        {

            if(System.currentTimeMillis() - lastActivity > TIMEOUT_MS) //user has been inactive for too long, this covers CWE-306 since user will most likely not be away from computer for more than 5 minutes without logging out
            {
                AuditLogger.log("SESSION_TIMEOUT", loggedInUsername);
                System.out.println("You were logged out due to inactivity");
                break;
            }

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

                    boolean isAuth = DatabaseController.authenticate(loggedInUsername, UserInterface.readPassword(scan, "Reenter password to confirm withdraw: ")); //user must reenter password before withdrawing money, this covers CWE-306

                    if(isAuth == false) //incorrect password given for reauthentication
                    {
                        AuditLogger.log("REAUTH_FAILURE", loggedInUsername);
                        System.out.println("Incorrect password. Withdrawal cancelled.\n");
                        break;
                    }

                    actionRes = DatabaseController.withdraw(loggedInUsername, cents); //withdraw money from the account

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

            lastActivity = System.currentTimeMillis(); //get the current time in milliseconds

            UserInterface.menu();
            userChoice = scan.nextLine();
        }

        AuditLogger.log("LOGOUT", loggedInUsername); //log when the user exits the application

        scan.close();
         
    }
}
