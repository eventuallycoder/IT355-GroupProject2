import java.util.Scanner;

//CWE 89 & CWE 79 are not included as this is a console application and does not have a web interface, so SQL injection and XSS are not applicable.
public class Main {

    public static Scanner scan = new Scanner(System.in);
    public static void main(String[] args) {

        DatabaseController.requirePepper();
        
        DatabaseController.createTables();  

        
        int attempts = 0; //keeps track of the number of log in attempts (locks at 3)
        
        //log the user in (by either creating an account or logging into preexisitng account)
        String loggedInUsername = "";
        while(loggedInUsername.equals("") && attempts < 3)
        {
            loggedInUsername = UserLogin.login(scan);

            // CWE-229: Guard against unexpected null return from login handler
            if (loggedInUsername == null) {
                loggedInUsername = "";
            }

            if(loggedInUsername.equals("")) //user failed to login/signup
            {
                attempts += 1;
                System.out.println("Login failed. Attempts remaining: " + (3 - attempts) + "\n");
            }
        }

        if(!loggedInUsername.isBlank()) //successfully logged in/created account
        {
            System.out.println("Welcome!\n");
            Session.start(loggedInUsername); //start the session for the logged in user (and no one else)
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

        // CWE-229: Guard against EOF on input stream and normalize surrounding whitespace
        if (!scan.hasNextLine()) {
            AuditLogger.log("LOGOUT", loggedInUsername);
            Session.end();
            scan.close();
            return;
        }
        userChoice = scan.nextLine().trim();
        
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
                    // CWE-229: Guard against EOF and strip whitespace from currency input
                    if (!scan.hasNextLine()) break;
                    amount = scan.nextLine().trim();

                    cents = DatabaseController.dollarsToCents(amount);

                    // CWE-229: Reject both invalid sentinel (-1) and zero-value (0) deposits
                    if(cents <= 0)
                    {
                        System.out.println("\nInvalid amount. Enter something like 25 or 25.50\n");
                        AuditLogger.log("DEPOSIT_FAILURE", loggedInUsername); //log fail to deposit
                        break;
                    }

                    actionRes = DatabaseController.deposit(loggedInUsername, cents);
                    if(actionRes)
                    {
                        System.out.println("\nDeposited " + DatabaseController.formatCents(cents) + " in account successfully.\n");
                        AuditLogger.log("DEPOSIT_SUCCESS", loggedInUsername, DatabaseController.formatCents(cents)); //log deposit success
                    }
                    else
                    {
                        System.out.println("\nTransaction could not complete, try again later.\n");
                        AuditLogger.log("DEPOSIT_FAILURE", loggedInUsername);
                    }
                 break;

                case "3":
                    System.out.print("Enter the amount to withdraw (in dollars): ");
                    // CWE-229: Guard against EOF and strip whitespace from currency input
                    if (!scan.hasNextLine()) break;
                    amount = scan.nextLine().trim();
                     
                    cents = DatabaseController.dollarsToCents(amount);

                    // CWE-229: Reject both invalid sentinel (-1) and zero-value (0) withdrawals
                    if(cents <= 0)
                    {
                        System.out.println("\nInvalid amount. Enter something like 25 or 25.50\n");
                        AuditLogger.log("WITHDRAWAL_FAILURE", loggedInUsername); //log fail to withdrawal b/c of invalid amount
                        break;
                    }

                    System.out.print("Withdraw " + DatabaseController.formatCents(cents) + " (y/n): "); //confirm the user wants to withdraw money, start of CWE-841 (the rest below: reauth and then finally withdraw)

                    // CWE-229: Guard against EOF and trim confirmation response
                    if(!scan.hasNextLine() || !scan.nextLine().trim().equalsIgnoreCase("y")) 
                    {
                        AuditLogger.log("WITHDRAWAL_CANCELLED", loggedInUsername, DatabaseController.formatCents(cents));
                        System.out.println("\nWithdrawal cancelled\n");
                        break;
                    }

                    String reauthPassword = UserInterface.readPassword(scan, "Reenter password to confirm withdraw: ");
                    // CWE-229: Reject null or empty password before calling authenticate
                    if (reauthPassword == null || reauthPassword.isEmpty()) {
                        AuditLogger.log("REAUTH_FAILURE", loggedInUsername);
                        System.out.println("Incorrect password. Withdrawal cancelled.\n");
                        break;
                    }

                    boolean isAuth = DatabaseController.authenticate(loggedInUsername, reauthPassword); //user must reenter password before withdrawing money, this covers CWE-306

                    if(isAuth == false) //incorrect password given for reauthentication
                    {
                        AuditLogger.log("REAUTH_FAILURE", loggedInUsername);
                        System.out.println("Incorrect password. Withdrawal cancelled.\n");
                        break;
                    }

                    actionRes = DatabaseController.withdraw(loggedInUsername, cents); //withdraw money from the account

                    if(actionRes)
                    {
                        System.out.println("Withdrawed " + DatabaseController.formatCents(cents) + " from account successfully.\n");
                        AuditLogger.log("WITHDRAWAL_SUCCESS", loggedInUsername, DatabaseController.formatCents(cents)); //log successful withdrawal
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
            // CWE-229: Guard against EOF on subsequent menu iterations
            if (!scan.hasNextLine()) break;
            userChoice = scan.nextLine().trim();
        }

        AuditLogger.log("LOGOUT", loggedInUsername); //log when the user exits the application
        Session.end(); //end the session for this user

        scan.close();
         
    }
}
