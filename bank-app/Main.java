import java.util.Scanner;

public class Main {

    public static Scanner scan = new Scanner(System.in);
    public static void main(String[] args) {

        DatabaseController.requirePepper();
        
        DatabaseController.createTables();  

        
        int attempts = 0; //keeps track of the number of log in attempts (locks at 3)
        
        //log the user in (by either creating an account or logging into preexisitng account)
        String loggedInUsername = "";
        while(loggedInUsername.equals("") && attempts < 3) //Restricts the number of login attempts to prevent a brute force attack to gain unauthorized access (CWE-307)
        {
            loggedInUsername = UserLogin.login(scan);

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

        userChoice = scan.nextLine();
        
        while(!userChoice.equals("4"))
        {
            if(System.currentTimeMillis() - lastActivity > TIMEOUT_MS) //user has been inactive for too long, this covers CWE-306 since user will most likely not be away from computer for more than 5 minutes without logging out
            {
                //this also covers CWE-1462, CWE-1463, and CWE-1464 because a user's session running for too long while inactive is a security risk, so it needs a timeout
                AuditLogger.log("SESSION_TIMEOUT", loggedInUsername);
                System.out.println("You were logged out due to inactivity");
                break;
            }

            //amount to deposit or withdrawl
            String amount = "";

            boolean actionRes = false;
            long cents;
            boolean forceLogout = false; //set to true when the user gets locked out mid-session

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
                    amount = scan.nextLine();
                     
                    cents = DatabaseController.dollarsToCents(amount);

                    if(cents == -1)
                    {
                        System.out.println("\nInvalid amount. Enter something like 25 or 25.50\n");
                        AuditLogger.log("WITHDRAWAL_FAILURE", loggedInUsername); //log fail to withdrawal b/c of invalid amount
                        break;
                    }

                    System.out.print("Withdraw " + DatabaseController.formatCents(cents) + " (y/n): "); //confirm the user wants to withdraw money, start of CWE-841 (the rest below: reauth and then finally withdraw)

                    if(!scan.nextLine().equalsIgnoreCase("y")) 
                    {
                        AuditLogger.log("WITHDRAWAL_CANCELLED", loggedInUsername, DatabaseController.formatCents(cents));
                        System.out.println("\nWithdrawal cancelled\n");
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
                        System.out.println("Withdrew " + DatabaseController.formatCents(cents) + " from account successfully.\n");
                        AuditLogger.log("WITHDRAWAL_SUCCESS", loggedInUsername, DatabaseController.formatCents(cents)); //log successful withdrawal
                    }
                    else
                    {
                        System.out.println("\nTransaction could not complete, try again later.\n");
                        AuditLogger.log("WITHDRAWAL_FAILURE", loggedInUsername); //log failure to withdraw
                    }
                 break;

                case "7": //change password
                    //ask for the old password first (input is hidden, same as at login) (CWE-620)
                    String oldPassword = UserInterface.readPassword(scan, "Enter your current password: ");

                    if(!DatabaseController.authenticate(loggedInUsername, oldPassword)) //old password must be correct before anything else
                    {
                        AuditLogger.log("PASSWORD_CHANGE_DENIED", loggedInUsername);
                        DatabaseController.recordFailedLogin(loggedInUsername); //counts toward the same failed attempts as logging in (CWE-307)

                        if(DatabaseController.getFailedAttempts(loggedInUsername) >= 3) //too many wrong passwords, lock the account for 15 minutes and end the session
                        {
                            DatabaseController.lockUser(loggedInUsername, 15);
                            AuditLogger.log("ACCOUNT_LOCKED", loggedInUsername);
                            System.out.println("\nToo many failed attempts. Your account has been locked, try again later.");
                            forceLogout = true;
                        }
                        else
                        {
                            System.out.println("\nIncorrect password. Password change cancelled.\n");
                        }
                        break;
                    }

                    DatabaseController.resetFailedLogins(loggedInUsername); //correct password, clear any previous failed attempts

                    String newPassword = UserInterface.readPassword(scan, "Enter your new password: ");

                    //new password has to meet the same rules as at signup
                    if(!PasswordValidator.isValid(newPassword, loggedInUsername))
                    {
                        UserInterface.printPasswordRules();
                        AuditLogger.log("PASSWORD_CHANGE_FAILURE", loggedInUsername);
                        System.out.println("New password does not meet the requirements. Password not changed.\n");
                        break;
                    }

                    if(newPassword.equals(oldPassword)) //must actually be a new password
                    {
                        AuditLogger.log("PASSWORD_CHANGE_FAILURE", loggedInUsername);
                        System.out.println("\nNew password must be different from your current password. Password not changed.\n");
                        break;
                    }

                    String confirmPassword = UserInterface.readPassword(scan, "Enter your new password again to confirm: ");

                    if(!newPassword.equals(confirmPassword))
                    {
                        AuditLogger.log("PASSWORD_CHANGE_FAILURE", loggedInUsername);
                        System.out.println("\nPasswords did not match. Password not changed.\n");
                        break;
                    }

                    actionRes = DatabaseController.changePassword(loggedInUsername, oldPassword, newPassword);

                    if(actionRes)
                    {
                        AuditLogger.log("PASSWORD_CHANGE_SUCCESS", loggedInUsername);
                        System.out.println("\nPassword changed successfully.\n");
                    }
                    else
                    {
                        AuditLogger.log("PASSWORD_CHANGE_FAILURE", loggedInUsername);
                        System.out.println("\nPassword could not be changed, try again later.\n");
                    }
                 break;

                default:
                    System.out.println("\nNot an option, try entering \"1\", \"2\", or \"3\"\n");
                    AuditLogger.log("INVALID_MENU_CHOICE", loggedInUsername); //log a selecion of an invalid menu option
                break;
            }

            if(forceLogout) //user was locked out, end the session
                break;

            lastActivity = System.currentTimeMillis(); //get the current time in milliseconds

            UserInterface.menu();
            userChoice = scan.nextLine();
        }

        AuditLogger.log("LOGOUT", loggedInUsername); //log when the user exits the application
        Session.end(); //end the session for this user

        scan.close();
         
    }
}