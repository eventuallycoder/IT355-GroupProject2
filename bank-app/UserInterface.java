public class UserInterface {

    //prints the welcome message for a user when they initially start up the app
    public static void printLoginMessage()
    {
        System.out.print("Welcome to Bank App Co., please enter \"0\" to sign up for an account or \"1\" to log in (without the quotes): ");
    }

    //prints the menu, an list of options the user can choose from
    public static void menu()
    {
        System.out.println("What would you like to do? (Enter the number for the option)");
        System.out.println("1. View account balance");
        System.out.println("2. Deposit money into account");
        System.out.println("3. Withdraw money from account");
        System.out.println("4. Exit application");
        System.out.print("Enter choice: ");
    }

    //tells the user the required password length
    public static void printPasswordRules()
    {
        System.out.println("\nPassword requirements:");
        System.out.println("1. Must be at least 12 characters long.");
        System.out.println("2. Contain at least one uppercase character.");
        System.out.println("3. Contain at least one lowercase character.");
        System.out.println("4. Contain at least one digit.");
        System.out.println("5. Contain at least one special character (like ! or #).");
        System.out.println("6. Must not be a commonly used password.");
        System.out.println("7. Not contain your username.\n");
    }
}
