public class UserInterface {

    //prints the welcome message for a user when they initially start up the app
    public static void printLoginMessage()
    {
        System.out.print("Welcome to Bank App Co., please enter \"0\" to sign up for an account or \"1\" to log in (without the quotes): ");
    }

    //prints the menu, an list of options the user can choose from
    public static void menu()
    {
        System.out.println("What would you like to do? (Enter the number for the option");
        System.out.println("1. View account balance");
        System.out.println("2. Deposit money into account");
        System.out.println("3. Withdrawal money from account");
        System.out.println("4. Exit application");
    }
}
