//this is the main way the user is interacting with the backend. Its purpose is to simulate a frontend basic interface
//without the complex integration

import java.util.Scanner;

public class UserInterface
{
    public static void main(String[] args) {
        welcomeMessage();
    }

    public static void welcomeMessage()
    {
        Scanner scan = new Scanner(System.in);
        System.out.println("Welcome to Secure Banking Inc");
        System.out.print("\nPlease enter '1' to sign in to an existing account, or '2' to sign up: ");

        String loginChoice = scan.nextLine();

        while(!(loginChoice.equals("1") || loginChoice.equals("2")))
        {
            System.out.print("\nPlease enter '1' to sign in to an existing account, or '2' to sign up: ");

            loginChoice = scan.nextLine();
        }



        
        
    }
}