import java.util.Scanner;

public class Main {
    public static void main(String[] args) {
        
        DatabaseController.createTables();

        UserInterface.printLoginMessage();

        Scanner scan = new Scanner(System.in);

        String loginChoice = scan.nextLine();

        switch(loginChoice)
        {
            case "1":
                //UserLogin.login("","");
            break;

            case "2":
                //UserLogin.signup();
            break;
        }

        scan.close();
    }
}
