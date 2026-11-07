 
public class Main {
    public static void main(String[] args) {
        
        DatabaseController.createTables();

        //log the user in (by either creating an account or logging into preexisitng account)
        boolean authSuccess = UserLogin.login();

        if(authSuccess)
            System.out.println("Welcome!");
        else
        {
            System.out.println("Authentication could not complete, please try again.");
            System.exit(0);
        }



    }
}
