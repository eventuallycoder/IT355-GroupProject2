package src.main.java.com.bankapp.exception;

public class AuthenticationException extends BankException {
    AuthenticationException(String message)
    {
        super(message);
    }
}
