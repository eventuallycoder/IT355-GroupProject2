package src.main.java.com.bankapp.exception;

public class DataAccessException extends RuntimeException{
    
    DataAccessException(String message, Throwable cause)
    {
        super(message, cause);
    }
}
