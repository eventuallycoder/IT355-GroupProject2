import java.sql.Statement;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

public class DatabaseController {

    private DatabaseController(){}

    private static final String DB_DIRECTORY = "bank-app/Database";
    private static final String DB_FILE = DB_DIRECTORY + "/Database.db";
    private static final String URL = "jdbc:sqlite:" + DB_FILE;

    private static Connection connect() throws SQLException {

        new java.io.File(DB_DIRECTORY).mkdirs(); // make the database folder if it doesn't exist

        Connection conn = DriverManager.getConnection(URL);

        try (Statement stmt = conn.createStatement()) {
            stmt.execute("PRAGMA foreign_keys = ON");
        }
        return conn;
    }

    public static void createTables()
    {
        String users = """
                        CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username        TEXT    NOT NULL UNIQUE COLLATE NOCASE,
                        password_hash   TEXT    NOT NULL
                        )""";

        String accounts = """
                            CREATE TABLE IF NOT EXISTS accounts (
                            id             INTEGER PRIMARY KEY AUTOINCREMENT,
                            user_id        INTEGER NOT NULL UNIQUE REFERENCES users(id),
                            account_number TEXT    NOT NULL UNIQUE,
                            balance_cents  INTEGER NOT NULL DEFAULT 0 CHECK (balance_cents >= 0)
                            )""";
        
        try(Connection conn = connect(); Statement stmt = conn.createStatement())
        {
            stmt.execute(users);
            stmt.execute(accounts);
        }
        catch(SQLException e)
        {
            System.out.println(e.getMessage());
        }

    }


}
