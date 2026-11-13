import java.io.File;
import java.io.IOException;
import java.math.BigDecimal;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.text.NumberFormat;
import java.util.Base64;
import java.util.Locale;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;


public class DatabaseController {

    private DatabaseController() {}

    //CWE-22 / CWE-434: the database location is fixed and checked by SafePaths, it is never built from user input
    private static final String DB_FILE_NAME = "Database.db";

    // Upper bound so a balance can never overflow SQLite's 64-bit integer
    private static final long MAX_BALANCE_CENTS = Long.MAX_VALUE / 2;

    //CWE-338: ALL randomness in this app (password salts, account numbers) comes from this cryptographically
    private static final SecureRandom RANDOM = new SecureRandom();

    // ------------------------------------------------------------------
    // Connection + schema
    // ------------------------------------------------------------------

    private static Connection connect() throws SQLException {
        Path dbPath;
        try {
            Files.createDirectories(SafePaths.DB_DIR);
            dbPath = SafePaths.resolveInside(SafePaths.DB_DIR, DB_FILE_NAME); //CWE-22 / CWE-434
        } catch (IOException e) {
            throw new SQLException("Database location is not permitted", e);
        }
        Connection conn = DriverManager.getConnection("jdbc:sqlite:" + dbPath);
        try (Statement stmt = conn.createStatement()) {
            stmt.execute("PRAGMA foreign_keys = ON");
        }
        return conn;
    }


    public static void createTables() {
        String users = """
                CREATE TABLE IF NOT EXISTS users (
                    failed_attempts INTEGER NOT NULL DEFAULT 0,
                    locked_until INTEGER,
                    id            INTEGER PRIMARY KEY AUTOINCREMENT,
                    username      TEXT    NOT NULL UNIQUE COLLATE NOCASE,
                    password_hash TEXT    NOT NULL
                )""";

        String accounts = """
                CREATE TABLE IF NOT EXISTS accounts (
                    id             INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id        INTEGER NOT NULL UNIQUE REFERENCES users(id),
                    account_number TEXT    NOT NULL UNIQUE,
                    balance_cents  INTEGER NOT NULL DEFAULT 0 CHECK (balance_cents >= 0)
                )""";

        try (Connection conn = connect(); Statement stmt = conn.createStatement()) {
            stmt.execute(users);
            stmt.execute(accounts);
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
    }
    //CWE-178: Normalize usernames to lowercase to prevent case-sensitivity mismatches in authentication and account management
    private static String normalizeUsername(String username) {
        return username.trim().toLowerCase(Locale.ROOT);
    }

    // ------------------------------------------------------------------
    // Sign up (creates the user AND their bank account atomically)
    // ------------------------------------------------------------------

    /**
     * @return true if the user was created, false if the username is taken
     *         or something went wrong.
     */
    public static boolean signUp(String username, String password) {
        if (username == null || username.isBlank() || password == null || password.isEmpty()) {
            return false;
        }

        // CWE-178: Store canonical lowercase username to prevent case-sensitivity mismatches
        String cleanUser = normalizeUsername(username);
        String hash = hashPassword(password);

        try (Connection conn = connect()) {
            conn.setAutoCommit(false);
            try {
                long userId = insertUser(conn, cleanUser, hash);
                insertAccount(conn, userId);
                conn.commit();
                return true;
            } catch (SQLException e) {
                conn.rollback();
                if (e.getMessage() != null && e.getMessage().contains("UNIQUE")) {
                    return false; // username already exists
                }
                throw e;
            }
        } catch (SQLException e) {
            System.out.println(e.getMessage());
            return false;
        }
    }

    private static long insertUser(Connection conn, String username, String hash) throws SQLException {
        String sql = "INSERT INTO users (username, password_hash) VALUES (?, ?)";
        try (PreparedStatement ps = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            ps.setString(1, username);
            ps.setString(2, hash);
            ps.executeUpdate();
            try (ResultSet keys = ps.getGeneratedKeys()) {
                if (keys.next()) return keys.getLong(1);
                throw new SQLException("Failed to retrieve new user id");
            }
        }
    }

    private static void insertAccount(Connection conn, long userId) throws SQLException {
        String sql = "INSERT INTO accounts (user_id, account_number) VALUES (?, ?)";
        // Retry in the (very unlikely) event of an account number collision
        for (int attempt = 0; attempt < 5; attempt++) {
            try (PreparedStatement ps = conn.prepareStatement(sql)) {
                ps.setLong(1, userId);
                ps.setString(2, generateAccountNumber());
                ps.executeUpdate();
                return;
            } catch (SQLException e) {
                boolean numberCollision = e.getMessage() != null
                        && e.getMessage().contains("account_number");
                if (!numberCollision) throw e;
            }
        }
        throw new SQLException("Could not generate a unique account number");
    }

    private static String generateAccountNumber() {
        //CWE-338
        StringBuilder sb = new StringBuilder(10);
        for (int i = 0; i < 10; i++) sb.append(RANDOM.nextInt(10));
        return sb.toString();
    }

    // ------------------------------------------------------------------
    // Login check
    // ------------------------------------------------------------------
    
    public static boolean authenticate(String username, String password) {
        // CWE-229: Reject null or empty credentials before passing values to SQL or password verification
        if (username == null || username.isBlank() || password == null || password.isEmpty()) {
            return false;
        }
        String sql = "SELECT password_hash FROM users WHERE username = ?";
        try (Connection conn = connect(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, username.trim());
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() && verifyPassword(password, rs.getString("password_hash"));
            }
        } catch (SQLException e) {
            System.out.println(e.getMessage());
            return false;
        }
    }


    // ------------------------------------------------------------------
    // Delete user (account first, then user)
    // ------------------------------------------------------------------

    /**
     * @return true if a user was deleted, false if no such user existed
     *         or something went wrong.
     */
     public static boolean deleteUser(String username, String password) {
        //CWE-425: a direct call must come from the logged in user, being able to supply a password isn't enough
        if(!sessionAllows(username))
            return false;
 
        if(authenticate(username, password) == false)
        {
            AuditLogger.log("DELETE_USER_DENIED", "-");
            return false;
        }


        // CWE-178 & CWE-229: Normalize casing and whitespace so database and audit logs stay consistent
        String cleanUser = normalizeUsername(username);

        try (Connection conn = connect()) {
            conn.setAutoCommit(false);
            try {
                try (PreparedStatement ps = conn.prepareStatement(
                        "DELETE FROM accounts WHERE user_id = (SELECT id FROM users WHERE username = ?)")) {
                    ps.setString(1, cleanUser);
                    ps.executeUpdate();
                }
                int deleted;
                try (PreparedStatement ps = conn.prepareStatement(
                        "DELETE FROM users WHERE username = ?")) {
                    ps.setString(1, cleanUser);
                    deleted = ps.executeUpdate();
                }
                conn.commit();
                boolean removed = deleted > 0;

                if(removed){
                    AuditLogger.log("USER_DELETED", cleanUser);
                    Session.end();
                }
                return removed;

            } catch (SQLException e) {
                conn.rollback();
                System.out.println(e.getMessage());
                return false;
            }
        } catch (SQLException e) {
            System.out.println(e.getMessage());
            return false;
        }
    }

    // ------------------------------------------------------------------
    // Balance
    // ------------------------------------------------------------------

    /** @return balance in cents, or -1 if the user/account wasn't found. */
    public static long getBalanceCents(String username) {
        
        if(!sessionAllows(username)) //if the passed username is not the currently logged in user, don't allow the person to see the real balance
            return -1;
        
        String sql = """
                SELECT a.balance_cents
                FROM accounts a
                JOIN users u ON u.id = a.user_id
                WHERE u.username = ?""";
        try (Connection conn = connect(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, username.trim()); // CWE-229: Normalize whitespace on username lookup
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? rs.getLong("balance_cents") : -1;
            }
        } catch (SQLException e) {
            System.out.println(e.getMessage());
            return -1;
        }
    }

    /** @return e.g. "$1,234.56", or null if the user/account wasn't found. */
    public static String getBalanceFormatted(String username) {
        long cents = getBalanceCents(username);
        return cents < 0 ? null : formatCents(cents);
    }

    public static String formatCents(long cents) {
        // CWE-229: Guard against negative values or error sentinels (-1) being formatted as currency
        if (cents < 0) {
            throw new IllegalArgumentException("Cents value cannot be negative");
        }
        return NumberFormat.getCurrencyInstance(Locale.US).format(BigDecimal.valueOf(cents, 2));
    }


    // ------------------------------------------------------------------
    // Password hashing (PBKDF2, stored as "salt:hash" in Base64)
    // ------------------------------------------------------------------

    private static final int ITERATIONS = 120_000;
    private static final int KEY_BITS   = 256;

    private static String hashPassword(String password) {
        byte[] salt = new byte[16];
        RANDOM.nextBytes(salt); //CWE-338
        byte[] hash = pbkdf2(password, salt);
        return Base64.getEncoder().encodeToString(salt) + ":" + Base64.getEncoder().encodeToString(hash);
    }

    private static boolean verifyPassword(String password, String stored) {
        // CWE-229: Reject null values before splitting or decoding
        if (password == null || stored == null) return false;
        String[] parts = stored.split(":");
        if (parts.length != 2) return false;
        try {
            byte[] salt     = Base64.getDecoder().decode(parts[0]);
            byte[] expected = Base64.getDecoder().decode(parts[1]);
            return MessageDigest.isEqual(expected, pbkdf2(password, salt));
        } catch (IllegalArgumentException e) {
            // CWE-229: Handle corrupted/non-Base64 stored hash values safely instead of crashing
            return false;
        }
    }


    private static byte[] pbkdf2(String password, byte[] salt) {
        try {
            PBEKeySpec spec = new PBEKeySpec((password + getPepper()).toCharArray(), salt, ITERATIONS, KEY_BITS);
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        } catch (Exception e) {
            throw new IllegalStateException("Password hashing failed", e);
        }
    }
    
    /**
     * Adds money to a user's account.
     *
     * @param amountCents must be > 0
     * @return true if the deposit succeeded, false if the amount is invalid,
     *         the user doesn't exist, or the balance would exceed the max.
     */
    public static boolean deposit(String username, long amountCents) {
        if(!sessionAllows(username))
            return false;
        
        if (amountCents <= 0 || amountCents > MAX_BALANCE_CENTS) return false;

        // CWE-178 & CWE-229: Normalize username before binding to SQL
        String cleanUser = normalizeUsername(username);

        String sql = """
                UPDATE accounts
                SET balance_cents = balance_cents + ?
                WHERE user_id = (SELECT id FROM users WHERE username = ?)
                  AND balance_cents <= ? - ?""";

        try (Connection conn = connect(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setLong(1, amountCents);
            ps.setString(2, cleanUser);
            ps.setLong(3, MAX_BALANCE_CENTS);
            ps.setLong(4, amountCents);
            return ps.executeUpdate() == 1;
        } catch (SQLException e) {
            System.out.println(e.getMessage());
            return false;
        }
    }


    /**
     * Removes money from a user's account.
     *
     * @param amountCents must be > 0
     * @return true if the withdrawal succeeded, false if the amount is invalid,
     *         the user doesn't exist, or there are insufficient funds.
     */
    public static boolean withdraw(String username, long amountCents) {
        if(!sessionAllows(username))
            return false;
        
        if (amountCents <= 0) return false;

        // CWE-178 & CWE-229: Normalize username before binding to SQL
        String cleanUser = normalizeUsername(username);

        String sql = """
                UPDATE accounts
                SET balance_cents = balance_cents - ?
                WHERE user_id = (SELECT id FROM users WHERE username = ?)
                  AND balance_cents >= ?""";

        try (Connection conn = connect(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setLong(1, amountCents);
            ps.setString(2, cleanUser);
            ps.setLong(3, amountCents);
            return ps.executeUpdate() == 1;
        } catch (SQLException e) {
            System.out.println(e.getMessage());
            return false;
        }
    }

    // ------------------------------------------------------------------
    // Dollar-string -> cents helper (for turning user input into amountCents)
    // ------------------------------------------------------------------

    /**
     * Converts input like "25", "25.5", "$1,234.56" into cents.
     *
     * @return the amount in cents, or -1 if the input isn't a valid positive
     *         dollar amount (letters, negatives, or fractions of a cent).
     */
    public static long dollarsToCents(String input) {
        if (input == null) return -1;
        String cleaned = input.replace("$", "").replace(",", "").trim();
        // CWE-229: Reject scientific notation (e.g. "1e5") or explicit '+' prefixes before BigDecimal parsing
        if (!cleaned.matches("^\\d+(\\.\\d{1,2})?$")) {
            return -1;
        }
        try {
            BigDecimal dollars = new BigDecimal(cleaned);
            if (dollars.signum() <= 0) return -1;
            // UNNECESSARY throws if there's more precision than whole cents (e.g. 1.005)
            return dollars.setScale(2, java.math.RoundingMode.UNNECESSARY)
                          .movePointRight(2)
                          .longValueExact();
        } catch (ArithmeticException | NumberFormatException e) {
            return -1;
        }
    }


    /**
     * 
     * @return the environment variable named as BANK_PEPPER
     */
    private static String getPepper() //part of CWE-798
    {
        return System.getenv("BANK_PEPPER");
    }


    //calls getPepper()
    public static void requirePepper() //part of CWE-798
    {
        String res = getPepper();

        if(res == null || res.isBlank())
        {
            System.out.println("BANK_PEPPER is not set. See setup notes");
            System.exit(1);
        }
    }

    //adds one to the failed attempts of logging into for a user
    public static void recordFailedLogin(String username)
    {
        // CWE-229: Ignore null or blank usernames before executing SQL update
        if (username == null || username.isBlank()) return;

        String sql = "UPDATE users SET failed_attempts = failed_attempts + 1 WHERE username = ?";

        try (Connection conn = connect(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, username.trim()); // CWE-229: Normalize whitespace
            ps.executeUpdate();
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
    }

    //resets a users number of failed attempts
    public static void resetFailedLogins(String username)
    {
        // CWE-229: Ignore null or blank usernames before executing SQL update
        if (username == null || username.isBlank()) return;

        String sql = "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE username = ?";

        try(Connection conn = connect(); PreparedStatement ps = conn.prepareStatement(sql))
        {
            ps.setString(1, username.trim()); // CWE-229: Normalize whitespace
            ps.executeUpdate();
        }
        catch(SQLException e)
        {
            System.out.println(e.getMessage());
        }
    }

    //gets the number of failed attempts a user currently has for trying to log in
    public static int getFailedAttempts(String username)
    {
        // CWE-229: Return 0 safely on null or blank usernames
        if (username == null || username.isBlank()) return 0;

        String sql = "SELECT failed_attempts FROM users WHERE username = ?";
        
        try (Connection conn = connect(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, username.trim()); // CWE-229: Normalize whitespace
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? rs.getInt("failed_attempts") : 0;
            }
        } catch (SQLException e) {
            System.out.println(e.getMessage());
            return 0;
        }
    }


        public static void lockUser(String username, int minutes)
    {
        // CWE-229: Reject null/blank usernames and non-positive or excessively large lock durations
        if (username == null || username.isBlank() || minutes <= 0 || minutes > 525_600) {
            return;
        }

        long lockedUntil = System.currentTimeMillis() + (minutes * 60L * 1000L); //current system time plus the lokc length

        String sql = "UPDATE users SET locked_until = ? WHERE username = ?";

        try(Connection conn = connect(); PreparedStatement ps = conn.prepareStatement(sql)){
            ps.setLong(1,lockedUntil);
            ps.setString(2,username.trim()); // CWE-229: Normalize whitespace to match stored usernames
            ps.executeUpdate();
        }
        catch(SQLException e){
            System.out.println(e.getMessage());
        }
    }

    /**
     * 
     * @param username a user's username
     * @return true if the user's lock hasn't run out yet
     */
    public static boolean isLocked(String username)
    {
        // CWE-229: Return false safely on null or blank usernames
        if (username == null || username.isBlank()) {
            return false;
        }

        String sql = "SELECT 1 FROM users WHERE username = ? AND locked_until > ?";

        try (Connection conn = connect(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, username.trim()); // CWE-229: Normalize whitespace to match stored usernames
            ps.setLong(2,System.currentTimeMillis());

            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        } catch (SQLException e) {
            System.out.println(e.getMessage());
            return false;
        }
        
    }

    /**
     * 
     * @param username should be the currently logged in user 
     * @return true if the passed user is the currently logged in user, false if not, part of CWE-306 and CWE-841
     */
    private static boolean sessionAllows(String username)
    {
        // CWE-229: Reject null or blank usernames before checking session state
        if (username == null || username.isBlank()) {
            AuditLogger.log("UNAUTHORIZED_ATTEMPT", "-");
            return false;
        }

        if(Session.isUser(username.trim()) == true) // CWE-229: Normalize whitespace before session comparison
            return true;
        else
        {
            AuditLogger.log("UNAUTHORIZED_ATTEMPT", "-"); //the username passed is not the currently logged in user
            return false;
        }
    }

}
