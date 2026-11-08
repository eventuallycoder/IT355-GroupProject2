import java.io.File;
import java.math.BigDecimal;
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

    private static final String DB_DIR  = "Database";
    private static final String DB_FILE = DB_DIR + "/Database.db";
    private static final String URL     = "jdbc:sqlite:" + DB_FILE;

    private static final SecureRandom RANDOM = new SecureRandom();

    // ------------------------------------------------------------------
    // Connection + schema
    // ------------------------------------------------------------------

    private static Connection connect() throws SQLException {
        new File(DB_DIR).mkdirs();
        Connection conn = DriverManager.getConnection(URL);
        try (Statement stmt = conn.createStatement()) {
            stmt.execute("PRAGMA foreign_keys = ON");
        }
        return conn;
    }

    public static void createTables() {
        String users = """
                CREATE TABLE IF NOT EXISTS users (
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

        String hash = hashPassword(password);

        try (Connection conn = connect()) {
            conn.setAutoCommit(false);
            try {
                long userId = insertUser(conn, username.trim(), hash);
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
        StringBuilder sb = new StringBuilder(10);
        for (int i = 0; i < 10; i++) sb.append(RANDOM.nextInt(10));
        return sb.toString();
    }

    // ------------------------------------------------------------------
    // Login check
    // ------------------------------------------------------------------

    public static boolean authenticate(String username, String password) {
        String sql = "SELECT password_hash FROM users WHERE username = ?";
        try (Connection conn = connect(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, username);
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
    public static boolean deleteUser(String username) {
        try (Connection conn = connect()) {
            conn.setAutoCommit(false);
            try {
                try (PreparedStatement ps = conn.prepareStatement(
                        "DELETE FROM accounts WHERE user_id = (SELECT id FROM users WHERE username = ?)")) {
                    ps.setString(1, username);
                    ps.executeUpdate();
                }
                int deleted;
                try (PreparedStatement ps = conn.prepareStatement(
                        "DELETE FROM users WHERE username = ?")) {
                    ps.setString(1, username);
                    deleted = ps.executeUpdate();
                }
                conn.commit();
                return deleted > 0;
            } catch (SQLException e) {
                conn.rollback();
                throw e;
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
        String sql = """
                SELECT a.balance_cents
                FROM accounts a
                JOIN users u ON u.id = a.user_id
                WHERE u.username = ?""";
        try (Connection conn = connect(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, username);
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
        return NumberFormat.getCurrencyInstance(Locale.US).format(BigDecimal.valueOf(cents, 2));
    }

    // ------------------------------------------------------------------
    // Password hashing (PBKDF2, stored as "salt:hash" in Base64)
    // ------------------------------------------------------------------

    private static final int ITERATIONS = 120_000;
    private static final int KEY_BITS   = 256;

    private static String hashPassword(String password) {
        byte[] salt = new byte[16];
        RANDOM.nextBytes(salt);
        byte[] hash = pbkdf2(password, salt);
        return Base64.getEncoder().encodeToString(salt) + ":" + Base64.getEncoder().encodeToString(hash);
    }

    private static boolean verifyPassword(String password, String stored) {
        String[] parts = stored.split(":");
        if (parts.length != 2) return false;
        byte[] salt     = Base64.getDecoder().decode(parts[0]);
        byte[] expected = Base64.getDecoder().decode(parts[1]);
        return MessageDigest.isEqual(expected, pbkdf2(password, salt));
    }

    private static byte[] pbkdf2(String password, byte[] salt) {
        try {
            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_BITS);
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        } catch (Exception e) {
            throw new IllegalStateException("Password hashing failed", e);
        }
    }
}