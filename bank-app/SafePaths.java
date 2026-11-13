import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Set;

//Every file the application reads or writes is resolved through this class.
//Covers CWE-22 (path traversal) and CWE-434 (unrestricted file upload / arbitrary file creation)
public final class SafePaths {

    private SafePaths() {}

    //CWE-434: the ONLY file names the application is allowed to create or write. Anything else is refused,
    //so no input (or future code change) can cause a file of an unexpected name/type to be written.
    private static final Set<String> ALLOWED_FILES = Set.of("audit.log", "Database.db");

    //fixed, absolute base directories (never built from user input)
    public static final Path APP_DIR = Paths.get("").toAbsolutePath().normalize();
    public static final Path DB_DIR  = APP_DIR.resolve("Database").normalize();

    /**
     * Resolves an allowlisted file name inside baseDir and guarantees the result cannot leave baseDir.
     *
     * @throws IOException if the name is not allowlisted, is not a plain file name,
     *                     escapes baseDir, or is a symbolic link
     */
    public static Path resolveInside(Path baseDir, String fileName) throws IOException {
        if (baseDir == null || fileName == null || fileName.isBlank()) {
            throw new IOException("Invalid file request");
        }

        //CWE-434: allowlist check
        if (!ALLOWED_FILES.contains(fileName)) {
            throw new IOException("File name is not permitted");
        }

        //CWE-22: must be a plain file name, no separators, parent references, or null bytes
        if (fileName.contains("/") || fileName.contains("\\") || fileName.contains("..") || fileName.indexOf('\0') >= 0) {
            throw new IOException("File name must not contain path elements");
        }

        Path base   = baseDir.toAbsolutePath().normalize();
        Path target = base.resolve(fileName).normalize();

        //CWE-22: after normalizing, the file must sit directly inside the base directory
        if (!target.startsWith(base) || !base.equals(target.getParent())) {
            throw new IOException("Path escapes the application directory");
        }

        //CWE-22: refuse symbolic links so a link can't redirect a write somewhere else
        if (Files.exists(target, LinkOption.NOFOLLOW_LINKS) && Files.isSymbolicLink(target)) {
            throw new IOException("Symbolic links are not permitted");
        }

        //CWE-22: if the file already exists, its real location must still be inside the real base directory
        if (Files.exists(base) && Files.exists(target)) {
            if (!target.toRealPath().startsWith(base.toRealPath())) {
                throw new IOException("Resolved path escapes the application directory");
            }
        }

        return target;
    }
}