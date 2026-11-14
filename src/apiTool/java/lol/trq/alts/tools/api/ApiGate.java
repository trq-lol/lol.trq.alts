package lol.trq.alts.tools.api;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * The compatibility gate over a committed API dump. The baseline file is a header of {@code #} lines, one of
 * which is {@code # version X.Y.Z}, then the sorted lines of {@link ApiDump}.
 *
 * <ul>
 *   <li>A baseline line that is gone from the current dump (removed, or changed, which removes the old line)
 *       fails the gate, unless the build's major version is greater than the baseline's.
 *   <li>A current line the baseline lacks fails the gate until the dump is regenerated ({@code apiDump}).
 *   <li>A problem with the surface itself (an exported internal package, an internal type in an exported
 *       signature) always fails it.
 * </ul>
 *
 * <p>Usage: {@code dump <jar> <baseline> <version> [dependency...]} writes the baseline; {@code check <jar>
 * <baseline> <version> [dependency...]} checks the jar against it for a build of {@code version}.
 */
public final class ApiGate {

    /** The header line that records the version the dump belongs to. */
    static final String VERSION_PREFIX = "# version ";

    private ApiGate() {}

    /**
     * The header a dump is written with.
     *
     * @param version the version the dump belongs to
     * @return the header lines
     */
    static List<String> header(String version) {
        return List.of(
                "# The exported API of lol.trq.alts: every public or protected type, member and signature in a",
                "# package the module exports. Generated from the built jar by ./gradlew apiDump and checked by",
                "# ./gradlew apiCheck (part of check); do not edit by hand. Packages under internal are not listed.",
                VERSION_PREFIX + version);
    }

    /**
     * The text of a baseline file.
     *
     * @param dump the dump
     * @param version the version it belongs to
     * @return the lines to write
     */
    static List<String> baseline(ApiDump.Result dump, String version) {
        List<String> out = new ArrayList<>(header(version));
        out.addAll(dump.lines());
        return out;
    }

    /**
     * Checks a dump against a baseline.
     *
     * @param baseline the baseline file's lines
     * @param current the current dump
     * @param buildVersion the version being built
     * @return every reason the gate fails; empty when it passes
     */
    static List<String> check(List<String> baseline, ApiDump.Result current, String buildVersion) {
        List<String> problems = new ArrayList<>(current.problems());
        Optional<String> baselineVersion = baseline.stream()
                .filter(l -> l.startsWith(VERSION_PREFIX))
                .map(l -> l.substring(VERSION_PREFIX.length()).trim())
                .findFirst();
        if (baselineVersion.isEmpty()) {
            problems.add("the baseline has no '" + VERSION_PREFIX.trim() + "' header line");
            return problems;
        }
        Set<String> base = new LinkedHashSet<>();
        for (String line : baseline) {
            if (!line.isBlank() && !line.startsWith("#")) {
                base.add(line);
            }
        }
        Set<String> now = new LinkedHashSet<>(current.lines());
        List<String> removed =
                base.stream().filter(l -> !now.contains(l)).sorted().toList();
        List<String> added =
                now.stream().filter(l -> !base.contains(l)).sorted().toList();
        if (!removed.isEmpty() && major(buildVersion) <= major(baselineVersion.get())) {
            problems.add(removed.size() + " line(s) of the " + baselineVersion.get()
                    + " API were removed or changed, which only a new major version may do (building "
                    + buildVersion + "):\n" + bulleted("- ", removed));
        }
        if (!added.isEmpty()) {
            problems.add(added.size() + " line(s) of API are not in the baseline; run ./gradlew apiDump and commit"
                    + " the dump:\n" + bulleted("+ ", added));
        }
        return problems;
    }

    /**
     * The major version: the number before the first dot or hyphen.
     *
     * @param version a version such as {@code 1.2.3} or {@code 2.0.0-rc1}
     * @return its major number
     */
    static int major(String version) {
        String head = version.trim().split("[.\\-+]", 2)[0];
        try {
            return Integer.parseInt(head);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("not a version: " + version, e);
        }
    }

    private static String bulleted(String mark, List<String> lines) {
        StringBuilder out = new StringBuilder();
        for (String line : lines) {
            out.append("    ").append(mark).append(line).append('\n');
        }
        return out.toString().stripTrailing();
    }

    /**
     * Runs {@code dump} or {@code check}.
     *
     * @param args the mode, the jar, the baseline file, the version, then the jar's dependencies
     * @throws IOException if a file cannot be read or written
     */
    public static void main(String[] args) throws IOException {
        if (args.length < 4 || !(args[0].equals("dump") || args[0].equals("check"))) {
            System.err.println("usage: dump|check <jar> <baseline> <version> [dependency...]");
            System.exit(2);
        }
        Path jar = Path.of(args[1]);
        Path baselineFile = Path.of(args[2]);
        String version = args[3];
        List<Path> dependencies = new ArrayList<>();
        for (int i = 4; i < args.length; i++) {
            dependencies.add(Path.of(args[i]));
        }
        ApiDump.Result dump = ApiDump.dump(jar, dependencies);
        if (args[0].equals("dump")) {
            if (!dump.problems().isEmpty()) {
                fail("not dumped", dump.problems());
            }
            Files.createDirectories(baselineFile.toAbsolutePath().getParent());
            // LF on every platform, so the committed dump does not change with the machine that wrote it.
            Files.writeString(baselineFile, String.join("\n", baseline(dump, version)) + "\n", StandardCharsets.UTF_8);
            System.out.println("wrote " + dump.lines().size() + " API lines for " + version + " to " + baselineFile);
            return;
        }
        if (!Files.isRegularFile(baselineFile)) {
            fail("no baseline", List.of(baselineFile + " does not exist; run ./gradlew apiDump"));
        }
        List<String> problems = check(Files.readAllLines(baselineFile, StandardCharsets.UTF_8), dump, version);
        if (!problems.isEmpty()) {
            fail("the API check failed", problems);
        }
        System.out.println("API check passed: " + dump.lines().size() + " lines match " + baselineFile.getFileName());
    }

    private static void fail(String what, List<String> problems) {
        System.err.println(what + ":");
        for (String problem : problems) {
            System.err.println("  " + problem);
        }
        System.exit(1);
    }
}
