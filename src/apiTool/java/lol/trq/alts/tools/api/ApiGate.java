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
 *   <li>{@code dump} refuses to write over a baseline whose lines it would erase within the baseline's major
 *       version, so regenerating the dump records additions and cannot launder a removal. {@code
 *       --allow-breaking=<reason>} ({@code -PapiAllowBreaking}) overrides that, and the reason is written into
 *       the dump's header.
 * </ul>
 *
 * <p>Usage: {@code dump <jar> <baseline> <version> [dependency...]} writes the baseline; {@code check <jar>
 * <baseline> <version> [dependency...]} checks the jar against it for a build of {@code version}.
 */
public final class ApiGate {

    /** The header line that records the version the dump belongs to. */
    static final String VERSION_PREFIX = "# version ";

    /** The header line that records why a dump dropped lines within its major version. */
    static final String BREAKING_PREFIX = "# breaking: ";

    /** The argument that gives a reason to drop lines within the major version ({@code -PapiAllowBreaking}). */
    static final String ALLOW_BREAKING_ARG = "--allow-breaking=";

    /** The argument that names the build's own version, when the dump is written for another. */
    static final String PROJECT_VERSION_ARG = "--project-version=";

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
        return baseline(dump, version, null);
    }

    /**
     * The text of a baseline file that records why it was allowed to drop lines in the same major version.
     *
     * @param dump the dump
     * @param version the version it belongs to
     * @param breakingReason the reason given for dropping lines, or {@code null}
     * @return the lines to write
     */
    static List<String> baseline(ApiDump.Result dump, String version, String breakingReason) {
        List<String> out = new ArrayList<>(header(version));
        if (breakingReason != null) {
            out.add(BREAKING_PREFIX + breakingReason);
        }
        out.addAll(dump.lines());
        return out;
    }

    /**
     * Why a dump must not be written over an existing baseline: writing it would erase lines of the
     * baseline's API in the same major version, which is exactly what {@link #check} refuses. Regenerating
     * the dump records additions; it never launders a removal.
     *
     * @param existing the current baseline file's lines, or {@code null} when there is none (refused without a
     *     reason)
     * @param dump the new dump
     * @param version the version the new dump is written for
     * @param projectVersion the version the build is for ({@code project.version})
     * @param breakingReason the reason given to drop lines anyway ({@code -PapiAllowBreaking}), or {@code null}
     * @return every reason to refuse; empty when the dump may be written
     */
    static List<String> dumpRefusal(
            List<String> existing, ApiDump.Result dump, String version, String projectVersion, String breakingReason) {
        List<String> problems = new ArrayList<>(dump.problems());
        boolean allowed = breakingReason != null && !breakingReason.isBlank();
        // Without a baseline there is nothing to compare against, so a missing or headerless file would let any
        // removal through: writing one needs a stated reason (the first dump of a library, or a repair).
        if (existing == null) {
            if (!allowed) {
                problems.add("there is no baseline to compare against; the first dump needs"
                        + " -PapiAllowBreaking=<reason> (restore the committed file otherwise)");
            }
            return problems;
        }
        Optional<String> baselineVersion = versionOf(existing);
        if (baselineVersion.isEmpty()) {
            if (!allowed) {
                problems.add("the baseline has no '" + VERSION_PREFIX.trim() + "' header line, so a removal could"
                        + " not be detected; restore it, or pass -PapiAllowBreaking=<reason>");
            }
            return problems;
        }
        // A dump may not claim a major the build has not reached, or the removal rule below could be met by
        // naming any later major. The one exception is the baseline's own major: the dump for the coming
        // release (1.0.0) is written while the build still says 0.x.
        int ahead = major(version);
        if (ahead > major(projectVersion) && ahead != major(baselineVersion.get()) && !allowed) {
            problems.add("a dump for " + version + " is ahead of this build (" + projectVersion
                    + "); bump the version in build.gradle first (or pass -PapiAllowBreaking=<reason>)");
        }
        Set<String> now = new LinkedHashSet<>(dump.lines());
        List<String> removed =
                lines(existing).stream().filter(l -> !now.contains(l)).sorted().toList();
        if (!removed.isEmpty() && major(version) <= major(baselineVersion.get()) && !allowed) {
            problems.add(removed.size() + " line(s) of the " + baselineVersion.get()
                    + " API would be erased by a dump for " + version
                    + "; only a new major version may remove API (or pass -PapiAllowBreaking=<reason>):\n"
                    + bulleted("- ", removed));
        }
        return problems;
    }

    private static Optional<String> versionOf(List<String> baseline) {
        return baseline.stream()
                .filter(l -> l.startsWith(VERSION_PREFIX))
                .map(l -> l.substring(VERSION_PREFIX.length()).trim())
                .findFirst();
    }

    private static Set<String> lines(List<String> baseline) {
        Set<String> base = new LinkedHashSet<>();
        for (String line : baseline) {
            if (!line.isBlank() && !line.startsWith("#")) {
                base.add(line);
            }
        }
        return base;
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
        Optional<String> baselineVersion = versionOf(baseline);
        if (baselineVersion.isEmpty()) {
            problems.add("the baseline has no '" + VERSION_PREFIX.trim() + "' header line");
            return problems;
        }
        if (major(buildVersion) >= 1 && major(baselineVersion.get()) > major(buildVersion)) {
            // From 1.0 on, a baseline of a later major than the build was written for a release that has not
            // been reached, which is how a removal would otherwise slip through a same-major build.
            problems.add("the baseline is for " + baselineVersion.get() + ", a later major than this build ("
                    + buildVersion + "); a dump may not run ahead of the version in build.gradle");
            return problems;
        }
        Set<String> base = lines(baseline);
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
            problems.add(added.size() + " line(s) of API are not in the baseline (additions only: run ./gradlew"
                    + " apiDump and commit the dump):\n" + bulleted("+ ", added));
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
        String breakingReason = null;
        String projectVersion = version;
        for (int i = 4; i < args.length; i++) {
            if (args[i].startsWith(PROJECT_VERSION_ARG)) {
                projectVersion = args[i].substring(PROJECT_VERSION_ARG.length()).trim();
            } else if (args[i].startsWith(ALLOW_BREAKING_ARG)) {
                String reason = args[i].substring(ALLOW_BREAKING_ARG.length()).trim();
                breakingReason = reason.isEmpty() ? null : reason;
            } else {
                dependencies.add(Path.of(args[i]));
            }
        }
        ApiDump.Result dump = ApiDump.dump(jar, dependencies);
        if (args[0].equals("dump")) {
            List<String> existing =
                    Files.isRegularFile(baselineFile) ? Files.readAllLines(baselineFile, StandardCharsets.UTF_8) : null;
            List<String> refusal = dumpRefusal(existing, dump, version, projectVersion, breakingReason);
            if (!refusal.isEmpty()) {
                fail("not dumped", refusal);
            }
            if (breakingReason != null) {
                System.out.println("writing the dump with removals allowed: " + breakingReason);
            }
            Files.createDirectories(baselineFile.toAbsolutePath().getParent());
            // LF on every platform, so the committed dump does not change with the machine that wrote it.
            Files.writeString(
                    baselineFile,
                    String.join("\n", baseline(dump, version, breakingReason)) + "\n",
                    StandardCharsets.UTF_8);
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
