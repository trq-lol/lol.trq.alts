package lol.trq.alts.tools.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.stream.Stream;
import javax.tools.ToolProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The gate itself, over fixture modules compiled here: a removed or changed member fails it, an added one
 * needs a dump, a major bump allows a removal, and the internal packages are ignored by the comparison but
 * may not leak into the surface.
 */
class ApiGateTest {

    private static final String MODULE = "module fixture { exports fx; }";

    private static final String API_V1 = """
            package fx;
            public class Api {
                public void kept() {}
                public void removed() {}
                public String changed() { return ""; }
                void packagePrivate() {}
            }
            """;

    @TempDir
    Path temp;

    @Test
    void anUnchangedApiPasses() throws IOException {
        List<String> baseline = baseline(API_V1, "1.0.0");

        assertEquals(List.of(), ApiGate.check(baseline, dump(MODULE, Map.of("fx/Api.java", API_V1)), "1.0.0"));
        assertEquals(List.of(), ApiGate.check(baseline, dump(MODULE, Map.of("fx/Api.java", API_V1)), "1.4.2"));
    }

    @Test
    void aRemovedMethodFailsInTheSameMajor() throws IOException {
        List<String> baseline = baseline(API_V1, "1.0.0");
        String v2 = API_V1.replace("    public void removed() {}\n", "");

        List<String> problems = ApiGate.check(baseline, dump(MODULE, Map.of("fx/Api.java", v2)), "1.3.0");

        assertEquals(1, problems.size(), problems::toString);
        assertTrue(problems.get(0).contains("removed or changed"), problems::toString);
        assertTrue(problems.get(0).contains("fx.Api.removed()"), problems::toString);
    }

    @Test
    void aChangedSignatureFailsInTheSameMajor() throws IOException {
        List<String> baseline = baseline(API_V1, "1.0.0");
        String v2 =
                API_V1.replace("public String changed() { return \"\"; }", "public Object changed() { return \"\"; }");

        List<String> problems = ApiGate.check(baseline, dump(MODULE, Map.of("fx/Api.java", v2)), "1.0.1");

        assertTrue(
                problems.stream()
                        .anyMatch(p -> p.contains("removed or changed") && p.contains("String fx.Api.changed()")),
                problems::toString);
    }

    @Test
    void aMajorBumpAllowsARemoval() throws IOException {
        List<String> baseline = baseline(API_V1, "1.0.0");
        String v2 = API_V1.replace("    public void removed() {}\n", "");

        assertEquals(List.of(), ApiGate.check(baseline, dump(MODULE, Map.of("fx/Api.java", v2)), "2.0.0"));
        assertEquals(
                1,
                ApiGate.check(baseline, dump(MODULE, Map.of("fx/Api.java", v2)), "1.99.0")
                        .size());
        assertEquals(
                1,
                ApiGate.check(baseline, dump(MODULE, Map.of("fx/Api.java", v2)), "0.12.0")
                        .size());
    }

    @Test
    void anAddedMethodRequiresADump() throws IOException {
        List<String> baseline = baseline(API_V1, "1.0.0");
        String v2 =
                API_V1.replace("public void kept() {}", "public void kept() {}\n    public int added() { return 1; }");

        List<String> problems = ApiGate.check(baseline, dump(MODULE, Map.of("fx/Api.java", v2)), "1.1.0");

        assertEquals(1, problems.size(), problems::toString);
        assertTrue(problems.get(0).contains("apiDump"), problems::toString);
        assertTrue(problems.get(0).contains("fx.Api.added()"), problems::toString);
        // Even a major bump does not take an undumped addition.
        assertEquals(
                1,
                ApiGate.check(baseline, dump(MODULE, Map.of("fx/Api.java", v2)), "2.0.0")
                        .size());
    }

    @Test
    void aSameMajorDumpOverARemovalIsRefused() throws IOException {
        List<String> baseline = baseline(API_V1, "1.0.0");
        String v2 = API_V1.replace("    public void removed() {}\n", "");
        ApiDump.Result current = dump(MODULE, Map.of("fx/Api.java", v2));

        List<String> refusal = ApiGate.dumpRefusal(baseline, current, "1.1.0", null);

        assertEquals(1, refusal.size(), refusal::toString);
        assertTrue(refusal.get(0).contains("would be erased"), refusal::toString);
        assertTrue(refusal.get(0).contains("fx.Api.removed()"), refusal::toString);
        // A blank reason is no reason.
        assertEquals(1, ApiGate.dumpRefusal(baseline, current, "1.0.0", " ").size());
    }

    @Test
    void aMajorBumpDumpOverARemovalIsWritten() throws IOException {
        List<String> baseline = baseline(API_V1, "1.0.0");
        String v2 = API_V1.replace("    public void removed() {}\n", "");

        assertEquals(List.of(), ApiGate.dumpRefusal(baseline, dump(MODULE, Map.of("fx/Api.java", v2)), "2.0.0", null));
    }

    @Test
    void aDumpThatOnlyAddsIsWritten() throws IOException {
        List<String> baseline = baseline(API_V1, "1.0.0");
        String v2 =
                API_V1.replace("public void kept() {}", "public void kept() {}\n    public int added() { return 1; }");

        assertEquals(List.of(), ApiGate.dumpRefusal(baseline, dump(MODULE, Map.of("fx/Api.java", v2)), "1.1.0", null));
        assertEquals(List.of(), ApiGate.dumpRefusal(null, dump(MODULE, Map.of("fx/Api.java", v2)), "1.1.0", null));
    }

    @Test
    void anAllowedBreakingDumpIsWrittenWithItsReason() throws IOException {
        List<String> baseline = baseline(API_V1, "1.0.0");
        String v2 = API_V1.replace("    public void removed() {}\n", "");
        ApiDump.Result current = dump(MODULE, Map.of("fx/Api.java", v2));

        assertEquals(List.of(), ApiGate.dumpRefusal(baseline, current, "1.1.0", "removed() was never usable"));
        List<String> written = ApiGate.baseline(current, "1.1.0", "removed() was never usable");

        assertTrue(written.contains(ApiGate.BREAKING_PREFIX + "removed() was never usable"), written::toString);
        assertEquals(List.of(), ApiGate.check(written, current, "1.1.0"), "the recorded dump checks clean");
    }

    @Test
    void aBaselineWithoutAVersionFails() throws IOException {
        List<String> baseline = baseline(API_V1, "1.0.0").stream()
                .filter(l -> !l.startsWith(ApiGate.VERSION_PREFIX))
                .toList();

        List<String> problems = ApiGate.check(baseline, dump(MODULE, Map.of("fx/Api.java", API_V1)), "1.0.0");

        assertEquals(1, problems.size(), problems::toString);
        assertTrue(problems.get(0).contains("version"), problems::toString);
    }

    @Test
    void theInternalPackagesAreIgnored() throws IOException {
        String module = "module fixture { exports fx; }";
        String internalV1 = "package fx.internal;\npublic class Impl { public void a() {} }\n";
        String internalV2 = "package fx.internal;\npublic class Impl { public void b() {} }\n";
        List<String> baseline = ApiGate.baseline(
                dump(module, Map.of("fx/Api.java", API_V1, "fx/internal/Impl.java", internalV1)), "1.0.0");

        assertTrue(baseline.stream().noneMatch(l -> l.contains("fx.internal")), baseline::toString);
        assertEquals(
                List.of(),
                ApiGate.check(
                        baseline,
                        dump(module, Map.of("fx/Api.java", API_V1, "fx/internal/Impl.java", internalV2)),
                        "1.0.0"));
    }

    @Test
    void exportingAnInternalPackageFails() throws IOException {
        String module = "module fixture { exports fx; exports fx.internal; }";
        String internal = "package fx.internal;\npublic class Impl { public void a() {} }\n";

        ApiDump.Result dump = dump(module, Map.of("fx/Api.java", API_V1, "fx/internal/Impl.java", internal));

        assertTrue(
                dump.problems().stream().anyMatch(p -> p.contains("exports an internal package: fx.internal")),
                dump.problems()::toString);
        assertTrue(dump.lines().stream().noneMatch(l -> l.contains("fx.internal")), "it is still not dumped");
    }

    @Test
    void exportingAPackageBelowInternalFails() throws IOException {
        // internal anywhere in the name marks the package, not only as its last segment
        String module = "module fixture { exports fx; exports fx.internal.deep; }";
        String deep = "package fx.internal.deep;\npublic class Impl { public void a() {} }\n";

        ApiDump.Result dump = dump(module, Map.of("fx/Api.java", API_V1, "fx/internal/deep/Impl.java", deep));

        assertTrue(
                dump.problems().stream().anyMatch(p -> p.contains("exports an internal package: fx.internal.deep")),
                dump.problems()::toString);
        assertTrue(dump.lines().stream().noneMatch(l -> l.contains("fx.internal")), "it is still not dumped");
    }

    @Test
    void aPreReleaseVersionHasItsMajor() {
        assertEquals(2, ApiGate.major("2.0.0-rc1"));
        assertEquals(1, ApiGate.major("1.4.0+build.7"));
        assertEquals(0, ApiGate.major("0.12.0"));
    }

    @Test
    void anInternalTypeInAnExportedSignatureFails() throws IOException {
        String module = "module lol.trq.alts { exports lol.trq.alts; }";
        String api =
                "package lol.trq.alts;\npublic class Api { public lol.trq.alts.internal.Impl leak() { return null; } }\n";
        String internal = "package lol.trq.alts.internal;\npublic class Impl {}\n";

        ApiDump.Result dump =
                dump(module, Map.of("lol/trq/alts/Api.java", api, "lol/trq/alts/internal/Impl.java", internal));

        assertTrue(
                dump.problems().stream().anyMatch(p -> p.contains("names an internal type") && p.contains("leak()")),
                dump.problems()::toString);
        assertTrue(ApiGate.check(ApiGate.baseline(dump, "1.0.0"), dump, "1.0.0").stream()
                .anyMatch(p -> p.contains("names an internal type")));
    }

    @Test
    void theDumpCoversEveryKindOfMember() throws IOException {
        String source = """
                package fx;
                public final class Api<T extends Comparable<T>> implements java.io.Serializable {
                    public static final int LIMIT = 3;
                    protected String hidden;
                    private int secret;
                    public Api() {}
                    public <X> java.util.List<X> generic(X x, T... more) throws java.io.IOException { return null; }
                    public enum Mode { ON, OFF }
                    public record Pair(String left, @Deprecated int right) {}
                    public sealed interface Shape permits Circle {}
                    public static final class Circle implements Shape {}
                    static class Hidden { public void no() {} }
                }
                """;

        List<String> lines = dump(MODULE, Map.of("fx/Api.java", source)).lines();

        assertTrue(
                lines.contains("fx.Api type public final class Api<T extends java.lang.Comparable<T>>"
                        + " implements java.io.Serializable"),
                lines::toString);
        assertTrue(lines.contains("fx.Api field public static final int fx.Api.LIMIT"), lines::toString);
        assertTrue(lines.contains("fx.Api field protected java.lang.String fx.Api.hidden"), lines::toString);
        assertTrue(lines.contains("fx.Api ctor public fx.Api()"), lines::toString);
        assertTrue(
                lines.contains("fx.Api method public <X> java.util.List<X> fx.Api.generic(X,T...)"
                        + " throws java.io.IOException"),
                lines::toString);
        assertTrue(lines.contains("fx.Api$Mode constant ON"), lines::toString);
        assertTrue(lines.contains("fx.Api$Pair component int right"), lines::toString);
        assertTrue(
                lines.contains("fx.Api$Shape type public static abstract sealed interface Shape permits fx.Api$Circle")
                        || lines.contains(
                                "fx.Api$Shape type public static sealed interface Shape permits fx.Api$Circle"),
                lines::toString);
        assertTrue(lines.stream().noneMatch(l -> l.contains("secret") || l.contains("Hidden")), lines::toString);
        assertEquals(lines.stream().sorted().toList(), lines, "the dump is sorted");
    }

    private List<String> baseline(String api, String version) throws IOException {
        return ApiGate.baseline(dump(MODULE, Map.of("fx/Api.java", api)), version);
    }

    private ApiDump.Result dump(String module, Map<String, String> sources) throws IOException {
        Path root = Files.createTempDirectory(temp, "fixture");
        Path src = root.resolve("src");
        Path classes = root.resolve("classes");
        Files.createDirectories(classes);
        Files.createDirectories(src);
        Files.writeString(src.resolve("module-info.java"), module);
        for (Map.Entry<String, String> source : sources.entrySet()) {
            Path file = src.resolve(source.getKey());
            Files.createDirectories(file.getParent());
            Files.writeString(file, source.getValue());
        }
        List<String> files;
        try (Stream<Path> walk = Files.walk(src)) {
            files = walk.filter(p -> p.toString().endsWith(".java"))
                    .map(Path::toString)
                    .toList();
        }
        ByteArrayOutputStream diagnostics = new ByteArrayOutputStream();
        String[] args = Stream.concat(Stream.of("-d", classes.toString()), files.stream())
                .toArray(String[]::new);
        int exit = ToolProvider.getSystemJavaCompiler().run(null, diagnostics, diagnostics, args);
        assertEquals(0, exit, () -> diagnostics.toString(StandardCharsets.UTF_8));
        Path jar = root.resolve("fixture.jar");
        try (OutputStream out = Files.newOutputStream(jar);
                JarOutputStream zip = new JarOutputStream(out);
                Stream<Path> walk = Files.walk(classes)) {
            for (Path file : walk.filter(Files::isRegularFile).sorted().toList()) {
                zip.putNextEntry(
                        new JarEntry(classes.relativize(file).toString().replace('\\', '/')));
                zip.write(Files.readAllBytes(file));
                zip.closeEntry();
            }
        }
        return ApiDump.dump(jar, List.of());
    }
}
