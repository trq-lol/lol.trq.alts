package lol.trq.alts;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.module.ModuleDescriptor;
import java.lang.module.ModuleFinder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.TimeUnit;
import java.util.jar.Attributes;
import java.util.jar.JarFile;
import java.util.stream.Collectors;
import javax.tools.JavaCompiler;
import javax.tools.ToolProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * A host on the module path, against the built jar: a consumer module that {@code requires lol.trq.alts}
 * compiles and runs with Gson resolved transitively, and one that imports an internal type does not compile.
 * The Gradle {@code test} task passes the jar and Gson's jar as system properties.
 */
class ModulePathConsumerTest {

    private static final String CONSUMER_MODULE = "module example.consumer {\n    requires lol.trq.alts;\n}\n";

    /**
     * Uses the runtime and its builder, a service interface, the account store and host secrets, the vault
     * API and the exception, plus a Gson type it never requires itself. It writes through one runtime and
     * reads back through a second, so Gson rebuilds the store's private records inside the module.
     */
    private static final String CONSUMER_MAIN = """
            package example.consumer;

            import com.google.gson.JsonObject;
            import java.nio.file.Path;
            import java.util.Optional;
            import lol.trq.alts.AltsException;
            import lol.trq.alts.AltsFailure;
            import lol.trq.alts.AltsRuntime;
            import lol.trq.alts.auth.AltLoginService;
            import lol.trq.alts.auth.LoginResult;
            import lol.trq.alts.model.LoginMode;
            import lol.trq.alts.store.AccountStore;
            import lol.trq.alts.vault.RepoLocator;
            import lol.trq.alts.vault.SharedVault;

            public final class Main {
                public static void main(String[] args) throws Exception {
                    Path dir = Path.of(args[0]);
                    try (AltsRuntime<Object> alts = runtime(dir)) {
                        AltLoginService login = alts.loginService();
                        LoginResult result = login.loginOffline("ModuleHost", LoginMode.ADD).get();
                        System.out.println("login " + result.success());
                        alts.secrets().put("token", "kept");
                    }
                    try (AltsRuntime<Object> alts = runtime(dir)) {
                        AccountStore store = alts.store();
                        System.out.println("accounts " + store.accounts().size() + " " + store.accounts().get(0).username());
                        System.out.println("secret " + alts.secrets().get("token"));
                        System.out.println("loadError " + store.loadError().isPresent());
                        Optional<SharedVault> vault = Optional.empty();
                        System.out.println("vault " + vault.isPresent() + " " + (alts.vault() != null));
                    }
                    try {
                        RepoLocator.parse("not a locator");
                        System.out.println("parsed");
                    } catch (AltsException e) {
                        System.out.println("refused " + (e.kind() == AltsFailure.Kind.INVALID_INPUT));
                    }
                    JsonObject json = new JsonObject();
                    json.addProperty("gson", "transitive");
                    System.out.println(json);
                }

                private static AltsRuntime<Object> runtime(Path dir) {
                    return new AltsRuntime.Builder<Object>()
                            .sessionInjector(session -> {})
                            .vaultDirectory(() -> dir)
                            .mainThread(Runnable::run)
                            .toastSink((level, title, description, durationMs) -> {})
                            .build();
                }
            }
            """;

    private static final String INTERNAL_MAIN = """
            package example.consumer;

            import lol.trq.alts.internal.net.HttpTransport;

            public final class Main {
                public static void main(String[] args) {
                    System.out.println(HttpTransport.class);
                }
            }
            """;

    @TempDir
    Path temp;

    @Test
    void aConsumerModuleCompilesAndRunsWithGsonResolvedTransitively() throws Exception {
        Path out = temp.resolve("out");
        Compilation compiled = compile(temp.resolve("src"), CONSUMER_MAIN, out);
        assertEquals(0, compiled.exit(), () -> "the consumer must compile:\n" + compiled.diagnostics());

        Path data = Files.createDirectories(temp.resolve("data"));
        List<String> command = new ArrayList<>(List.of(
                javaBinary(),
                "--module-path",
                String.join(
                        java.io.File.pathSeparator,
                        out.toString(),
                        libraryJar().toString(),
                        gsonJar().toString()),
                "--module",
                "example.consumer/example.consumer.Main",
                data.toString()));
        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        assertTrue(process.waitFor(60, TimeUnit.SECONDS), "the consumer must finish");
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);

        assertEquals(0, process.exitValue(), () -> "the consumer must run:\n" + output);
        assertEquals(
                List.of(
                        "login true",
                        "accounts 1 ModuleHost",
                        "secret kept",
                        "loadError false",
                        "vault false true",
                        "refused true",
                        "{\"gson\":\"transitive\"}"),
                output.lines().toList());
    }

    @Test
    void aConsumerImportingAnInternalTypeDoesNotCompile() throws IOException {
        Compilation compiled = compile(temp.resolve("src"), INTERNAL_MAIN, temp.resolve("out"));

        assertNotEquals(0, compiled.exit(), "an internal package must not be readable");
        assertTrue(
                compiled.diagnostics().contains("lol.trq.alts.internal.net"),
                () -> "the refusal must name the internal package:\n" + compiled.diagnostics());
        assertTrue(
                compiled.diagnostics().contains("declared in module lol.trq.alts")
                        && compiled.diagnostics().contains("does not export"),
                () -> "the refusal must be the module's, not a missing class:\n" + compiled.diagnostics());
    }

    @Test
    void theJarIsTheModuleItsDescriptorDeclares() throws IOException {
        ModuleDescriptor descriptor =
                ModuleFinder.of(libraryJar()).find("lol.trq.alts").orElseThrow().descriptor();

        assertFalse(descriptor.isAutomatic(), "the jar carries a module descriptor");
        Set<String> exported = descriptor.exports().stream()
                .filter(e -> !e.isQualified())
                .map(ModuleDescriptor.Exports::source)
                .collect(Collectors.toCollection(TreeSet::new));
        assertTrue(exported.contains("lol.trq.alts"), () -> "exports " + exported);
        assertTrue(
                exported.stream().noneMatch(p -> p.contains(".internal")),
                () -> "no internal package is exported: " + exported);
        assertTrue(
                descriptor.exports().stream().noneMatch(e -> e.source().contains(".internal")),
                "no internal package is exported to anyone");
        assertTrue(
                descriptor.requires().stream()
                        .anyMatch(r -> r.name().equals("com.google.gson")
                                && r.modifiers().contains(ModuleDescriptor.Requires.Modifier.TRANSITIVE)),
                "Gson is required transitively");
        // Reflection is opened to Gson only, and only where it builds private records: the store files', the
        // device-code response's, and the one an account is read and written through. The exported model
        // package is not opened: no final field of AltAccount is set by reflection.
        assertEquals(
                Set.of(
                        "lol.trq.alts.store -> [com.google.gson]",
                        "lol.trq.alts.internal.auth -> [com.google.gson]",
                        "lol.trq.alts.internal.store -> [com.google.gson]"),
                descriptor.opens().stream()
                        .map(o -> o.source() + " -> " + new TreeSet<>(o.targets()))
                        .collect(Collectors.toSet()),
                "the opens are exactly the three Gson needs");
        assertFalse(descriptor.isOpen(), "the module is not open");
    }

    @Test
    void theJarIsSealedAndNamesNoAutomaticModule() throws IOException {
        try (JarFile jar = new JarFile(libraryJar().toFile())) {
            Attributes main = jar.getManifest().getMainAttributes();

            assertEquals("true", main.getValue(Attributes.Name.SEALED), "the jar is sealed");
            assertEquals(null, main.getValue("Automatic-Module-Name"), "the descriptor names the module");
        }
    }

    private record Compilation(int exit, String diagnostics) {}

    private static Compilation compile(Path src, String main, Path out) throws IOException {
        Path moduleInfo = src.resolve("module-info.java");
        Path mainFile = src.resolve("example/consumer/Main.java");
        Files.createDirectories(mainFile.getParent());
        Files.writeString(moduleInfo, CONSUMER_MODULE);
        Files.writeString(mainFile, main);
        Files.createDirectories(out);
        JavaCompiler javac = ToolProvider.getSystemJavaCompiler();
        assertNotNull(javac, "the test JVM is a JDK");
        ByteArrayOutputStream diagnostics = new ByteArrayOutputStream();
        int exit = javac.run(
                null,
                diagnostics,
                diagnostics,
                // In process, javac would otherwise default to this JVM's class path, which holds the
                // library's classes outside any module.
                "--class-path",
                Files.createDirectories(out.resolveSibling("empty-class-path")).toString(),
                "--module-path",
                String.join(
                        java.io.File.pathSeparator,
                        libraryJar().toString(),
                        gsonJar().toString()),
                "-d",
                out.toString(),
                moduleInfo.toString(),
                mainFile.toString());
        return new Compilation(exit, diagnostics.toString(StandardCharsets.UTF_8));
    }

    private static String javaBinary() {
        return ProcessHandle.current().info().command().orElseThrow();
    }

    private static Path libraryJar() {
        return required("lol.trq.alts.moduleJar");
    }

    private static Path gsonJar() {
        return required("lol.trq.alts.gsonJar");
    }

    private static Path required(String property) {
        String value = System.getProperty(property);
        assertNotNull(value, () -> property + " is set by the Gradle test task; set it to run this test elsewhere");
        Path path = Path.of(value);
        assertTrue(Files.isRegularFile(path), () -> property + " names no file: " + path);
        return path;
    }
}
