package lol.trq.alts;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.source.doctree.DocCommentTree;
import com.sun.source.doctree.DocTree;
import com.sun.source.doctree.SinceTree;
import com.sun.source.tree.ClassTree;
import com.sun.source.tree.CompilationUnitTree;
import com.sun.source.tree.MethodTree;
import com.sun.source.tree.ModifiersTree;
import com.sun.source.tree.NewClassTree;
import com.sun.source.tree.Tree;
import com.sun.source.tree.VariableTree;
import com.sun.source.util.DocTrees;
import com.sun.source.util.JavacTask;
import com.sun.source.util.TreePath;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import javax.lang.model.element.Modifier;
import javax.tools.JavaCompiler;
import javax.tools.StandardJavaFileManager;
import javax.tools.ToolProvider;
import org.junit.jupiter.api.Test;

/**
 * Every declaration a host can name in an exported package carries an {@code @since} naming a release: each
 * public or protected type, constructor, method, field and enum constant, read from the sources. A record's
 * components are documented by its {@code @param} tags and its implicit members have no declaration, so
 * neither is checked. A release is a version the CHANGELOG has a heading for, or the version of the
 * committed API dump.
 */
class SinceTagsTest {

    private static final Path SOURCES = Path.of("src/main/java");
    private static final Pattern VERSION = Pattern.compile("^(\\d+\\.\\d+\\.\\d+)\\b");

    @Test
    void everyExportedDeclarationNamesTheReleaseItShippedIn() throws IOException {
        Set<String> releases = releases();
        List<String> problems = new ArrayList<>();
        int checked = 0;
        for (CompilationUnitTree unit : exportedUnits()) {
            for (Declaration declaration : declarations(unit)) {
                checked++;
                String problem = problem(declaration, releases);
                if (problem != null) {
                    problems.add(declaration.where() + ": " + problem);
                }
            }
        }

        int scanned = checked;
        assertTrue(scanned > 500, () -> "the scan found too little to be the API; it checked " + scanned);
        assertEquals(List.of(), problems, () -> problems.size() + " declaration(s):\n" + String.join("\n", problems));
    }

    private static String problem(Declaration declaration, Set<String> releases) {
        if (declaration.doc() == null) {
            return "no Javadoc";
        }
        List<String> since = new ArrayList<>();
        for (DocTree tag : declaration.doc().getBlockTags()) {
            if (tag instanceof SinceTree s) {
                since.add(s.getBody().toString().trim());
            }
        }
        if (since.isEmpty()) {
            return "no @since";
        }
        if (since.size() > 1) {
            return "more than one @since";
        }
        Matcher version = VERSION.matcher(since.get(0));
        if (!version.find()) {
            return "@since does not begin with a version: " + since.get(0);
        }
        if (!releases.contains(version.group(1))) {
            return "@since " + version.group(1) + " is not a release (" + releases + ")";
        }
        return null;
    }

    /** The CHANGELOG's release headings, plus the version the API dump belongs to. */
    private static Set<String> releases() throws IOException {
        Set<String> releases = new TreeSet<>();
        Matcher heading =
                Pattern.compile("(?m)^## \\[(\\d+\\.\\d+\\.\\d+)]").matcher(Files.readString(Path.of("CHANGELOG.md")));
        while (heading.find()) {
            releases.add(heading.group(1));
        }
        Matcher dump =
                Pattern.compile("(?m)^# version (\\S+)$").matcher(Files.readString(Path.of("api/lol.trq.alts.api")));
        assertTrue(dump.find(), "the API dump records its version");
        releases.add(dump.group(1));
        return releases;
    }

    private record Declaration(String where, DocCommentTree doc) {}

    private static DocTrees docs;

    private static List<CompilationUnitTree> exportedUnits() throws IOException {
        Set<String> exported = new TreeSet<>();
        Matcher export = Pattern.compile("(?m)^\\s*exports\\s+([\\w.]+)\\s*;")
                .matcher(Files.readString(SOURCES.resolve("module-info.java")));
        while (export.find()) {
            exported.add(export.group(1));
        }
        assertTrue(exported.contains("lol.trq.alts"), () -> "exports " + exported);
        List<Path> files;
        try (Stream<Path> walk = Files.walk(SOURCES)) {
            files = walk.filter(p -> p.toString().endsWith(".java"))
                    .filter(p -> !p.getFileName().toString().equals("module-info.java"))
                    .filter(p -> exported.contains(SOURCES.relativize(p.getParent())
                            .toString()
                            .replace('\\', '.')
                            .replace('/', '.')))
                    .sorted()
                    .toList();
        }
        JavaCompiler javac = ToolProvider.getSystemJavaCompiler();
        assertNotNull(javac, "the test JVM is a JDK");
        StandardJavaFileManager files0 = javac.getStandardFileManager(null, null, StandardCharsets.UTF_8);
        JavacTask task = (JavacTask) javac.getTask(
                null, files0, d -> {}, List.of("-proc:none"), null, files0.getJavaFileObjectsFromPaths(files));
        List<CompilationUnitTree> units = new ArrayList<>();
        task.parse().forEach(units::add);
        docs = DocTrees.instance(task);
        return units;
    }

    private static List<Declaration> declarations(CompilationUnitTree unit) {
        List<Declaration> out = new ArrayList<>();
        for (Tree tree : unit.getTypeDecls()) {
            if (tree instanceof ClassTree type && type.getModifiers().getFlags().contains(Modifier.PUBLIC)) {
                type(unit, type, unit.getPackageName() + ".", out);
            }
        }
        return out;
    }

    private static void type(CompilationUnitTree unit, ClassTree type, String prefix, List<Declaration> out) {
        String name = prefix + type.getSimpleName();
        out.add(declaration(unit, type, name));
        boolean inInterface = type.getKind() == Tree.Kind.INTERFACE || type.getKind() == Tree.Kind.ANNOTATION_TYPE;
        boolean isRecord = type.getKind() == Tree.Kind.RECORD;
        for (Tree member : type.getMembers()) {
            if (member instanceof ClassTree nested) {
                if (visible(nested.getModifiers(), inInterface)) {
                    type(unit, nested, name + ".", out);
                }
            } else if (member instanceof MethodTree method) {
                if (visible(method.getModifiers(), inInterface)) {
                    String label = method.getName().contentEquals("<init>")
                            ? type.getSimpleName().toString()
                            : method.getName().toString();
                    out.add(declaration(
                            unit,
                            method,
                            name + "#" + label + "(" + method.getParameters().size() + ")"));
                }
            } else if (member instanceof VariableTree field) {
                boolean constant = type.getKind() == Tree.Kind.ENUM
                        && field.getInitializer() instanceof NewClassTree init
                        && init.getIdentifier().toString().contentEquals(type.getSimpleName());
                boolean component = isRecord && !field.getModifiers().getFlags().contains(Modifier.STATIC);
                if (constant || (!component && visible(field.getModifiers(), inInterface))) {
                    out.add(declaration(unit, field, name + "#" + field.getName()));
                }
            }
        }
    }

    private static boolean visible(ModifiersTree modifiers, boolean inInterface) {
        Set<Modifier> flags = modifiers.getFlags();
        if (flags.contains(Modifier.PRIVATE)) {
            return false;
        }
        return flags.contains(Modifier.PUBLIC) || flags.contains(Modifier.PROTECTED) || inInterface;
    }

    private static Declaration declaration(CompilationUnitTree unit, Tree tree, String where) {
        return new Declaration(where, docs.getDocCommentTree(TreePath.getPath(unit, tree)));
    }
}
