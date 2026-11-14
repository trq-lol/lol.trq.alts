package lol.trq.alts.tools.api;

import java.io.IOException;
import java.io.InputStream;
import java.lang.classfile.Attributes;
import java.lang.classfile.ClassFile;
import java.lang.classfile.FieldModel;
import java.lang.constant.ConstantDesc;
import java.lang.module.ModuleDescriptor;
import java.lang.module.ModuleFinder;
import java.lang.module.ModuleReference;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.RecordComponent;
import java.lang.reflect.Type;
import java.lang.reflect.TypeVariable;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.stream.Collectors;

/**
 * Dumps the exported API of a modular jar as sorted text lines, from the compiled classes, by reflection and
 * with the JDK only. One line per public or protected type, record component, enum constant, field,
 * constructor and method of every accessible type in a package the module descriptor exports to everyone.
 * Each line starts with the type's binary name, so the sorted file reads type by type.
 *
 * <p>A package whose name has an {@code internal} segment is never dumped, exported or not: the compatibility
 * gate ignores it. Exporting one, or naming an internal type in an exported signature, is reported as a
 * problem instead.
 */
public final class ApiDump {

    /** The segment that marks an implementation package. */
    static final String INTERNAL_SEGMENT = "internal";

    private ApiDump() {}

    /**
     * The dump of one jar.
     *
     * @param lines the sorted API lines
     * @param problems what is wrong with the surface itself, independent of any baseline
     */
    public record Result(List<String> lines, List<String> problems) {}

    /**
     * Dumps a modular jar.
     *
     * @param jar the jar, which carries a module descriptor
     * @param dependencies what its classes need to load (Gson, for this library)
     * @return the dump
     * @throws IOException if the jar cannot be read
     */
    public static Result dump(Path jar, List<Path> dependencies) throws IOException {
        Set<ModuleReference> modules = ModuleFinder.of(jar).findAll();
        if (modules.size() != 1 || modules.iterator().next().descriptor().isAutomatic()) {
            return new Result(List.of(), List.of("the jar carries no module descriptor: " + jar.getFileName()));
        }
        ModuleDescriptor descriptor = modules.iterator().next().descriptor();
        List<String> problems = new ArrayList<>();
        Set<String> exported = new TreeSet<>();
        for (ModuleDescriptor.Exports export : descriptor.exports()) {
            if (isInternal(export.source())) {
                problems.add("the module exports an internal package: " + export.source()
                        + (export.isQualified()
                                ? " (to " + String.join(", ", new TreeSet<>(export.targets())) + ")"
                                : ""));
            } else if (!export.isQualified()) {
                exported.add(export.source());
            }
        }

        List<String> lines = new ArrayList<>();
        try (URLClassLoader loader = new URLClassLoader(urls(jar, dependencies), ClassLoader.getPlatformClassLoader());
                JarFile file = new JarFile(jar.toFile())) {
            for (String name : classNames(file)) {
                String pkg = name.lastIndexOf('.') < 0 ? "" : name.substring(0, name.lastIndexOf('.'));
                if (!exported.contains(pkg)) {
                    continue;
                }
                Class<?> type;
                try {
                    type = Class.forName(name, false, loader);
                } catch (ClassNotFoundException | LinkageError e) {
                    problems.add("cannot load " + name + ": " + e);
                    continue;
                }
                if (accessible(type)) {
                    describe(type, constants(file, name), lines);
                }
            }
        }
        lines.sort(null);
        for (String line : lines) {
            if (line.contains("lol.trq.alts." + INTERNAL_SEGMENT + ".")) {
                problems.add("an exported signature names an internal type: " + line);
            }
        }
        return new Result(List.copyOf(lines), List.copyOf(problems));
    }

    static boolean isInternal(String pkg) {
        return Arrays.asList(pkg.split("\\.")).contains(INTERNAL_SEGMENT);
    }

    private static URL[] urls(Path jar, List<Path> dependencies) throws MalformedURLException {
        List<URL> urls = new ArrayList<>();
        urls.add(jar.toUri().toURL());
        for (Path dependency : dependencies) {
            urls.add(dependency.toUri().toURL());
        }
        return urls.toArray(URL[]::new);
    }

    private static List<String> classNames(JarFile file) {
        List<String> names = new ArrayList<>();
        Enumeration<JarEntry> entries = file.entries();
        while (entries.hasMoreElements()) {
            String entry = entries.nextElement().getName();
            if (entry.endsWith(".class") && !entry.endsWith("module-info.class") && !entry.startsWith("META-INF/")) {
                names.add(entry.substring(0, entry.length() - ".class".length()).replace('/', '.'));
            }
        }
        names.sort(null);
        return names;
    }

    /** A host can name the type: public at top level, public or protected all the way out when nested. */
    private static boolean accessible(Class<?> type) {
        if (type.isSynthetic() || type.isAnonymousClass() || type.isLocalClass()) {
            return false;
        }
        for (Class<?> c = type; c != null; c = c.getDeclaringClass()) {
            int mods = c.getModifiers();
            boolean visible = c.getDeclaringClass() == null
                    ? Modifier.isPublic(mods)
                    : Modifier.isPublic(mods) || Modifier.isProtected(mods);
            if (!visible) {
                return false;
            }
        }
        return true;
    }

    private static boolean exposed(int modifiers) {
        return Modifier.isPublic(modifiers) || Modifier.isProtected(modifiers);
    }

    /**
     * The compile-time constants of a class, read from its fields' {@code ConstantValue} attributes with the
     * JDK class-file API, so nothing is initialized. A host's compiler inlines these values, so changing one
     * is a change to the API even though no signature moves.
     */
    private static Map<String, String> constants(JarFile file, String className) throws IOException {
        JarEntry entry = file.getJarEntry(className.replace('.', '/') + ".class");
        Map<String, String> out = new HashMap<>();
        byte[] bytes;
        try (InputStream in = file.getInputStream(entry)) {
            bytes = in.readAllBytes();
        }
        for (FieldModel field : ClassFile.of().parse(bytes).fields()) {
            field.findAttribute(Attributes.constantValue())
                    .ifPresent(constant -> out.put(
                            field.fieldName().stringValue(),
                            render(
                                    constant.constant().constantValue(),
                                    field.fieldTypeSymbol().descriptorString())));
        }
        return out;
    }

    /** A constant as Java source would write it, so the dump line reads like the declaration. */
    static String render(ConstantDesc value, String descriptor) {
        return switch (descriptor) {
            case "Z" -> Boolean.toString(((Integer) value) != 0);
            case "C" -> "'" + escape(String.valueOf((char) ((Integer) value).intValue())) + "'";
            case "J" -> value + "L";
            case "F" -> value + "F";
            case "D" -> value + "D";
            case "Ljava/lang/String;" -> "\"" + escape((String) value) + "\"";
            default -> String.valueOf(value);
        };
    }

    private static String escape(String text) {
        StringBuilder out = new StringBuilder();
        for (char c : text.toCharArray()) {
            switch (c) {
                case '\\' -> out.append("\\\\");
                case '"' -> out.append("\\\"");
                case '\'' -> out.append("\\'");
                default -> {
                    if (c < 0x20 || c > 0x7e) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        return out.toString();
    }

    private static void describe(Class<?> type, Map<String, String> constants, List<String> lines) {
        String owner = type.getName();
        lines.add(owner + " type " + header(type));
        if (type.isRecord()) {
            for (RecordComponent component : type.getRecordComponents()) {
                lines.add(owner + " component " + component.getGenericType().getTypeName() + " " + component.getName());
            }
        }
        for (Field field : type.getDeclaredFields()) {
            if (field.isSynthetic() || !exposed(field.getModifiers())) {
                continue;
            }
            lines.add(
                    field.isEnumConstant()
                            ? owner + " constant " + field.getName()
                            : owner + " field " + field.toGenericString() + constantSuffix(field, constants));
        }
        for (Constructor<?> constructor : type.getDeclaredConstructors()) {
            if (!constructor.isSynthetic() && exposed(constructor.getModifiers())) {
                lines.add(owner + " ctor " + constructor.toGenericString());
            }
        }
        for (Method method : type.getDeclaredMethods()) {
            if (!method.isSynthetic() && !method.isBridge() && exposed(method.getModifiers())) {
                lines.add(owner + " method " + method.toGenericString());
            }
        }
    }

    private static String constantSuffix(Field field, Map<String, String> constants) {
        int mods = field.getModifiers();
        String value = Modifier.isStatic(mods) && Modifier.isFinal(mods) ? constants.get(field.getName()) : null;
        return value == null ? "" : " = " + value;
    }

    private static String header(Class<?> type) {
        StringBuilder out = new StringBuilder();
        int mods = type.getModifiers() & Modifier.classModifiers();
        if (type.isInterface()) {
            mods &= ~Modifier.ABSTRACT;
        }
        String modifiers = Modifier.toString(mods);
        if (!modifiers.isEmpty()) {
            out.append(modifiers).append(' ');
        }
        if (type.isSealed()) {
            out.append("sealed ");
        }
        out.append(
                type.isAnnotation()
                        ? "@interface"
                        : type.isInterface()
                                ? "interface"
                                : type.isEnum() ? "enum" : type.isRecord() ? "record" : "class");
        out.append(' ').append(type.getSimpleName()).append(typeParameters(type.getTypeParameters()));
        Type superclass = type.getGenericSuperclass();
        if (superclass != null
                && !Set.of(Object.class, Enum.class, Record.class).contains(type.getSuperclass())) {
            out.append(" extends ").append(superclass.getTypeName());
        }
        Type[] interfaces = type.getGenericInterfaces();
        if (interfaces.length > 0) {
            out.append(type.isInterface() ? " extends " : " implements ")
                    .append(Arrays.stream(interfaces).map(Type::getTypeName).collect(Collectors.joining(", ")));
        }
        if (type.isSealed()) {
            out.append(" permits ")
                    .append(Arrays.stream(type.getPermittedSubclasses())
                            .map(Class::getName)
                            .sorted()
                            .collect(Collectors.joining(", ")));
        }
        return out.toString();
    }

    private static String typeParameters(TypeVariable<?>[] variables) {
        if (variables.length == 0) {
            return "";
        }
        return Arrays.stream(variables)
                .map(v -> {
                    List<String> bounds = Arrays.stream(v.getBounds())
                            .filter(b -> b != Object.class)
                            .map(Type::getTypeName)
                            .toList();
                    return bounds.isEmpty() ? v.getName() : v.getName() + " extends " + String.join(" & ", bounds);
                })
                .collect(Collectors.joining(", ", "<", ">"));
    }
}
