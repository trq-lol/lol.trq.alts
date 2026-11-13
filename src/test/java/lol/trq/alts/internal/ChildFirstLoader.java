package lol.trq.alts.internal;

import java.io.IOException;
import java.io.InputStream;

/**
 * A class loader that defines one class itself, from its parent's bytes, and delegates every other: the
 * copy has the library's own class name but another defining loader, which is what an internal bridge's
 * install check has to tell apart.
 */
public final class ChildFirstLoader extends ClassLoader {

    private final String own;

    /**
     * Creates the loader.
     *
     * @param parent the loader whose bytes are copied and to which everything else is delegated
     * @param own the binary name of the one class this loader defines itself
     */
    public ChildFirstLoader(ClassLoader parent, String own) {
        super(parent);
        this.own = own;
    }

    @Override
    protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
        if (!name.equals(own)) {
            return super.loadClass(name, resolve);
        }
        synchronized (getClassLoadingLock(name)) {
            Class<?> loaded = findLoadedClass(name);
            if (loaded == null) {
                String resource = name.replace('.', '/') + ".class";
                try (InputStream in = getParent().getResourceAsStream(resource)) {
                    if (in == null) {
                        throw new ClassNotFoundException(name);
                    }
                    byte[] bytes = in.readAllBytes();
                    loaded = defineClass(name, bytes, 0, bytes.length);
                } catch (IOException unreadable) {
                    throw new ClassNotFoundException(name, unreadable);
                }
            }
            if (resolve) {
                resolveClass(loaded);
            }
            return loaded;
        }
    }
}
