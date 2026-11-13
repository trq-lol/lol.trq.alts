package lol.trq.alts.store;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

/**
 * Reads what the stores leave on disk, for tests in any package. Each test owns its stores (or its
 * runtime) and closes them, so there is no process-wide state left to reset.
 */
public final class StoreTestHooks {

    private StoreTestHooks() {}

    /** Returns the content of every unreadable copy kept beside {@code fileName}, oldest first. */
    public static List<byte[]> unreadableCopies(Path directory, String fileName) throws IOException {
        List<Path> copies;
        try (Stream<Path> entries = Files.list(directory)) {
            copies = entries.filter(
                            entry -> entry.getFileName().toString().startsWith(fileName + StoreFile.UNREADABLE_SUFFIX))
                    .sorted()
                    .toList();
        }
        List<byte[]> contents = new ArrayList<>();
        for (Path copy : copies) {
            contents.add(Files.readAllBytes(copy));
        }
        return contents;
    }

    /** Returns whether {@code file} opens under the machine-derived key for {@code keyBinding}. */
    public static boolean opensUnderMachineKey(Path file, String keyBinding) throws IOException {
        String sealed = new String(Files.readAllBytes(file), StandardCharsets.ISO_8859_1).strip();
        try {
            EncryptionUtil.decrypt(sealed, EncryptionUtil.getHardwareKey(keyBinding));
            return true;
        } catch (Exception sealedUnderSomethingElse) {
            return false;
        }
    }

    /**
     * Returns every file in {@code directory} that opens under the machine-derived key. The lock files
     * are left out: they hold nothing, and an open store's lock file cannot be read on every platform.
     */
    public static List<Path> filesOpeningUnderMachineKey(Path directory, String keyBinding) throws IOException {
        List<Path> files;
        try (Stream<Path> entries = Files.list(directory)) {
            files = entries.filter(Files::isRegularFile)
                    .filter(file -> !isLockFile(file))
                    .toList();
        }
        List<Path> open = new ArrayList<>();
        for (Path file : files) {
            if (opensUnderMachineKey(file, keyBinding)) {
                open.add(file);
            }
        }
        return open;
    }

    /** Returns whether {@code file} is a store's sidecar lock file. */
    public static boolean isLockFile(Path file) {
        return file.getFileName().toString().endsWith(StoreFile.LOCK_SUFFIX);
    }
}
