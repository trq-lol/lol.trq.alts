package lol.trq.alts.store;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.AccessDeniedException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;
import lol.trq.alts.spi.StoreKeyProvider;
import lol.trq.alts.spi.VaultDirectoryProvider;

/**
 * The one encrypted file behind a store: where it lives, what key seals it, and how a snapshot of the
 * store's state reaches the disk without ever leaving a half-written file there.
 *
 * <p>A write goes to a sibling temporary file, is forced to disk, and is then moved over the store in
 * one step, so a crash or a second writer leaves either the old file or the new one and never a blend.
 * Writes are serialized, and each carries the order its snapshot was taken in, so a late writer cannot
 * put an older state over a newer one. The file a write replaces is kept as a single rolling backup.
 *
 * <p>Three rules keep a store from being lost or weakened. A file that could not be read is copied aside
 * under a name of its own before anything replaces it. While the last load failed because the host's key
 * was unavailable, nothing is written at all, since the file on disk is intact and merely unread. And a
 * host key, once installed, is never dropped: a file that does not open under it is unreadable, except
 * on the one launch a host asks for files from before the key to be migrated.
 *
 * <p>Nothing here throws at a caller. A failed read is reported on {@link #loadError()} and a failed
 * write on {@link #saveError()}, and both are built from the file's name and a fixed phrase — the JDK's
 * own I/O messages are the absolute path, and these strings travel into a host's UI and its log.
 *
 * @author trq
 * @since 0.12.0
 */
final class StoreFile {

    /** How long a burst of mutations is gathered for before it is written, when coalescing is on. */
    static final Duration DEFAULT_WRITE_DELAY = Duration.ofMillis(100);

    /** Suffix of the temporary file a write is staged in. */
    static final String TEMP_SUFFIX = ".tmp";

    /** Suffix of the rolling copy of the last good file a write replaced. */
    static final String BACKUP_SUFFIX = ".bak";

    /**
     * Start of the suffix given to a copy of a store file that could not be read, so a failed load never
     * costs the data. Each copy's name continues with the time it was made.
     */
    static final String UNREADABLE_SUFFIX = ".unreadable";

    /** How many unreadable copies are kept; the oldest go once there are more. */
    static final int MAX_UNREADABLE_KEPT = 5;

    /** Every store file in the process, for the shutdown flush. */
    private static final List<StoreFile> ALL = new CopyOnWriteArrayList<>();

    /** Serializes every read and write of the file, and guards the key cache. */
    private final Object ioLock = new Object();

    /** Guards the pending snapshot and its bookkeeping; never held across I/O. */
    private final Object pendingLock = new Object();

    private volatile String fileName;
    private volatile String keyBinding;
    private volatile VaultDirectoryProvider directoryProvider;
    private volatile StoreKeyProvider keyProvider;
    private volatile boolean migrateFromMachineKey;
    private volatile long writeDelayMillis;
    private volatile String loadError;
    private volatile String saveError;

    private Pending pending;
    private ScheduledFuture<?> timer;
    private long timerDueNanos;
    private long submitted;

    private long written;
    private boolean knownGood;
    private boolean unreadableOnDisk;
    private boolean awaitingKey;
    private boolean resealing;
    private String hostSecret;
    private String sealedUnder;
    private EncryptionUtil.DerivedKey sealingKey;

    /**
     * Creates the file with its neutral defaults; a host overrides them through {@link #configure}.
     *
     * @param defaultFileName the on-disk filename
     * @param defaultKeyBinding the constant mixed into the encryption key
     */
    StoreFile(String defaultFileName, String defaultKeyBinding) {
        this.fileName = defaultFileName;
        this.keyBinding = defaultKeyBinding;
        ALL.add(this);
    }

    /**
     * Points the file at a host directory and installs the host's key in the same step, so there is no
     * moment at which the new directory is bound and a write could still be sealed under the machine
     * key. Writes go back to synchronous until {@link #writeDelay} says otherwise. A snapshot still
     * waiting to be written goes to the previous directory first.
     *
     * <p>A null {@code key} leaves an installed provider in place: the provider is process-wide, and a
     * second binding that names none must not downgrade the store to the machine-derived key.
     *
     * @param provider the host-supplied vault directory provider
     * @param key the host key provider, or null to keep the one in place
     * @param migrate whether a file that opens only under the machine-derived key may be loaded and
     *     resealed under the host's; applies only while a key provider is installed
     */
    void bind(VaultDirectoryProvider provider, StoreKeyProvider key, boolean migrate) {
        Objects.requireNonNull(provider, "VaultDirectoryProvider");
        if (directoryProvider != null) {
            flush();
        }
        synchronized (ioLock) {
            directoryProvider = provider;
            if (key != null && key != keyProvider) {
                keyProvider = key;
                forgetKeys();
            }
            migrateFromMachineKey = migrate;
            writeDelayMillis = 0L;
            knownGood = false;
        }
    }

    /**
     * Overrides the filename and key-binding constant. Null or blank arguments leave the current value
     * unchanged.
     *
     * @param storeFileName the on-disk filename, or null/blank to keep the current one
     * @param storeKeyBinding the key-binding constant, or null/blank to keep the current one
     */
    void configure(String storeFileName, String storeKeyBinding) {
        if (storeFileName != null && !storeFileName.isBlank()) {
            fileName = storeFileName;
        }
        if (storeKeyBinding != null && !storeKeyBinding.isBlank()) {
            keyBinding = storeKeyBinding;
        }
    }

    /**
     * Installs the host's key provider. A null argument is ignored: an installed provider is never
     * removed this way, because removing it would send the next write out under the machine-derived key.
     *
     * @param provider the host key provider, or null to keep the one in place
     */
    void keyProvider(StoreKeyProvider provider) {
        if (provider == null) {
            return;
        }
        synchronized (ioLock) {
            keyProvider = provider;
            forgetKeys();
        }
    }

    /**
     * Returns the file to the state of a process that never installed a key provider and never loaded:
     * no host key, no migration, no recorded failure, and nothing waiting to be written. For tests only,
     * which is why it is not reachable from outside this package.
     */
    void resetForTests() {
        synchronized (ioLock) {
            synchronized (pendingLock) {
                pending = null;
            }
            keyProvider = null;
            migrateFromMachineKey = false;
            forgetKeys();
            knownGood = false;
            unreadableOnDisk = false;
            awaitingKey = false;
            resealing = false;
            loadError = null;
            saveError = null;
        }
    }

    /**
     * Sets how long mutations are gathered for before one write covers them all.
     *
     * @param delay the coalescing window; null, zero, or negative writes synchronously
     */
    void writeDelay(Duration delay) {
        writeDelayMillis = delay == null || delay.isNegative() ? 0L : delay.toMillis();
    }

    /**
     * Returns the filename, for messages that name the file without naming its path.
     *
     * @return the on-disk filename
     */
    String fileName() {
        return fileName;
    }

    /**
     * Returns why the last load could not read an existing file.
     *
     * @return the failure description, or null when the last load succeeded or found no file, or when
     *     the store has been written successfully since
     */
    String loadError() {
        return loadError;
    }

    /**
     * Returns why the last write did not reach the disk.
     *
     * @return the failure description, or null when the last write succeeded
     */
    String saveError() {
        return saveError;
    }

    /**
     * Hands over a snapshot to be written. The caller must hold the lock that guards the store's state,
     * so the order snapshots arrive in is the order the state went through. With no write delay the
     * snapshot is on disk when this returns; with one, it is written by the background writer, by the
     * next {@link #flush()}, or at JVM shutdown, whichever comes first.
     *
     * @param plaintext produces the serialized snapshot; it is called at most once, off the caller's
     *     thread when coalescing, so it must close over an immutable copy
     */
    void submit(Supplier<String> plaintext) {
        long delay = writeDelayMillis;
        boolean inline = delay <= 0;
        synchronized (pendingLock) {
            pending = new Pending(++submitted, plaintext);
            if (!inline) {
                inline = !schedule(delay);
            }
        }
        if (inline) {
            flush();
        }
    }

    /**
     * Writes the snapshot that is waiting, if one is, and returns once it is on disk. Also waits out a
     * write already in progress on another thread.
     */
    void flush() {
        synchronized (ioLock) {
            Pending next;
            synchronized (pendingLock) {
                next = pending;
                pending = null;
            }
            if (next == null || next.order() <= written) {
                return;
            }
            if (awaitingKey) {
                // The file on disk is intact; it simply has not been read. Writing what is in memory
                // now would replace every account in it with whatever was added since.
                saveError = fileName + ": not written, because the store key was unavailable when the store"
                        + " was loaded; load it again first";
                retain(next);
                return;
            }
            try {
                write(next.plaintext().get());
                written = next.order();
                knownGood = true;
                unreadableOnDisk = false;
                resealing = false;
                saveError = null;
                // The file on disk is now the one just written, so an earlier failure to read what it
                // replaced no longer describes it.
                loadError = null;
            } catch (WriteFailure failure) {
                saveError = fileName + ": " + failure.getMessage();
                retain(next);
            } catch (RuntimeException failure) {
                saveError = fileName + ": could not be written";
                retain(next);
            }
        }
    }

    /**
     * Reads and decrypts the file and hands the plaintext to {@code installer}. A snapshot waiting to be
     * written lands first, so a load never reads a file older than the state already in memory. The
     * caller must hold the lock that guards the store's state.
     *
     * @param installer parses the plaintext into the store; a throw marks the file unreadable
     * @return what the load found
     */
    LoadOutcome load(Installer installer) {
        flush();
        synchronized (ioLock) {
            String name = fileName;
            Path file;
            try {
                file = directory().resolve(name);
            } catch (RuntimeException unavailable) {
                return unreadable(name, "store directory unavailable");
            }
            if (!Files.exists(file)) {
                loadError = null;
                knownGood = false;
                unreadableOnDisk = false;
                if (awaitingKey) {
                    // There is no store left to protect, so what was held back can be written.
                    awaitingKey = false;
                    flush();
                }
                return LoadOutcome.ABSENT;
            }

            String sealed;
            try {
                // Latin-1 so that a file which is not text at all still reaches the decoder and fails
                // there, as "not a store", rather than here as a charset error.
                sealed = new String(Files.readAllBytes(file), StandardCharsets.ISO_8859_1).strip();
            } catch (IOException failure) {
                return unreadable(name, reason(failure, "could not be read"));
            }

            String password;
            try {
                password = password();
            } catch (WriteFailure keyUnavailable) {
                awaitingKey = true;
                return unreadable(name, keyUnavailable.getMessage());
            }
            boolean heldBack = awaitingKey;
            awaitingKey = false;

            String plaintext;
            boolean migrated = false;
            try {
                plaintext = EncryptionUtil.decrypt(sealed, password);
            } catch (Exception wrongKeyOrDamaged) {
                // Only on the host's explicit say-so. Trying the machine key every time would let anyone
                // who can write the directory plant a file sealed under it, and have it load.
                plaintext = keyProvider != null && migrateFromMachineKey ? openUnderMachineKey(sealed) : null;
                if (plaintext == null) {
                    return unreadable(name, "could not be decrypted (wrong key or damaged file)");
                }
                migrated = true;
            }

            try {
                installer.install(plaintext);
            } catch (Exception malformed) {
                return unreadable(name, "contents are not a valid store");
            }
            if (heldBack) {
                // What was held back is a snapshot of memory from before this load replaced it.
                synchronized (pendingLock) {
                    pending = null;
                }
                saveError = null;
            }
            loadError = null;
            knownGood = true;
            unreadableOnDisk = false;
            resealing = migrated;
            return migrated ? LoadOutcome.MIGRATED : LoadOutcome.LOADED;
        }
    }

    /** Flushes every store file in the process; run at JVM shutdown. */
    private static void flushAll() {
        for (StoreFile file : ALL) {
            file.flush();
        }
    }

    /**
     * Tries a file that did not open under the host's key against the machine-derived default, which is
     * what sealed it before the host installed a key provider.
     *
     * @param sealed the encrypted bundle
     * @return the plaintext, or null when the file does not open under the default key either
     */
    private String openUnderMachineKey(String sealed) {
        try {
            return EncryptionUtil.decrypt(sealed, EncryptionUtil.getHardwareKey(keyBinding));
        } catch (Exception notTheDefaultKeyEither) {
            return null;
        }
    }

    /**
     * Reseals every kept copy of the store that still opens under the machine-derived key — the rolling
     * backup and any unreadable copy — under the host's key. A host installs a key so that a copied
     * directory does not open offline, and one such copy left behind would undo that for the whole
     * store. A copy that cannot be resealed is deleted; one that can be neither fails the write.
     *
     * @param directory the store directory
     * @param name the store file's name
     * @throws WriteFailure when a machine-keyed copy could be neither resealed nor removed
     */
    private void resealMachineKeyedCopies(Path directory, String name) throws WriteFailure {
        List<Path> copies = new ArrayList<>(unreadableCopies(directory, name));
        Path backup = directory.resolve(name + BACKUP_SUFFIX);
        if (Files.exists(backup)) {
            copies.add(backup);
        }
        for (Path copy : copies) {
            String plaintext;
            try {
                plaintext =
                        openUnderMachineKey(new String(Files.readAllBytes(copy), StandardCharsets.ISO_8859_1).strip());
            } catch (IOException unread) {
                plaintext = null;
            }
            if (plaintext == null) {
                continue;
            }
            Path staged = copy.resolveSibling(copy.getFileName() + TEMP_SUFFIX);
            try {
                writeDurably(
                        staged, EncryptionUtil.encrypt(plaintext, sealingKey()).getBytes(StandardCharsets.US_ASCII));
                moveIntoPlace(staged, copy);
            } catch (IOException | GeneralSecurityException notResealed) {
                discard(staged);
                try {
                    Files.deleteIfExists(copy);
                } catch (IOException stillThere) {
                    throw new WriteFailure("a copy sealed under the machine key could not be resealed or removed");
                }
            }
        }
    }

    /**
     * Lists the unreadable copies kept beside the store, oldest first.
     *
     * @param directory the store directory
     * @param name the store file's name
     * @return the copies, sorted by name, which sorts them by the time each was made
     */
    private static List<Path> unreadableCopies(Path directory, String name) {
        String prefix = name + UNREADABLE_SUFFIX;
        List<Path> copies = new ArrayList<>();
        try (DirectoryStream<Path> entries = Files.newDirectoryStream(directory)) {
            for (Path entry : entries) {
                String entryName = entry.getFileName().toString();
                if (entryName.startsWith(prefix) && !entryName.endsWith(TEMP_SUFFIX)) {
                    copies.add(entry);
                }
            }
        } catch (IOException | RuntimeException unlistable) {
            return List.of();
        }
        copies.sort((left, right) ->
                left.getFileName().toString().compareTo(right.getFileName().toString()));
        return copies;
    }

    /**
     * Records a failed load.
     *
     * @param name the file's name
     * @param reason a fixed, path-free phrase
     * @return {@link LoadOutcome#FAILED}
     */
    private LoadOutcome unreadable(String name, String reason) {
        loadError = name + ": " + reason;
        knownGood = false;
        unreadableOnDisk = true;
        return LoadOutcome.FAILED;
    }

    /**
     * Keeps a snapshot whose write failed so the next flush retries it, unless a newer one has arrived.
     *
     * @param failed the snapshot that did not reach the disk
     */
    private void retain(Pending failed) {
        synchronized (pendingLock) {
            if (pending == null) {
                pending = failed;
            }
        }
    }

    /**
     * Makes sure a flush is queued on the background writer no later than {@code delayMillis} from now.
     * A flush already queued sooner than that covers this snapshot too, which is the coalescing; one
     * queued later, under a longer delay since shortened, is replaced. Called with the pending lock held.
     *
     * @param delayMillis how long to gather mutations for
     * @return true when a flush is queued, false when the writer is unavailable and the caller must
     *     write inline
     */
    private boolean schedule(long delayMillis) {
        long due = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(delayMillis);
        if (timer != null && timerDueNanos - due <= 0) {
            return true;
        }
        try {
            ScheduledFuture<?> replaced = timer;
            timer = Writer.EXECUTOR.schedule(this::flushScheduled, delayMillis, TimeUnit.MILLISECONDS);
            timerDueNanos = due;
            if (replaced != null) {
                replaced.cancel(false);
            }
            return true;
        } catch (RejectedExecutionException unavailable) {
            return false;
        }
    }

    private void flushScheduled() {
        synchronized (pendingLock) {
            timer = null;
        }
        flush();
    }

    /**
     * Encrypts {@code plaintext} and replaces the store file with it atomically.
     *
     * @param plaintext the serialized snapshot
     * @throws WriteFailure with a fixed, path-free reason when the snapshot did not reach the disk
     */
    private void write(String plaintext) throws WriteFailure {
        String name = fileName;
        Path directory;
        try {
            directory = directory();
        } catch (RuntimeException unavailable) {
            throw new WriteFailure("store directory unavailable");
        }
        Path target = directory.resolve(name);
        Path temp = directory.resolve(name + TEMP_SUFFIX);

        try {
            Files.createDirectories(directory);
        } catch (IOException failure) {
            throw new WriteFailure(reason(failure, "store directory could not be created"));
        }
        preserveUnreadable(directory, target, name);

        byte[] sealed;
        try {
            sealed = EncryptionUtil.encrypt(plaintext, sealingKey()).getBytes(StandardCharsets.US_ASCII);
        } catch (GeneralSecurityException failure) {
            throw new WriteFailure("could not be encrypted");
        }

        try {
            writeDurably(temp, sealed);
            if (resealing) {
                // The file being replaced is sealed under the machine key, so it is not kept as the
                // backup, and no older copy is left under that key either. Done before the move: a
                // crash in between leaves the store itself still to migrate, never a migrated store
                // beside a machine-keyed copy of it.
                resealMachineKeyedCopies(directory, name);
            } else if (knownGood && Files.exists(target)) {
                keepBackup(target, directory.resolve(name + BACKUP_SUFFIX));
            }
            moveIntoPlace(temp, target);
        } catch (IOException failure) {
            discard(temp);
            throw new WriteFailure(reason(failure, "could not be written"));
        } catch (WriteFailure failure) {
            discard(temp);
            throw failure;
        }
        syncDirectory(directory);
    }

    /**
     * Copies an unreadable store aside so a write cannot destroy it. Every such file gets a copy under a
     * name of its own, so a second incident never costs the copy made for the first; only a file whose
     * exact bytes are already kept is not copied again. Once more than {@link #MAX_UNREADABLE_KEPT}
     * copies exist the oldest are removed.
     *
     * @param directory the store directory
     * @param target the store file
     * @param name the store file's name
     * @throws WriteFailure when the unreadable file could not be preserved, so the write must not happen
     */
    private void preserveUnreadable(Path directory, Path target, String name) throws WriteFailure {
        if (!unreadableOnDisk || !Files.exists(target)) {
            return;
        }
        List<Path> kept = unreadableCopies(directory, name);
        try {
            for (Path copy : kept) {
                if (Files.mismatch(target, copy) < 0) {
                    return;
                }
            }
            String stem = name + UNREADABLE_SUFFIX + "." + System.currentTimeMillis();
            Path aside = directory.resolve(stem);
            for (int attempt = 1; Files.exists(aside); attempt++) {
                aside = directory.resolve(stem + "-" + attempt);
            }
            Files.copy(target, aside, StandardCopyOption.COPY_ATTRIBUTES);
        } catch (IOException | RuntimeException failure) {
            throw new WriteFailure("unreadable store could not be preserved, so it was not overwritten");
        }
        for (int index = 0; index <= kept.size() - MAX_UNREADABLE_KEPT; index++) {
            discard(kept.get(index));
        }
    }

    /**
     * Writes {@code bytes} to a new file readable by its owner only, and forces them to the device.
     *
     * @param file the file to create
     * @param bytes the content
     * @throws IOException if the file cannot be created or written
     */
    private static void writeDurably(Path file, byte[] bytes) throws IOException {
        Files.deleteIfExists(file);
        if (posix(file)) {
            // Created with the permissions rather than narrowed afterwards, so there is no moment at
            // which the credentials sit in a file another local user could open.
            Files.createFile(file, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        } else {
            Files.createFile(file);
        }
        try (FileChannel channel = FileChannel.open(file, StandardOpenOption.WRITE)) {
            ByteBuffer buffer = ByteBuffer.wrap(bytes);
            while (buffer.hasRemaining()) {
                channel.write(buffer);
            }
            channel.force(true);
        }
    }

    /**
     * Returns whether {@code file}'s filesystem carries POSIX permissions.
     *
     * @param file a path on the filesystem in question
     * @return true when owner-only permissions can be set
     */
    private static boolean posix(Path file) {
        return file.getFileSystem().supportedFileAttributeViews().contains("posix");
    }

    /**
     * Keeps the file about to be replaced as the single rolling backup. Best effort: a backup that
     * cannot be made is not a reason to refuse the write it would have preceded.
     *
     * @param target the current store file
     * @param backup where its copy goes
     */
    private static void keepBackup(Path target, Path backup) {
        try {
            Files.copy(target, backup, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.COPY_ATTRIBUTES);
        } catch (IOException noBackup) {
            // The store itself is still written atomically; only the extra copy is missing.
        }
    }

    /**
     * Moves the staged file over the store in one step, falling back to a plain replace on a filesystem
     * that cannot do it atomically.
     *
     * @param temp the staged file
     * @param target the store file
     * @throws IOException if the move fails
     */
    private static void moveIntoPlace(Path temp, Path target) throws IOException {
        try {
            Files.move(temp, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (AtomicMoveNotSupportedException notAtomicHere) {
            Files.move(temp, target, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    /**
     * Forces the directory entry to disk so the rename itself survives a power loss. Not every platform
     * can open a directory for this, and the write is already complete where it cannot.
     *
     * @param directory the store directory
     */
    private static void syncDirectory(Path directory) {
        try (FileChannel channel = FileChannel.open(directory, StandardOpenOption.READ)) {
            channel.force(true);
        } catch (IOException | RuntimeException unsupported) {
            // Windows refuses to open a directory as a channel; the rename is durable enough there.
        }
    }

    private static void discard(Path temp) {
        try {
            Files.deleteIfExists(temp);
        } catch (IOException leftBehind) {
            // The next write deletes it before staging again.
        }
    }

    /**
     * Returns the key writes are sealed under, deriving it on first use and again only when the password
     * behind it changes. One derivation per process is what keeps PBKDF2 off every save.
     *
     * @return the cached sealing key
     * @throws WriteFailure when the host's key provider cannot supply its key
     * @throws GeneralSecurityException if derivation fails
     */
    private EncryptionUtil.DerivedKey sealingKey() throws WriteFailure, GeneralSecurityException {
        String password = password();
        if (sealingKey == null || !password.equals(sealedUnder)) {
            sealingKey = EncryptionUtil.derive(password);
            sealedUnder = password;
        }
        return sealingKey;
    }

    /**
     * Returns the password the key is derived from: the host's key material when a provider is
     * installed, the machine-derived default otherwise. Never falls back from the first to the second.
     *
     * @return the derivation password
     * @throws WriteFailure when the host's key provider throws or returns too little
     */
    private String password() throws WriteFailure {
        StoreKeyProvider provider = keyProvider;
        if (provider == null) {
            return EncryptionUtil.getHardwareKey(keyBinding);
        }
        if (hostSecret == null) {
            byte[] material;
            try {
                material = provider.keyMaterial();
            } catch (Exception failure) {
                throw new WriteFailure("store key unavailable");
            }
            if (material == null || material.length < StoreKeyProvider.MIN_LENGTH) {
                throw new WriteFailure("store key unavailable");
            }
            hostSecret = Base64.getEncoder().encodeToString(material);
        }
        return "host-key:" + hostSecret + ":" + keyBinding;
    }

    private void forgetKeys() {
        hostSecret = null;
        sealedUnder = null;
        sealingKey = null;
    }

    private Path directory() {
        VaultDirectoryProvider provider = directoryProvider;
        if (provider == null) {
            throw new IllegalStateException("store not bound");
        }
        return Objects.requireNonNull(provider.vaultDirectory(), "vaultDirectory");
    }

    /**
     * Describes an I/O failure without naming a path.
     *
     * @param failure the failure to describe
     * @param fallback the phrase for a failure with no more specific cause
     * @return a short, path-free reason
     */
    private static String reason(IOException failure, String fallback) {
        if (failure instanceof AccessDeniedException) {
            return "access denied";
        }
        if (failure instanceof NoSuchFileException) {
            return "no such file";
        }
        return fallback;
    }

    /** What a load found. */
    enum LoadOutcome {
        /** There is no file; the store has simply never been written. */
        ABSENT,
        /** The file was read into the store. */
        LOADED,
        /** The file was read under the machine-derived key and should be rewritten under the host's. */
        MIGRATED,
        /** The file exists and could not be read; see {@link StoreFile#loadError()}. */
        FAILED
    }

    /** Parses decrypted plaintext into a store. */
    @FunctionalInterface
    interface Installer {

        /**
         * Installs the plaintext into the store.
         *
         * @param plaintext the decrypted file content
         * @throws Exception if the content is not a valid store
         */
        void install(String plaintext) throws Exception;
    }

    /**
     * A snapshot waiting to be written.
     *
     * @param order the position of this snapshot in the sequence of mutations
     * @param plaintext produces the serialized snapshot
     */
    private record Pending(long order, Supplier<String> plaintext) {}

    /** A write that did not reach the disk; the message is a fixed, path-free phrase. */
    private static final class WriteFailure extends Exception {

        private static final long serialVersionUID = 1L;

        WriteFailure(String reason) {
            super(reason);
        }
    }

    /** The background writer, created on the first coalesced write together with its shutdown flush. */
    private static final class Writer {

        static final ScheduledThreadPoolExecutor EXECUTOR = create();

        private Writer() {}

        private static ScheduledThreadPoolExecutor create() {
            ScheduledThreadPoolExecutor executor = new ScheduledThreadPoolExecutor(1, task -> {
                Thread thread = new Thread(task, "alts-store-writer");
                thread.setDaemon(true);
                return thread;
            });
            executor.setKeepAliveTime(30, TimeUnit.SECONDS);
            executor.allowCoreThreadTimeOut(true);
            executor.setRemoveOnCancelPolicy(true);
            try {
                // The writer is a daemon, so without this a snapshot gathered in the last instant before
                // exit would die with it. A host that never calls flush() still loses nothing.
                Runtime.getRuntime().addShutdownHook(new Thread(StoreFile::flushAll, "alts-store-flush"));
            } catch (IllegalStateException alreadyShuttingDown) {
                // Too late to register; the caller's own flush is all that is left.
            }
            return executor;
        }
    }
}
