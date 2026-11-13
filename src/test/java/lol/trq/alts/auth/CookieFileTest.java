package lol.trq.alts.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import lol.trq.alts.AltsException;
import lol.trq.alts.AltsFailure.Kind;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class CookieFileTest {

    private static final String NETSCAPE = ".login.live.com\tTRUE\t/\tTRUE\t0\tMSPOK\tabc123\n";

    @TempDir
    Path dir;

    private Path write(String name, byte[] bytes) throws IOException {
        Path file = dir.resolve(name);
        Files.write(file, bytes);
        return file;
    }

    @Test
    void readsPlainUtf8() throws IOException {
        Path file = write("cookies.txt", NETSCAPE.getBytes(StandardCharsets.UTF_8));

        assertEquals(NETSCAPE, CookieFile.read(file));
    }

    @Test
    void stripsUtf8ByteOrderMark() throws IOException {
        byte[] body = NETSCAPE.getBytes(StandardCharsets.UTF_8);
        byte[] withBom = new byte[body.length + 3];
        withBom[0] = (byte) 0xEF;
        withBom[1] = (byte) 0xBB;
        withBom[2] = (byte) 0xBF;
        System.arraycopy(body, 0, withBom, 3, body.length);

        String read = CookieFile.read(write("bom.txt", withBom));

        assertEquals(NETSCAPE, read);
        assertFalse(read.startsWith("﻿"), "byte-order mark must not survive into the parsed text");
    }

    @Test
    void decodesUtf16AsWrittenByPowerShellRedirection() throws IOException {
        // A UTF-16LE export decoded as UTF-8 keeps every character but interleaves NULs, so assert the
        // decoded text equals the original rather than merely containing the cookie name.
        byte[] utf16 = NETSCAPE.getBytes(StandardCharsets.UTF_16LE);
        byte[] withBom = new byte[utf16.length + 2];
        withBom[0] = (byte) 0xFF;
        withBom[1] = (byte) 0xFE;
        System.arraycopy(utf16, 0, withBom, 2, utf16.length);

        String read = CookieFile.read(write("utf16.txt", withBom));

        assertEquals(NETSCAPE, read);
        assertFalse(read.contains("\0"), "UTF-16 must not be decoded as UTF-8");
    }

    @Test
    void decodesBigEndianUtf16() throws IOException {
        byte[] utf16 = NETSCAPE.getBytes(StandardCharsets.UTF_16BE);
        byte[] withBom = new byte[utf16.length + 2];
        withBom[0] = (byte) 0xFE;
        withBom[1] = (byte) 0xFF;
        System.arraycopy(utf16, 0, withBom, 2, utf16.length);

        assertEquals(NETSCAPE, CookieFile.read(write("utf16be.txt", withBom)));
    }

    @Test
    void rejectsMissingFile() {
        AltsException thrown = assertThrows(AltsException.class, () -> CookieFile.read(dir.resolve("absent.txt")));
        assertEquals(Kind.INVALID_INPUT, thrown.kind());
    }

    @Test
    void rejectsDirectory() {
        assertEquals(
                Kind.INVALID_INPUT,
                assertThrows(AltsException.class, () -> CookieFile.read(dir)).kind());
    }

    @Test
    void rejectsBlankFile() throws IOException {
        Path file = write("blank.txt", "   \n\t\n".getBytes(StandardCharsets.UTF_8));

        assertEquals(
                Kind.INVALID_INPUT,
                assertThrows(AltsException.class, () -> CookieFile.read(file)).kind());
    }

    @Test
    void rejectsOversizedFile() throws IOException {
        Path file = write("huge.txt", new byte[(int) CookieFile.MAX_BYTES + 1]);

        AltsException thrown = assertThrows(AltsException.class, () -> CookieFile.read(file));
        assertEquals(Kind.INVALID_INPUT, thrown.kind());
    }

    /**
     * The cap has to bind the read, not a stat taken before it. Reading a huge file to find out it was
     * huge is the thing the cap exists to prevent, and a file that grew between the two would slip it.
     */
    @Test
    void readsNoMoreThanOneByteBeyondTheCap() throws IOException {
        Path file = write("huge.txt", new byte[(int) CookieFile.MAX_BYTES * 2]);

        AltsException thrown = assertThrows(AltsException.class, () -> CookieFile.read(file));
        assertEquals(Kind.INVALID_INPUT, thrown.kind());
    }

    /**
     * Every failure message reaches a {@code LoginResult} that a host shows in its UI and writes to its
     * log. The JDK's own I/O messages are the absolute path, so an unreadable file under a home directory
     * would publish that directory unless the message is rebuilt from the file name alone.
     */
    @Test
    void aFailureNamesTheFileAndNeverThePathToIt() {
        Path absent = dir.resolve("absent.txt");

        AltsException thrown = assertThrows(AltsException.class, () -> CookieFile.read(absent));
        assertEquals(Kind.INVALID_INPUT, thrown.kind());

        assertFalse(
                thrown.getMessage().contains(dir.toString()),
                "the containing directory must not travel into a message: " + thrown.getMessage());
    }

    @Test
    void aDirectoryIsRejectedAsNotAFileRatherThanAsMissing() {
        AltsException thrown = assertThrows(AltsException.class, () -> CookieFile.read(dir));
        assertEquals(Kind.INVALID_INPUT, thrown.kind());
    }

    @Test
    void theAdvertisedExtensionsCoverWhatExportersActuallyWrite() {
        assertTrue(CookieFile.EXTENSIONS.contains("txt"), "the Netscape export");
        assertTrue(CookieFile.EXTENSIONS.contains("json"), "the cookie-editor export");
        assertFalse(CookieFile.EXTENSIONS.isEmpty());
    }
}
