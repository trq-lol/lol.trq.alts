package lol.trq.alts.account;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import javax.imageio.ImageIO;
import lol.trq.alts.AltsException;
import lol.trq.alts.AltsFailure.Kind;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Skin uploads. What these defend: a file that is not a skin is refused before a request is spent on it,
 * with a reason a host can branch on, and no failure names a path on the user's disk.
 */
class SkinUploadTest {

    private static final String PROFILE = "{\"id\":\"abc\",\"name\":\"Alex\",\"skins\":[],\"capes\":[]}";

    @TempDir
    Path directory;

    private LoopbackServices server;

    @BeforeEach
    void setUp() throws IOException {
        server = new LoopbackServices();
        server.canned(200, PROFILE);
    }

    @AfterEach
    void tearDown() {
        server.close();
    }

    static byte[] png(int width, int height) throws IOException {
        BufferedImage image = new BufferedImage(width, height, BufferedImage.TYPE_INT_ARGB);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ImageIO.write(image, "png", out);
        return out.toByteArray();
    }

    /**
     * Asserts an upload of {@code bytes} is refused locally as {@link Kind#INVALID_INPUT}, and returns the
     * problem {@link SkinService#validate(byte[])} names for the same bytes.
     */
    private SkinProblem refusal(byte[] bytes) {
        AltsException thrown =
                assertThrows(AltsException.class, () -> server.services().skin().upload(bytes, SkinModel.CLASSIC));
        assertEquals(Kind.INVALID_INPUT, thrown.kind(), "a local refusal is invalid input");
        return server.services().skin().validate(bytes).orElseThrow();
    }

    @Test
    void aValidSkinIsUploadedAsMultipartAndReturnsTheProfile() throws Exception {
        byte[] skin = png(64, 64);

        PlayerProfile profile = server.services().skin().upload(skin, SkinModel.SLIM);

        assertEquals("Alex", profile.name());
        LoopbackServices.Request request = server.last();
        assertEquals("POST", request.method());
        assertEquals("/minecraft/profile/skins", request.rawPath());
        assertTrue(request.contentType().startsWith("multipart/form-data; boundary="));
        String body = new String(request.body(), StandardCharsets.ISO_8859_1);
        assertTrue(body.contains("name=\"variant\"\r\n\r\nslim\r\n"), "the model travels as the variant field");
        assertTrue(body.contains("filename=\"skin.png\""));
        assertTrue(body.contains(new String(skin, StandardCharsets.ISO_8859_1)), "the PNG travels unmodified");
    }

    @Test
    void theLegacyLayoutIsAccepted() throws Exception {
        server.services().skin().upload(png(64, 32), SkinModel.CLASSIC);

        assertEquals(1, server.requests().size());
    }

    @Test
    void bytesThatAreNotASkinAreRefusedBeforeAnyRequest() throws Exception {
        assertEquals(SkinProblem.EMPTY, refusal(null));
        assertEquals(SkinProblem.EMPTY, refusal(new byte[0]));
        assertEquals(SkinProblem.NOT_PNG, refusal(new byte[] {1, 2, 3}));
        assertEquals(
                SkinProblem.NOT_PNG,
                refusal("<html>definitely not an image, but long enough to hold a header</html>"
                        .getBytes(StandardCharsets.UTF_8)));
        byte[] jpegish = new byte[64];
        jpegish[0] = (byte) 0xff;
        jpegish[1] = (byte) 0xd8;
        assertEquals(SkinProblem.NOT_PNG, refusal(jpegish));
        byte[] truncated = new byte[20];
        System.arraycopy(png(64, 64), 0, truncated, 0, 20);
        assertEquals(SkinProblem.NOT_PNG, refusal(truncated), "a header cut short is not a PNG");

        assertEquals(SkinProblem.WRONG_DIMENSIONS, refusal(png(128, 128)));
        assertEquals(SkinProblem.WRONG_DIMENSIONS, refusal(png(64, 48)));
        assertEquals(SkinProblem.WRONG_DIMENSIONS, refusal(png(32, 64)));
        assertEquals(SkinProblem.WRONG_DIMENSIONS, refusal(png(16, 16)));

        byte[] oversized = new byte[SkinService.MAX_SKIN_BYTES + 1];
        System.arraycopy(png(64, 64), 0, oversized, 0, 24);
        assertEquals(SkinProblem.TOO_LARGE, refusal(oversized));

        assertTrue(server.requests().isEmpty(), "nothing invalid reached the service");
    }

    @Test
    void validateSaysWhyWithoutSendingAnything() throws Exception {
        SkinService skin = server.services().skin();

        assertEquals(java.util.Optional.empty(), skin.validate(png(64, 64)));
        assertEquals(java.util.Optional.empty(), skin.validate(png(64, 32)), "the legacy canvas is a skin too");
        assertEquals(java.util.Optional.of(SkinProblem.EMPTY), skin.validate(null));
        assertEquals(java.util.Optional.of(SkinProblem.NOT_PNG), skin.validate(new byte[] {9}));
        assertEquals(
                java.util.Optional.of(SkinProblem.TOO_LARGE), skin.validate(new byte[SkinService.MAX_SKIN_BYTES + 1]));
        assertTrue(server.requests().isEmpty(), "validating sends nothing");
    }

    @Test
    void aSkinFileIsReadAndUploaded() throws Exception {
        Path file = directory.resolve("my-skin.png");
        Files.write(file, png(64, 64));

        PlayerProfile profile = server.services().skin().upload(file, SkinModel.CLASSIC);

        assertEquals("Alex", profile.name());
        String body = new String(server.last().body(), StandardCharsets.ISO_8859_1);
        assertTrue(body.contains("filename=\"skin.png\""), "the local file name is not sent either");
        assertFalse(body.contains("my-skin"));
    }

    @Test
    void noFileFailureLeaksThePath() throws Exception {
        Path missing = directory.resolve("secret-folder-name").resolve("missing.png");
        Path notASkin = directory.resolve("notes.txt");
        Files.writeString(notASkin, "these are not the pixels you are looking for");
        Path wrongSize = directory.resolve("big.png");
        Files.write(wrongSize, png(256, 256));
        Path huge = directory.resolve("huge.png");
        Files.write(huge, new byte[SkinService.MAX_SKIN_BYTES + 1]);

        SkinService skin = server.services().skin();
        AltsException gone = assertThrows(AltsException.class, () -> skin.upload(missing, SkinModel.CLASSIC));
        AltsException folder = assertThrows(AltsException.class, () -> skin.upload(directory, SkinModel.CLASSIC));
        AltsException text = assertThrows(AltsException.class, () -> skin.upload(notASkin, SkinModel.CLASSIC));
        AltsException big = assertThrows(AltsException.class, () -> skin.upload(wrongSize, SkinModel.CLASSIC));
        AltsException tooLarge = assertThrows(AltsException.class, () -> skin.upload(huge, SkinModel.CLASSIC));
        AltsException none = assertThrows(AltsException.class, () -> skin.upload((Path) null, SkinModel.CLASSIC));

        for (AltsException failure : new AltsException[] {gone, folder, text, big, tooLarge, none}) {
            assertEquals(Kind.INVALID_INPUT, failure.kind());
        }
        assertEquals(
                SkinProblem.NOT_PNG, skin.validate(Files.readAllBytes(notASkin)).orElseThrow());
        assertEquals(
                SkinProblem.WRONG_DIMENSIONS,
                skin.validate(Files.readAllBytes(wrongSize)).orElseThrow());
        assertEquals(
                SkinProblem.TOO_LARGE, skin.validate(Files.readAllBytes(huge)).orElseThrow());

        String root = directory.toAbsolutePath().toString();
        for (AltsException failure : new AltsException[] {gone, folder, text, big, tooLarge}) {
            String everything = failure.getMessage() + " " + failure + " " + failure.getCause();
            assertFalse(everything.contains(root), "the absolute path leaked: " + everything);
            assertFalse(everything.contains("secret-folder-name"), "a path segment leaked: " + everything);
            assertFalse(everything.contains("missing.png"), "the file name leaked: " + everything);
            assertFalse(everything.contains("notes.txt"), "the file name leaked: " + everything);
            assertNull(failure.getCause(), "no file-system exception rides along carrying the path");
        }
        assertTrue(server.requests().isEmpty());
    }

    @Test
    void aServiceRefusalOfAnUploadCarriesItsKind() throws Exception {
        byte[] skin = png(64, 64);

        server.canned(401, "{\"errorMessage\":\"Invalid token\"}");
        assertEquals(
                Kind.UNAUTHORIZED,
                assertThrows(AltsException.class, () -> server.services().skin().upload(skin, SkinModel.CLASSIC))
                        .kind());

        server.rateLimited(4);
        assertEquals(
                Kind.RATE_LIMITED,
                assertThrows(AltsException.class, () -> server.services().skin().upload(skin, SkinModel.CLASSIC))
                        .kind());

        server.canned(400, "{\"errorMessage\":\"Could not validate image data.\"}");
        AltsException rejected =
                assertThrows(AltsException.class, () -> server.services().skin().upload(skin, SkinModel.CLASSIC));
        assertEquals(Kind.INVALID_INPUT, rejected.kind(), "the service refused the input");
        assertEquals(3, server.requests().size(), "each of these refusals came from the service");
    }
}
