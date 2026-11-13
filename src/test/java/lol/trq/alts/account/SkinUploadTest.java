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

    private SkinValidationException.Reason refusal(byte[] bytes) {
        SkinValidationException thrown = assertThrows(
                SkinValidationException.class, () -> server.services().skin().upload(bytes, SkinModel.CLASSIC));
        assertEquals(0, thrown.status(), "a local refusal carries no HTTP status");
        return thrown.reason();
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
        assertEquals(SkinValidationException.Reason.EMPTY, refusal(null));
        assertEquals(SkinValidationException.Reason.EMPTY, refusal(new byte[0]));
        assertEquals(SkinValidationException.Reason.NOT_PNG, refusal(new byte[] {1, 2, 3}));
        assertEquals(
                SkinValidationException.Reason.NOT_PNG,
                refusal("<html>definitely not an image, but long enough to hold a header</html>"
                        .getBytes(StandardCharsets.UTF_8)));
        byte[] jpegish = new byte[64];
        jpegish[0] = (byte) 0xff;
        jpegish[1] = (byte) 0xd8;
        assertEquals(SkinValidationException.Reason.NOT_PNG, refusal(jpegish));
        byte[] truncated = new byte[20];
        System.arraycopy(png(64, 64), 0, truncated, 0, 20);
        assertEquals(SkinValidationException.Reason.NOT_PNG, refusal(truncated), "a header cut short is not a PNG");

        assertEquals(SkinValidationException.Reason.WRONG_DIMENSIONS, refusal(png(128, 128)));
        assertEquals(SkinValidationException.Reason.WRONG_DIMENSIONS, refusal(png(64, 48)));
        assertEquals(SkinValidationException.Reason.WRONG_DIMENSIONS, refusal(png(32, 64)));
        assertEquals(SkinValidationException.Reason.WRONG_DIMENSIONS, refusal(png(16, 16)));

        byte[] oversized = new byte[SkinService.MAX_SKIN_BYTES + 1];
        System.arraycopy(png(64, 64), 0, oversized, 0, 24);
        assertEquals(SkinValidationException.Reason.TOO_LARGE, refusal(oversized));

        assertTrue(server.requests().isEmpty(), "nothing invalid reached the service");
    }

    @Test
    void aValidationFailureIsStillAnAccountException() {
        AccountException thrown = assertThrows(
                AccountException.class, () -> server.services().skin().upload(new byte[] {9}, SkinModel.CLASSIC));

        assertTrue(thrown instanceof SkinValidationException, "an existing catch block still sees it");
        assertFalse(thrown.tokenRefused());
        assertFalse(thrown.rateLimited());
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
        SkinValidationException gone =
                assertThrows(SkinValidationException.class, () -> skin.upload(missing, SkinModel.CLASSIC));
        SkinValidationException folder =
                assertThrows(SkinValidationException.class, () -> skin.upload(directory, SkinModel.CLASSIC));
        SkinValidationException text =
                assertThrows(SkinValidationException.class, () -> skin.upload(notASkin, SkinModel.CLASSIC));
        SkinValidationException big =
                assertThrows(SkinValidationException.class, () -> skin.upload(wrongSize, SkinModel.CLASSIC));
        SkinValidationException tooLarge =
                assertThrows(SkinValidationException.class, () -> skin.upload(huge, SkinModel.CLASSIC));
        SkinValidationException none =
                assertThrows(SkinValidationException.class, () -> skin.upload((Path) null, SkinModel.CLASSIC));

        assertEquals(SkinValidationException.Reason.UNREADABLE, gone.reason());
        assertEquals(SkinValidationException.Reason.UNREADABLE, folder.reason());
        assertEquals(SkinValidationException.Reason.NOT_PNG, text.reason());
        assertEquals(SkinValidationException.Reason.WRONG_DIMENSIONS, big.reason());
        assertEquals(SkinValidationException.Reason.TOO_LARGE, tooLarge.reason());
        assertEquals(SkinValidationException.Reason.UNREADABLE, none.reason());

        String root = directory.toAbsolutePath().toString();
        for (SkinValidationException failure : new SkinValidationException[] {gone, folder, text, big, tooLarge}) {
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
    void aServiceRefusalOfAnUploadCarriesItsStatus() throws Exception {
        byte[] skin = png(64, 64);

        server.canned(401, "{\"errorMessage\":\"Invalid token\"}");
        assertTrue(assertThrows(
                        AccountException.class, () -> server.services().skin().upload(skin, SkinModel.CLASSIC))
                .tokenRefused());

        server.rateLimited(4);
        assertTrue(assertThrows(
                        AccountException.class, () -> server.services().skin().upload(skin, SkinModel.CLASSIC))
                .rateLimited());

        server.canned(400, "{\"errorMessage\":\"Could not validate image data.\"}");
        AccountException rejected = assertThrows(
                AccountException.class, () -> server.services().skin().upload(skin, SkinModel.CLASSIC));
        assertEquals(400, rejected.status());
        assertFalse(rejected instanceof SkinValidationException, "a service rejection is not a local one");
    }
}
