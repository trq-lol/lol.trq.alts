package lol.trq.alts.account;

import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import javax.imageio.ImageIO;
import lol.trq.alts.net.HttpUtil;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * The multipart boundary of a skin upload. A constant boundary is a string a crafted file can contain,
 * ending its own part early and appending fields of its choosing; a random one per request is not.
 */
class SkinUploadBoundaryTest {

    private static final String PROFILE = "{\"id\":\"abc\",\"name\":\"Alex\",\"skins\":[],\"capes\":[]}";

    private LoopbackServices server;

    @BeforeEach
    void setUp() throws IOException {
        HttpUtil.resetForTests();
        server = new LoopbackServices();
        server.canned(200, PROFILE);
    }

    @AfterEach
    void tearDown() {
        server.close();
    }

    private static byte[] png(int width, int height) throws IOException {
        BufferedImage image = new BufferedImage(width, height, BufferedImage.TYPE_INT_ARGB);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ImageIO.write(image, "png", out);
        return out.toByteArray();
    }

    @Test
    void theMultipartBoundaryIsFreshForEveryRequest() throws Exception {
        byte[] skin = png(64, 64);

        server.services().skin().upload(skin, SkinModel.CLASSIC);
        String first = server.last().contentType();
        server.services().skin().upload(skin, SkinModel.CLASSIC);
        String second = server.last().contentType();

        assertNotEquals(first, second, "a constant boundary is one a crafted file could contain");
        String boundary = first.substring(first.indexOf("boundary=") + "boundary=".length());
        assertTrue(boundary.length() >= 32, "the boundary carries real randomness: " + boundary);
        String body = new String(server.requests().get(0).body(), StandardCharsets.ISO_8859_1);
        assertTrue(body.endsWith("--" + boundary + "--\r\n"), "the body is framed with the declared boundary");
    }
}
