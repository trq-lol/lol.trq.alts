package lol.trq.alts.skin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.zip.CRC32;
import javax.imageio.ImageIO;
import org.junit.jupiter.api.Test;

/**
 * The parts of the default avatar source that handle data it did not choose: the texture URL a profile
 * names, and the image behind it. What these defend is that the URL can only ever be Mojang's texture
 * host over TLS, and that an image declaring an enormous canvas is turned away from its header, before
 * any pixel buffer is allocated for it.
 */
class MojangAvatarSourceTest {

    private static final String TEXTURE_PATH = "/texture/0123456789abcdef";

    @Test
    void aPlainHttpTextureUrlIsUpgradedToHttps() {
        assertEquals(
                "https://textures.minecraft.net" + TEXTURE_PATH,
                MojangAvatarSource.trustedTextureUrl("http://textures.minecraft.net" + TEXTURE_PATH));
        assertEquals(
                "https://textures.minecraft.net" + TEXTURE_PATH,
                MojangAvatarSource.trustedTextureUrl("https://textures.minecraft.net" + TEXTURE_PATH));
        assertEquals(
                "https://textures.minecraft.net" + TEXTURE_PATH,
                MojangAvatarSource.trustedTextureUrl("HTTP://Textures.Minecraft.Net" + TEXTURE_PATH));
    }

    @Test
    void aTextureUrlOnAnyOtherHostIsRefused() {
        assertNull(MojangAvatarSource.trustedTextureUrl(null));
        assertNull(MojangAvatarSource.trustedTextureUrl("http://textures.example.net" + TEXTURE_PATH));
        assertNull(MojangAvatarSource.trustedTextureUrl("http://127.0.0.1" + TEXTURE_PATH));
        assertNull(
                MojangAvatarSource.trustedTextureUrl("http://textures.minecraft.net.example.net" + TEXTURE_PATH),
                "a host that merely starts with the real one is another host");
        assertNull(
                MojangAvatarSource.trustedTextureUrl("http://textures.minecraft.net@example.net" + TEXTURE_PATH),
                "user-info must not disguise the real host");
        assertNull(
                MojangAvatarSource.trustedTextureUrl("http://example.net@textures.minecraft.net" + TEXTURE_PATH),
                "nor is user-info accepted on the real one");
        assertNull(MojangAvatarSource.trustedTextureUrl("http://textures.minecraft.net:8080" + TEXTURE_PATH));
        assertNull(MojangAvatarSource.trustedTextureUrl("ftp://textures.minecraft.net" + TEXTURE_PATH));
        assertNull(MojangAvatarSource.trustedTextureUrl("file:///etc/hostname"));
        assertNull(MojangAvatarSource.trustedTextureUrl("//textures.minecraft.net" + TEXTURE_PATH));
        assertNull(MojangAvatarSource.trustedTextureUrl("http://textures.minecraft.net"));
        assertNull(MojangAvatarSource.trustedTextureUrl("not a url"));
    }

    @Test
    void aRealSkinDecodesAndCropsToTheRequestedSize() throws Exception {
        byte[] skin = png(64, 64);

        assertNotNull(MojangAvatarSource.decodeSkin(skin));
        BufferedImage face = MojangAvatarSource.cropFace(skin, 32);

        assertNotNull(face);
        assertEquals(32, face.getWidth());
        assertEquals(32, face.getHeight());
        assertNotNull(MojangAvatarSource.cropFace(png(64, 32), 8), "the legacy 64x32 layout still has a face");
        assertNotNull(MojangAvatarSource.decodeSkin(png(128, 128)), "a double-resolution skin is within the bound");
    }

    /**
     * The regression this guards: a few dozen bytes declaring a 30000x30000 canvas used to reach the
     * decoder, which tried to allocate gigabytes for it.
     */
    @Test
    void anImageDeclaringAHugeCanvasIsRejectedFromItsHeader() throws Exception {
        byte[] bomb = pngDeclaring(30_000, 30_000);
        assertTrue(bomb.length < 200, "the hostile image is tiny on the wire");

        assertNull(MojangAvatarSource.decodeSkin(bomb), "the declared size is checked before decoding");
        assertNull(MojangAvatarSource.cropFace(bomb, 64));
        assertNull(MojangAvatarSource.decodeSkin(pngDeclaring(129, 64)), "one side over the bound is enough");
        assertNull(MojangAvatarSource.decodeSkin(pngDeclaring(64, 4096)));
    }

    @Test
    void bytesThatAreNotAnImageYieldNoFace() {
        assertNull(MojangAvatarSource.decodeSkin(new byte[] {1, 2, 3, 4}));
        assertNull(MojangAvatarSource.decodeSkin(new byte[0]));
        assertNull(MojangAvatarSource.cropFace("<html>blocked</html>".getBytes(StandardCharsets.UTF_8), 64));
    }

    private static byte[] png(int width, int height) throws IOException {
        BufferedImage image = new BufferedImage(width, height, BufferedImage.TYPE_INT_ARGB);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ImageIO.write(image, "png", out);
        return out.toByteArray();
    }

    /** A structurally valid PNG whose header declares the given size, with no meaningful pixel data behind it. */
    private static byte[] pngDeclaring(int width, int height) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(new byte[] {(byte) 0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'});
        ByteArrayOutputStream header = new ByteArrayOutputStream();
        DataOutputStream fields = new DataOutputStream(header);
        fields.writeInt(width);
        fields.writeInt(height);
        fields.writeByte(8); // bit depth
        fields.writeByte(6); // RGBA
        fields.writeByte(0);
        fields.writeByte(0);
        fields.writeByte(0);
        chunk(out, "IHDR", header.toByteArray());
        // An empty zlib stream: valid framing, no pixels.
        chunk(out, "IDAT", new byte[] {0x78, (byte) 0x9c, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01});
        chunk(out, "IEND", new byte[0]);
        return out.toByteArray();
    }

    private static void chunk(ByteArrayOutputStream out, String type, byte[] data) throws IOException {
        byte[] name = type.getBytes(StandardCharsets.US_ASCII);
        CRC32 crc = new CRC32();
        crc.update(name);
        crc.update(data);
        DataOutputStream stream = new DataOutputStream(out);
        stream.writeInt(data.length);
        stream.write(name);
        stream.write(data);
        stream.writeInt((int) crc.getValue());
    }
}
