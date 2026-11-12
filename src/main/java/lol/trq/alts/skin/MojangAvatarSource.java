package lol.trq.alts.skin;

import com.google.gson.JsonObject;
import java.awt.Graphics2D;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Iterator;
import javax.imageio.ImageIO;
import javax.imageio.ImageReader;
import javax.imageio.stream.ImageInputStream;
import lol.trq.alts.net.HttpUtil;
import lol.trq.alts.net.NetworkScope;
import lol.trq.alts.spi.AvatarSource;

/**
 * The default {@link AvatarSource}: resolve the skin from Mojang's session server and crop the face
 * locally, so a player's identity is disclosed to no party the host was not already talking to.
 *
 * <p>The alternative a library reaches for — a third-party head-render URL keyed by name or UUID —
 * hands that service the identity of every account on every cache miss. For an alt manager that is not
 * one name; it is the whole list one person controls, arriving from one address. Mojang already knows
 * these accounts, since the host authenticated them through it, so sourcing the skin here removes a
 * trust relationship rather than adding one.
 *
 * <p>The face is the 8×8 head region with the hat overlay composited on top, matching what a head-render
 * service would return. A skin that cannot be read, or a profile with none, yields {@code null} and the
 * cache falls back to whatever the host draws for a missing head.
 *
 * <p>The texture URL comes out of a profile property, and the profile names it over plain HTTP, so
 * neither the URL nor the bytes behind it are trusted. The URL must point at Mojang's texture host and is
 * fetched over HTTPS whatever scheme it was given with; the image's declared dimensions are read from
 * its header and checked against the size of a skin before a single pixel is decoded, because a
 * kilobyte of PNG can declare a canvas that takes gigabytes to allocate.
 *
 * @author trq
 * @since 0.10.0
 */
public final class MojangAvatarSource implements AvatarSource {

    private static final String PROFILE_URL = "https://sessionserver.mojang.com/session/minecraft/profile/";
    private static final String TEXTURES_PROPERTY = "textures";

    /** The head occupies an 8×8 block at (8,8) on a 64-wide skin, and the hat an 8×8 block at (40,8). */
    private static final int FACE_X = 8;

    private static final int FACE_Y = 8;
    private static final int HAT_X = 40;
    private static final int FACE_SIZE = 8;

    /** Cap on a downloaded skin PNG. A vanilla skin is a couple of kilobytes; this is far past any real one. */
    private static final long MAX_SKIN_BYTES = 1L << 20;

    /** The only host a skin texture is fetched from. */
    private static final String TEXTURE_HOST = "textures.minecraft.net";

    /**
     * Creates the source. It holds no state; one instance serves every lookup.
     *
     * @since 0.10.0
     */
    public MojangAvatarSource() {}

    /**
     * The largest canvas accepted, per side. A skin is 64x64 (64x32 for the legacy layout); this leaves
     * room for a double-resolution one and nothing more.
     */
    private static final int MAX_SKIN_DIMENSION = 128;

    @Override
    public byte[] avatarPng(String uuid, int sizePx) throws Exception {
        String skinUrl = trustedTextureUrl(skinUrl(uuid));
        if (skinUrl == null) {
            return null;
        }
        byte[] skinBytes = HttpUtil.getBytes(
                skinUrl, null, MAX_SKIN_BYTES, NetworkScope.forAccount(NetworkScope.Purpose.AVATAR, uuid, null));
        if (skinBytes == null) {
            return null;
        }
        BufferedImage face = cropFace(skinBytes, Math.max(sizePx, FACE_SIZE));
        return face == null ? null : encode(face);
    }

    /**
     * Reads the profile's {@code textures} property and pulls the skin URL out of it.
     *
     * @param uuid the player UUID
     * @return the skin PNG URL, or {@code null} when the profile has no skin
     * @throws Exception if the profile lookup fails
     */
    private static String skinUrl(String uuid) throws Exception {
        String cleanUuid = uuid.replace("-", "");
        JsonObject profile = HttpUtil.get(
                PROFILE_URL + cleanUuid, null, NetworkScope.forAccount(NetworkScope.Purpose.AVATAR, uuid, null));
        if (profile == null || !profile.has("properties")) {
            return null;
        }
        for (var element : profile.getAsJsonArray("properties")) {
            JsonObject property = element.getAsJsonObject();
            if (!TEXTURES_PROPERTY.equals(property.get("name").getAsString())) {
                continue;
            }
            String decoded =
                    new String(Base64.getDecoder().decode(property.get("value").getAsString()), StandardCharsets.UTF_8);
            JsonObject textures = com.google.gson.JsonParser.parseString(decoded)
                    .getAsJsonObject()
                    .getAsJsonObject("textures");
            if (textures == null || !textures.has("SKIN")) {
                return null;
            }
            return textures.getAsJsonObject("SKIN").get("url").getAsString();
        }
        return null;
    }

    /**
     * Admits a texture URL only if it points at Mojang's texture host, and returns it as an HTTPS URL.
     *
     * <p>The profile hands the URL out with an {@code http} scheme. Fetched that way, anyone on the path
     * chooses the bytes; the same host serves the same path over TLS, so the scheme is upgraded rather
     * than trusted. A URL naming any other host, carrying user-info or a port, or using another scheme is
     * refused outright: the property is data from a response, not an address the host chose to contact.
     *
     * @param url the texture URL from the profile, or null
     * @return the HTTPS form of the URL, or {@code null} when it is not an acceptable texture address
     */
    static String trustedTextureUrl(String url) {
        if (url == null) {
            return null;
        }
        URI uri;
        try {
            uri = URI.create(url.trim());
        } catch (IllegalArgumentException malformed) {
            return null;
        }
        String scheme = uri.getScheme();
        if (scheme == null || !(scheme.equalsIgnoreCase("http") || scheme.equalsIgnoreCase("https"))) {
            return null;
        }
        if (!TEXTURE_HOST.equalsIgnoreCase(uri.getHost()) || uri.getRawUserInfo() != null || uri.getPort() != -1) {
            return null;
        }
        String path = uri.getRawPath();
        if (path == null || path.isEmpty() || uri.getRawQuery() != null || uri.getRawFragment() != null) {
            return null;
        }
        return "https://" + TEXTURE_HOST + path;
    }

    /**
     * Decodes a skin, refusing one whose header declares a canvas larger than a skin can be. The
     * dimensions are read from the header alone, so an image built to exhaust memory on decode is
     * turned away before anything is allocated for its pixels.
     *
     * @param skinBytes the raw skin image
     * @return the decoded skin, or {@code null} when it is unreadable or oversized
     */
    static BufferedImage decodeSkin(byte[] skinBytes) {
        try (ImageInputStream input = ImageIO.createImageInputStream(new ByteArrayInputStream(skinBytes))) {
            if (input == null) {
                return null;
            }
            Iterator<ImageReader> readers = ImageIO.getImageReaders(input);
            if (!readers.hasNext()) {
                return null;
            }
            ImageReader reader = readers.next();
            try {
                reader.setInput(input, true, true);
                int width = reader.getWidth(0);
                int height = reader.getHeight(0);
                if (width < 1 || height < 1 || width > MAX_SKIN_DIMENSION || height > MAX_SKIN_DIMENSION) {
                    return null;
                }
                return reader.read(0);
            } finally {
                reader.dispose();
            }
        } catch (Exception | OutOfMemoryError | StackOverflowError unreadable) {
            // The size check bounds the decode, so an Error here would mean a decoder fault rather than
            // an oversized canvas; either way an undecodable skin is a missing head, not a crash.
            return null;
        }
    }

    /**
     * Crops the face out of a skin, composites the hat over it, and scales to the requested size.
     *
     * @param skinBytes the raw skin PNG
     * @param sizePx the target face size
     * @return the face image, or {@code null} when the skin could not be decoded
     */
    static BufferedImage cropFace(byte[] skinBytes, int sizePx) {
        BufferedImage skin = decodeSkin(skinBytes);
        if (skin == null || skin.getWidth() < HAT_X + FACE_SIZE || skin.getHeight() < FACE_Y + FACE_SIZE) {
            return null;
        }

        BufferedImage base = skin.getSubimage(FACE_X, FACE_Y, FACE_SIZE, FACE_SIZE);
        BufferedImage composed = new BufferedImage(FACE_SIZE, FACE_SIZE, BufferedImage.TYPE_INT_ARGB);
        Graphics2D g = composed.createGraphics();
        try {
            g.drawImage(base, 0, 0, null);
            // The hat layer is transparent where the player has no hat, so it composites to a no-op there
            // and to the overlay where they do.
            g.drawImage(skin.getSubimage(HAT_X, FACE_Y, FACE_SIZE, FACE_SIZE), 0, 0, null);
        } finally {
            g.dispose();
        }

        if (sizePx == FACE_SIZE) {
            return composed;
        }
        BufferedImage scaled = new BufferedImage(sizePx, sizePx, BufferedImage.TYPE_INT_ARGB);
        Graphics2D scaleG = scaled.createGraphics();
        try {
            // Nearest-neighbour: a face is pixel art, and smoothing it turns crisp blocks to mush.
            scaleG.setRenderingHint(
                    java.awt.RenderingHints.KEY_INTERPOLATION,
                    java.awt.RenderingHints.VALUE_INTERPOLATION_NEAREST_NEIGHBOR);
            scaleG.drawImage(composed, 0, 0, sizePx, sizePx, null);
        } finally {
            scaleG.dispose();
        }
        return scaled;
    }

    private static byte[] encode(BufferedImage image) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ImageIO.write(image, "png", out);
        return out.toByteArray();
    }
}
