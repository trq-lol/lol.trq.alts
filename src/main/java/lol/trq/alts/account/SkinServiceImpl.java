package lol.trq.alts.account;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.Optional;
import lol.trq.alts.AltsException;
import lol.trq.alts.AltsFailure.Kind;
import lol.trq.alts.internal.net.Multipart;
import lol.trq.alts.net.NetworkScope;

/**
 * Concrete {@link SkinService}: a JSON POST for a URL skin, a multipart POST for an uploaded one, a
 * DELETE to reset.
 *
 * @author trq
 * @since 1.0.0
 */
final class SkinServiceImpl implements SkinService {

    private static final SecureRandom BOUNDARIES = new SecureRandom();

    /** The eight bytes every PNG begins with. */
    private static final byte[] PNG_SIGNATURE = {(byte) 0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'};

    /** Signature, then the IHDR chunk's length and type, then its width and height. */
    private static final int PNG_HEADER_LENGTH = 24;

    private static final int SKIN_WIDTH = 64;
    private static final int SKIN_HEIGHT = 64;
    private static final int LEGACY_SKIN_HEIGHT = 32;

    private final AccountHttp http;
    private final AccountEndpoints endpoints;
    private final Gson gson;

    SkinServiceImpl(AccountHttp http, AccountEndpoints endpoints, Gson gson) {
        this.http = http;
        this.endpoints = endpoints;
        this.gson = gson;
    }

    @Override
    public Optional<SkinProblem> validate(byte[] pngBytes) {
        return problemWith(pngBytes);
    }

    @Override
    public PlayerProfile setFromUrl(String url, SkinModel model) {
        JsonObject request = new JsonObject();
        request.addProperty("variant", (model == null ? SkinModel.CLASSIC : model).apiVariant());
        request.addProperty("url", url);
        JsonObject response =
                http.sendJson("POST", endpoints.skins(), request.toString(), NetworkScope.Purpose.PROFILE);
        return AccountHttp.decode(gson, response, PlayerProfile.class);
    }

    @Override
    public PlayerProfile upload(byte[] pngBytes, SkinModel model) {
        Optional<SkinProblem> problem = problemWith(pngBytes);
        if (problem.isPresent()) {
            throw refused(problem.get());
        }
        Multipart form = new Multipart(boundary())
                .field("variant", (model == null ? SkinModel.CLASSIC : model).apiVariant())
                .file("file", "skin.png", "image/png", pngBytes);
        JsonObject response =
                http.sendRaw("POST", endpoints.skins(), form.contentType(), form.body(), NetworkScope.Purpose.PROFILE);
        return AccountHttp.decode(gson, response, PlayerProfile.class);
    }

    @Override
    public PlayerProfile upload(Path pngFile, SkinModel model) {
        return upload(read(pngFile), model);
    }

    @Override
    public void reset() {
        resetToDefault();
    }

    @Override
    public PlayerProfile resetToDefault() {
        JsonObject response = http.sendJson("DELETE", endpoints.activeSkin(), null, NetworkScope.Purpose.PROFILE);
        return AccountHttp.decode(gson, response, PlayerProfile.class);
    }

    /**
     * Reads a skin file, refusing one that is too large before reading it.
     *
     * <p>Every failure is reported by kind and never by the underlying exception: a file-system
     * exception's message is the absolute path, which must not reach a message a host displays or logs.
     *
     * @param file the file to read
     * @return its bytes
     * @throws AltsException of kind {@link Kind#INVALID_INPUT} if the file is missing, unreadable, or too
     *     large
     */
    private static byte[] read(Path file) {
        if (file == null) {
            throw refused(SkinProblem.UNREADABLE);
        }
        try {
            if (!Files.isRegularFile(file)) {
                throw refused(SkinProblem.UNREADABLE);
            }
            if (Files.size(file) > MAX_SKIN_BYTES) {
                throw refused(SkinProblem.TOO_LARGE);
            }
            return Files.readAllBytes(file);
        } catch (IOException | SecurityException unreadable) {
            // Not kept as the cause: a file-system exception's message is the absolute path.
            throw refused(SkinProblem.UNREADABLE);
        }
    }

    /**
     * Checks that bytes are a skin the services could accept, so a wrong file costs no request.
     *
     * <p>Only the PNG header is read — the signature and the dimensions the first chunk declares. The
     * image is not decoded: the services do that, and decoding an arbitrary file here is work and risk
     * for nothing.
     *
     * @param png the candidate skin
     * @return why the bytes are refused, or empty when they are an uploadable skin
     */
    static Optional<SkinProblem> problemWith(byte[] png) {
        if (png == null || png.length == 0) {
            return Optional.of(SkinProblem.EMPTY);
        }
        if (png.length > MAX_SKIN_BYTES) {
            return Optional.of(SkinProblem.TOO_LARGE);
        }
        if (png.length < PNG_HEADER_LENGTH || !startsWithSignature(png) || !declaresHeaderChunk(png)) {
            return Optional.of(SkinProblem.NOT_PNG);
        }
        int width = readInt(png, 16);
        int height = readInt(png, 20);
        if (width != SKIN_WIDTH || (height != SKIN_HEIGHT && height != LEGACY_SKIN_HEIGHT)) {
            return Optional.of(SkinProblem.WRONG_DIMENSIONS);
        }
        return Optional.empty();
    }

    /** The failure an upload refused locally fails with: {@link Kind#INVALID_INPUT}, nothing sent. */
    private static AltsException refused(SkinProblem problem) {
        return new AltsException(Kind.INVALID_INPUT, describe(problem));
    }

    /** A fixed description of a problem, naming no path. */
    private static String describe(SkinProblem problem) {
        return switch (problem) {
            case UNREADABLE -> "The skin file could not be read";
            case EMPTY -> "The skin is empty";
            case TOO_LARGE -> "The skin is larger than " + MAX_SKIN_BYTES + " bytes";
            case NOT_PNG -> "The skin is not a PNG image";
            case WRONG_DIMENSIONS -> "A skin is 64x64 or 64x32 pixels";
        };
    }

    private static boolean startsWithSignature(byte[] png) {
        for (int i = 0; i < PNG_SIGNATURE.length; i++) {
            if (png[i] != PNG_SIGNATURE[i]) {
                return false;
            }
        }
        return true;
    }

    /** Returns whether the first chunk is the image header, whose type sits at bytes 12 to 15. */
    private static boolean declaresHeaderChunk(byte[] png) {
        return png[12] == 'I' && png[13] == 'H' && png[14] == 'D' && png[15] == 'R';
    }

    private static int readInt(byte[] bytes, int offset) {
        return ((bytes[offset] & 0xff) << 24)
                | ((bytes[offset + 1] & 0xff) << 16)
                | ((bytes[offset + 2] & 0xff) << 8)
                | (bytes[offset + 3] & 0xff);
    }

    /**
     * Returns a fresh multipart boundary. Random per request, so no fixed string exists for file content
     * to collide with — a constant boundary is one a crafted file can contain, ending its own part early
     * and appending fields of its choosing.
     *
     * @return a boundary unique to one request
     */
    private static String boundary() {
        byte[] random = new byte[16];
        BOUNDARIES.nextBytes(random);
        return "alts-skin-" + HexFormat.of().formatHex(random);
    }
}
