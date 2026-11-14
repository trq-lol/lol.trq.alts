package lol.trq.alts.account;

import java.nio.file.Path;
import java.util.Optional;

/**
 * Changes the account's skin.
 *
 * <p>Not designed for host implementation; methods may be added in minor releases.
 *
 * @author trq
 * @since 0.11.0
 */
public interface SkinService {

    /**
     * The largest skin, in bytes, an upload will send. A real skin is a few kilobytes; this is far past
     * any, and exists so a wrong file is refused here rather than read whole and posted.
     *
     * @since 0.12.0
     */
    int MAX_SKIN_BYTES = 1 << 20;

    /**
     * Checks PNG bytes the way {@link #upload(byte[], SkinModel)} does, without sending anything, and
     * says why they would be refused: the reason a host shows the user, which a
     * {@link lol.trq.alts.AltsFailure.Kind#INVALID_INPUT} failure alone does not carry.
     *
     * @param pngBytes the candidate skin
     * @return why the bytes are not an uploadable skin, or empty when they are one
     * @since 1.0.0
     */
    Optional<SkinProblem> validate(byte[] pngBytes);

    /**
     * Sets the skin from a texture URL Mojang will fetch.
     *
     * @param url the skin texture URL
     * @param model the arm model to render it with
     * @return the updated profile
     * @throws lol.trq.alts.AltsException if the token was refused or the service rejected the skin
     * @since 0.11.0
     */
    PlayerProfile setFromUrl(String url, SkinModel model);

    /**
     * Uploads a skin from PNG bytes.
     *
     * <p>The bytes are checked before anything is sent: they must be a PNG of 64x64 or 64x32 pixels, no
     * larger than {@link #MAX_SKIN_BYTES}. One that is not fails with an
     * {@link lol.trq.alts.AltsException} of kind {@link lol.trq.alts.AltsFailure.Kind#INVALID_INPUT};
     * {@link #validate(byte[])} says which check it failed.
     *
     * @param pngBytes the skin PNG
     * @param model the arm model to render it with
     * @return the updated profile
     * @throws lol.trq.alts.AltsException of kind {@code INVALID_INPUT} if the bytes are not an uploadable skin
     *     (nothing was sent), or of the kind the refusal was if the service refused or failed
     * @since 0.11.0
     */
    PlayerProfile upload(byte[] pngBytes, SkinModel model);

    /**
     * Uploads a skin from a PNG file, with the same checks as {@link #upload(byte[], SkinModel)}.
     *
     * <p>No failure this raises names the file: a path on the user's disk says where they keep things
     * and under what account name, and failure messages are what a host shows and logs.
     *
     * <p>A file that is missing, unreadable or not an uploadable skin fails with kind
     * {@link lol.trq.alts.AltsFailure.Kind#INVALID_INPUT}, which does not say which check it failed. A
     * host that wants the reason to show reads the bytes itself and calls {@link #validate(byte[])} on
     * them; there is no {@code validate(Path)}.
     *
     * @param pngFile the skin PNG file
     * @param model the arm model to render it with
     * @return the updated profile
     * @throws lol.trq.alts.AltsException of kind {@code INVALID_INPUT} if the file cannot be read or is not an
     *     uploadable skin (nothing was sent), or of the kind the refusal was if the service refused or failed
     * @throws UnsupportedOperationException if this implementation predates file uploads
     * @since 0.12.0
     */
    default PlayerProfile upload(Path pngFile, SkinModel model) {
        throw new UnsupportedOperationException("file upload is not supported by this implementation");
    }

    /**
     * Resets the skin to the default, removing any custom one.
     *
     * @throws lol.trq.alts.AltsException if the token was refused or the service failed
     * @since 0.11.0
     */
    void reset();

    /**
     * Resets the skin to the default and returns the profile as it stands afterwards, the way the other
     * mutations here do.
     *
     * @return the updated profile, or {@code null} when the service confirmed the reset without sending
     *     one back
     * @throws lol.trq.alts.AltsException if the token was refused or the service failed
     * @since 0.12.0
     */
    default PlayerProfile resetToDefault() {
        reset();
        return null;
    }
}
