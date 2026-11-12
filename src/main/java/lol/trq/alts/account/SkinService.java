package lol.trq.alts.account;

import java.nio.file.Path;

/**
 * Changes the account's skin.
 *
 * @author trq
 * @since 1.0.0
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
     * Sets the skin from a texture URL Mojang will fetch.
     *
     * @param url the skin texture URL
     * @param model the arm model to render it with
     * @return the updated profile
     * @throws AccountException if the token was refused or the service rejected the skin
     * @since 1.0.0
     */
    PlayerProfile setFromUrl(String url, SkinModel model) throws AccountException;

    /**
     * Uploads a skin from PNG bytes.
     *
     * <p>The bytes are checked before anything is sent: they must be a PNG of 64x64 or 64x32 pixels, no
     * larger than {@link #MAX_SKIN_BYTES}. One that is not fails with a
     * {@link SkinValidationException}, which says which.
     *
     * @param pngBytes the skin PNG
     * @param model the arm model to render it with
     * @return the updated profile
     * @throws SkinValidationException if the bytes are not an uploadable skin; nothing was sent
     * @throws AccountException if the token was refused or the service rejected the skin
     * @since 1.0.0
     */
    PlayerProfile upload(byte[] pngBytes, SkinModel model) throws AccountException;

    /**
     * Uploads a skin from a PNG file, with the same checks as {@link #upload(byte[], SkinModel)}.
     *
     * <p>No failure this raises names the file: a path on the user's disk says where they keep things
     * and under what account name, and failure messages are what a host shows and logs.
     *
     * @param pngFile the skin PNG file
     * @param model the arm model to render it with
     * @return the updated profile
     * @throws SkinValidationException if the file cannot be read or is not an uploadable skin; nothing
     *     was sent
     * @throws AccountException if the token was refused or the service rejected the skin
     * @throws UnsupportedOperationException if this implementation predates file uploads
     * @since 0.12.0
     */
    default PlayerProfile upload(Path pngFile, SkinModel model) throws AccountException {
        throw new UnsupportedOperationException("file upload is not supported by this implementation");
    }

    /**
     * Resets the skin to the default, removing any custom one.
     *
     * @throws AccountException if the token was refused or the service failed
     * @since 1.0.0
     */
    void reset() throws AccountException;

    /**
     * Resets the skin to the default and returns the profile as it stands afterwards, the way the other
     * mutations here do.
     *
     * @return the updated profile, or {@code null} when the service confirmed the reset without sending
     *     one back
     * @throws AccountException if the token was refused or the service failed
     * @since 0.12.0
     */
    default PlayerProfile resetToDefault() throws AccountException {
        reset();
        return null;
    }
}
