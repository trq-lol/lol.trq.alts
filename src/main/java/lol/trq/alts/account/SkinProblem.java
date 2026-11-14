package lol.trq.alts.account;

/**
 * Why a skin file is refused before anything is sent: the one place where a host needs a finer reason
 * than {@link lol.trq.alts.AltsFailure.Kind#INVALID_INPUT} to tell the user what to fix.
 *
 * <p>{@link SkinService#validate(byte[])} returns one without sending anything; an upload that fails
 * the same check fails with an {@link lol.trq.alts.AltsException} of kind
 * {@link lol.trq.alts.AltsFailure.Kind#INVALID_INPUT}. Branch on this, never on the message.
 *
 * @author trq
 * @since 1.0.0
 */
public enum SkinProblem {
    /**
     * The file could not be read: missing, a directory, or not readable.
     *
     * @since 1.0.0
     */
    UNREADABLE,

    /**
     * There were no bytes to upload.
     *
     * @since 1.0.0
     */
    EMPTY,

    /**
     * The data is larger than {@link SkinService#MAX_SKIN_BYTES}.
     *
     * @since 1.0.0
     */
    TOO_LARGE,

    /**
     * The data does not begin as a PNG, or its header is truncated.
     *
     * @since 1.0.0
     */
    NOT_PNG,

    /**
     * The image is a PNG but not 64x64 or 64x32, the two canvases a skin can have.
     *
     * @since 1.0.0
     */
    WRONG_DIMENSIONS
}
