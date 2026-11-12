package lol.trq.alts.account;

import java.io.Serial;

/**
 * Thrown when a skin is refused locally, before anything is sent: the bytes are not a PNG, the canvas is
 * not a skin's, the file is too large, or it could not be read.
 *
 * <p>An {@link AccountException} with a status of {@code 0}, so a caller that already handles an upload
 * failure handles this too; one that wants to tell the user what is wrong with the file branches on
 * {@link #reason()} rather than on the message.
 *
 * @author trq
 * @since 0.12.0
 */
public final class SkinValidationException extends AccountException {

    @Serial
    private static final long serialVersionUID = 1L;

    /** Why the skin was refused. */
    private final Reason reason;

    /**
     * Why a skin was refused before upload.
     *
     * @author trq
     * @since 0.12.0
     */
    public enum Reason {
        /** The file could not be read — missing, a directory, or not readable. */
        UNREADABLE,

        /** There were no bytes to upload. */
        EMPTY,

        /** The data is larger than {@link SkinService#MAX_SKIN_BYTES}. */
        TOO_LARGE,

        /** The data does not begin as a PNG, or its header is truncated. */
        NOT_PNG,

        /** The image is a PNG but not 64x64 or 64x32, the two canvases a skin can have. */
        WRONG_DIMENSIONS
    }

    /**
     * Creates a validation failure.
     *
     * @param reason why the skin was refused
     * @param message a short description, naming no local path
     * @since 0.12.0
     */
    public SkinValidationException(Reason reason, String message) {
        super(message, 0);
        this.reason = reason;
    }

    /**
     * Returns why the skin was refused.
     *
     * @return the reason
     * @since 0.12.0
     */
    public Reason reason() {
        return reason;
    }
}
