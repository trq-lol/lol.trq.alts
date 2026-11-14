package lol.trq.alts.account;

import com.google.gson.annotations.SerializedName;
import java.time.Duration;
import java.time.Instant;

/**
 * Whether an account may change its name right now, from {@code GET /minecraft/profile/namechange}.
 *
 * <p>Mojang enforces a cooldown between name changes; {@code nameChangeAllowed} is whether the account is
 * past it. {@code createdAt} is when the account was made, which a host turns into account age, and
 * {@code changedAt} is when the name last changed — the anchor for the cooldown a caller may want to
 * display.
 *
 * @param nameChangeAllowed whether a name change is permitted now
 * @param createdAt when the account was created, or {@code null} when the endpoint did not say
 * @param changedAt when the name was last changed, or {@code null} when it never was or the endpoint did
 *     not say; added in 0.12.0
 * @author trq
 * @since 0.11.0
 */
public record NameEligibility(
        @SerializedName("nameChangeAllowed") boolean nameChangeAllowed,
        @SerializedName("createdAt") Instant createdAt,
        @SerializedName("changedAt") Instant changedAt) {

    /**
     * The documented wait between two name changes.
     *
     * @since 0.12.0
     */
    public static final Duration NAME_CHANGE_COOLDOWN = Duration.ofDays(30);

    /**
     * Creates an eligibility with no known last-change time — the shape this record had before
     * {@code changedAt} was added.
     *
     * @param nameChangeAllowed whether a name change is permitted now
     * @param createdAt when the account was created, or {@code null}
     * @since 0.11.0
     */
    public NameEligibility(boolean nameChangeAllowed, Instant createdAt) {
        this(nameChangeAllowed, createdAt, null);
    }

    /**
     * Returns how long ago the account was created, or {@code null} when the creation time is unknown.
     *
     * @param now the current instant to measure against
     * @return the account's age, or null
     * @since 0.11.0
     */
    public Duration ageAt(Instant now) {
        return createdAt == null ? null : Duration.between(createdAt, now);
    }

    /**
     * Estimates the earliest instant the name can next be changed: the last change plus the documented
     * {@link #NAME_CHANGE_COOLDOWN}.
     *
     * <p><strong>An estimate, not the service's answer.</strong> The endpoint returns no such date; this
     * is arithmetic over the one it does return and a cooldown length taken from documentation, which
     * the service is free to change or to apply differently to a given account. Use it to show a user
     * roughly when to come back. {@link #nameChangeAllowed()} is the authority on whether a change is
     * permitted now, and where the two disagree the flag is right.
     *
     * @return the estimated instant, or {@code null} when the last-change time is unknown — including
     *     for a name that has never been changed
     * @since 0.12.0
     */
    public Instant estimatedNextChange() {
        return changedAt == null ? null : changedAt.plus(NAME_CHANGE_COOLDOWN);
    }

    /**
     * Estimates how long remains until the name can next be changed, by the same arithmetic and with
     * the same caveats as {@link #estimatedNextChange()}.
     *
     * @param now the current instant to measure against
     * @return the estimated wait; zero when a change is already allowed or the estimate has passed, and
     *     {@code null} when a change is not allowed and there is nothing to estimate from
     * @since 0.12.0
     */
    public Duration estimatedWaitAt(Instant now) {
        if (nameChangeAllowed) {
            return Duration.ZERO;
        }
        Instant next = estimatedNextChange();
        if (next == null) {
            return null;
        }
        return next.isAfter(now) ? Duration.between(now, next) : Duration.ZERO;
    }
}
