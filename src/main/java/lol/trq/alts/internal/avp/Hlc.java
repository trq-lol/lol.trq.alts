package lol.trq.alts.internal.avp;

import lol.trq.alts.internal.avp.Payload.Account;
import lol.trq.alts.internal.avp.Payload.Field;
import lol.trq.alts.internal.avp.Payload.Stamp;

/**
 * The hybrid logical clock that stamps a client's writes (AVP SPEC 5), with state {@code (at, n)}.
 *
 * <ul>
 *   <li>{@code tick(now)}: {@code (now, 0)} if {@code now > at}, otherwise {@code (at, n + 1)}.
 *   <li>{@code observe(stamp)}: a later {@code at} is taken with its {@code n}; an equal {@code at} takes
 *       the larger {@code n}; an earlier one changes nothing.
 * </ul>
 *
 * <p>A client observes every stamp of every payload it merges before its next tick, so every stamp it
 * writes is greater than every stamp it has seen. Not thread safe.
 *
 * <p>Ported from the Alt Vault Protocol reference implementation (MIT).
 *
 * @author trq
 * @since 1.0.0
 */
public final class Hlc {

    private long at;
    private long n;

    /**
     * A clock at a given state, for example one restored from storage.
     *
     * @param at the milliseconds
     * @param n the counter
     */
    public Hlc(long at, long n) {
        this.at = at;
        this.n = n;
    }

    /**
     * The clock's milliseconds.
     *
     * @return {@code at}
     */
    public long at() {
        return at;
    }

    /**
     * The clock's counter.
     *
     * @return {@code n}
     */
    public long n() {
        return n;
    }

    /**
     * Advances the clock for one write and returns its stamp. A counter that cannot grow moves the clock to
     * {@code (at + 1, 0)}, which still issues a greater stamp. At {@code (Long.MAX_VALUE, Long.MAX_VALUE)},
     * reachable only by observing a hostile stamp, no greater stamp exists, and the clock refuses rather
     * than issue one it has already seen.
     *
     * @param nowMillis the wall clock in epoch milliseconds
     * @param by the writer's member id
     * @return the write's stamp
     * @throws lol.trq.alts.AltsException of kind {@code PROTOCOL} if no greater stamp exists
     */
    public Stamp tick(long nowMillis, String by) {
        if (nowMillis > at) {
            at = nowMillis;
            n = 0;
        } else if (n < Long.MAX_VALUE) {
            n++;
        } else if (at < Long.MAX_VALUE) {
            at++;
            n = 0;
        } else {
            throw AvpFailures.protocol("the clock cannot issue a stamp greater than one it has seen");
        }
        return new Stamp(at, n, by);
    }

    /**
     * Folds in a stamp seen in a merged payload.
     *
     * @param stamp the stamp
     */
    public void observe(Stamp stamp) {
        if (stamp.at() > at) {
            at = stamp.at();
            n = stamp.n();
        } else if (stamp.at() == at) {
            n = Math.max(n, stamp.n());
        }
    }

    /**
     * Observes every stamp of a payload: each field, each ban and each deletion marker.
     *
     * @param payload the payload
     */
    public void observeAll(Payload payload) {
        for (Account a : payload.accounts().values()) {
            a.deleted().ifPresent(this::observe);
            for (Field f : a.fields().values()) {
                observe(f.stamp());
            }
            for (Field f : a.bans().values()) {
                observe(f.stamp());
            }
        }
    }
}
