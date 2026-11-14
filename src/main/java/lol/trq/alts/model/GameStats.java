package lol.trq.alts.model;

import com.google.gson.annotations.SerializedName;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * A server-agnostic snapshot of an account's public stats on one server, modelled as an ordered list of
 * display {@link Stat} chips. The library never interprets the chips: a host-side
 * {@link lol.trq.alts.spi.GameStatsSource} produces them ready to render (it holds any API key and knows
 * the server's format), and the library only models and caches the result. This keeps the core usable
 * with any server, not just one.
 *
 * <p>Everything here is optional in spirit: {@code stats} may be empty (the player exists but has nothing
 * notable), and a source may decline to produce stats at all.
 *
 * @param serverId an identifier for the server these stats are for (a label the source stamps)
 * @param uuid the player UUID these stats belong to
 * @param stats the ordered display chips; may be empty
 * @param fetchedAt the epoch-millis the source produced this snapshot
 * @author trq
 * @since 0.3.0
 */
public record GameStats(
        @SerializedName("serverId") String serverId,
        @SerializedName("uuid") String uuid,
        @SerializedName("stats") List<Stat> stats,
        @SerializedName("fetchedAt") long fetchedAt) {

    /**
     * Takes its own copy of {@code stats}, unmodifiable, so neither the list it was built from nor the
     * one {@link #stats()} returns can change the snapshot. {@code null} stays {@code null}.
     *
     * @since 0.3.0
     */
    public GameStats {
        stats = stats == null ? null : Collections.unmodifiableList(new ArrayList<>(stats));
    }

    /**
     * A single display chip: a short label and its value, for example {@code ("rank", "Veteran")} or
     * {@code ("wins", "128")}. The host decides how to render the pair (styling, ordering, joining).
     *
     * @param label the chip label
     * @param value the chip value
     * @author trq
     * @since 0.3.0
     */
    public record Stat(
            @SerializedName("label") String label,
            @SerializedName("value") String value) {}
}
