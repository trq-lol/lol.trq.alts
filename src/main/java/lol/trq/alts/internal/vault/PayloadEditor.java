package lol.trq.alts.internal.vault;

import com.google.gson.JsonElement;
import java.util.Optional;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.function.LongSupplier;
import lol.trq.alts.AltsException;
import lol.trq.alts.AltsFailure.Kind;
import lol.trq.alts.internal.avp.Hlc;
import lol.trq.alts.internal.avp.Payload;
import lol.trq.alts.internal.avp.Payload.Account;
import lol.trq.alts.internal.avp.Payload.Field;
import lol.trq.alts.internal.avp.Payload.Stamp;

/**
 * One write's edits to a copy of the local payload (AVP SPEC 5), each stamped by the vault's clock. The
 * vault observes every stamp it has merged before it hands an editor out, so every stamp an edit takes is
 * greater than every stamp the vault has seen.
 *
 * <p>Used only inside {@link VaultEngine#write}: an editor is not thread safe and is discarded with the write.
 *
 * @author trq
 * @since 1.0.0
 */
public final class PayloadEditor {

    private final SortedMap<String, Account> accounts;
    private final Hlc hlc;
    private final LongSupplier clock;
    private final String by;

    PayloadEditor(Payload base, Hlc hlc, LongSupplier clock, String by) {
        this.accounts = new TreeMap<>(base.accounts());
        this.hlc = hlc;
        this.clock = clock;
        this.by = by;
    }

    /**
     * A fresh stamp from the clock.
     *
     * @return the stamp
     * @throws AltsException of kind {@code PROTOCOL} if the clock cannot advance: the vault holds the largest
     *     stamp there is, which only a hostile member can have written
     */
    public Stamp tick() {
        try {
            return hlc.tick(clock.getAsLong(), by);
        } catch (AltsException e) {
            if (e.kind() == Kind.PROTOCOL) {
                throw new AltsException(Kind.PROTOCOL, VaultFailures.IMPOSSIBLE_TIMESTAMP);
            }
            throw e;
        }
    }

    private Account account(String uuid) {
        return accounts.getOrDefault(uuid, new Account(Optional.empty(), new TreeMap<>(), new TreeMap<>()));
    }

    /**
     * Sets one field of an account, creating the account if needed.
     *
     * @param uuid the account's player UUID
     * @param name the field name
     * @param value the value; a JSON null clears it
     */
    public void setField(String uuid, String name, JsonElement value) {
        Account a = account(uuid);
        SortedMap<String, Field> fields = new TreeMap<>(a.fields());
        fields.put(name, new Field(value, tick()));
        accounts.put(uuid, new Account(a.deleted(), fields, a.bans()));
    }

    /**
     * Sets the ban register of an account on one server.
     *
     * @param uuid the account's player UUID
     * @param serverId the server id
     * @param value the ban value; a JSON null clears it
     */
    public void setBan(String uuid, String serverId, JsonElement value) {
        Account a = account(uuid);
        SortedMap<String, Field> bans = new TreeMap<>(a.bans());
        bans.put(serverId, new Field(value, tick()));
        accounts.put(uuid, new Account(a.deleted(), a.fields(), bans));
    }

    /**
     * Deletes an account: its marker takes a fresh stamp, greater than every stamp it holds, and its fields
     * stay (SPEC 5). A later edit brings it back.
     *
     * @param uuid the account's player UUID
     */
    public void deleteAccount(String uuid) {
        Account a = account(uuid);
        accounts.put(uuid, new Account(Optional.of(tick()), a.fields(), a.bans()));
    }

    /**
     * The payload as edited so far.
     *
     * @return the payload
     */
    public Payload payload() {
        return new Payload(accounts);
    }

    /**
     * Counts only; a payload holds credentials.
     *
     * @return a description
     */
    @Override
    public String toString() {
        return "PayloadEditor[" + accounts.size() + " accounts]";
    }
}
