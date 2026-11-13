package lol.trq.alts.account;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

/**
 * The whole post-login account surface, built over one live Minecraft access token. Hands out the
 * focused services — profile, entitlements, name, skin, cape, player attributes, chat-signing
 * certificates, the privacy blocklist — each of which a host can hold on its own.
 *
 * <p>Reached through {@code AltsRuntime#accountServices}, one per account, over its access token; there is
 * no public factory, so every instance runs on its runtime's endpoints. Nothing here installs a session
 * or touches the account store; these operate directly on the account the token belongs to.
 *
 * @author trq
 * @since 1.0.0
 */
public final class AccountServices {

    private static final Gson GSON = new GsonBuilder().create();

    static {
        AccountBridge.install();
    }

    private final ProfileService profile;
    private final EntitlementService entitlements;
    private final NameService name;
    private final SkinService skin;
    private final CapeService cape;
    private final PlayerAttributesService attributes;
    private final CertificateService certificates;
    private final BlocklistService blocklist;

    private AccountServices(String token, String accountUuid, AccountEndpoints endpoints) {
        AccountHttp http = new AccountHttp(token, accountUuid);
        this.profile = new ProfileServiceImpl(http, endpoints, GSON);
        this.entitlements = new EntitlementServiceImpl(http, endpoints);
        this.name = new NameServiceImpl(http, endpoints, GSON);
        this.skin = new SkinServiceImpl(http, endpoints, GSON);
        this.cape = new CapeServiceImpl(http, endpoints, GSON, this.profile);
        this.attributes = new PlayerAttributesServiceImpl(http, endpoints);
        this.certificates = new CertificateServiceImpl(http, endpoints);
        this.blocklist = new BlocklistServiceImpl(http, endpoints);
    }

    /**
     * Builds the services against a given endpoint base. Package-private: the runtime reaches it through
     * {@link AccountBridge}, and a host through {@code AltsRuntime#accountServices}.
     *
     * @param token the account's Minecraft access token
     * @param accountUuid the account UUID, for per-account request routing; may be null
     * @param endpoints the Minecraft services base
     * @return the services
     */
    static AccountServices create(String token, String accountUuid, AccountEndpoints endpoints) {
        return new AccountServices(token, accountUuid, endpoints == null ? AccountEndpoints.defaults() : endpoints);
    }

    /**
     * Returns the profile service — the full read, and creation for an account that has none.
     *
     * @return the profile service
     * @since 1.0.0
     */
    public ProfileService profile() {
        return profile;
    }

    /**
     * Returns the entitlement (ownership) service.
     *
     * @return the entitlement service
     * @since 1.0.0
     */
    public EntitlementService entitlements() {
        return entitlements;
    }

    /**
     * Returns the name service — availability, eligibility, change, and scheduled claim.
     *
     * @return the name service
     * @since 1.0.0
     */
    public NameService name() {
        return name;
    }

    /**
     * Returns the skin service.
     *
     * @return the skin service
     * @since 1.0.0
     */
    public SkinService skin() {
        return skin;
    }

    /**
     * Returns the cape service.
     *
     * @return the cape service
     * @since 1.0.0
     */
    public CapeService cape() {
        return cape;
    }

    /**
     * Returns the player-attributes service — privileges, preferences, and ban status.
     *
     * @return the player-attributes service
     * @since 0.12.0
     */
    public PlayerAttributesService attributes() {
        return attributes;
    }

    /**
     * Returns the certificate service, which issues the account's chat-signing key pair.
     *
     * @return the certificate service
     * @since 0.12.0
     */
    public CertificateService certificates() {
        return certificates;
    }

    /**
     * Returns the privacy-blocklist service.
     *
     * @return the blocklist service
     * @since 0.12.0
     */
    public BlocklistService blocklist() {
        return blocklist;
    }
}
