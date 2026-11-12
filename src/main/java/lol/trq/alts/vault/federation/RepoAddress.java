package lol.trq.alts.vault.federation;

import java.util.Objects;
import java.util.regex.Pattern;

/**
 * A federated, globally-resolvable address for a shared repository: the host of the server that holds
 * it plus the server-local repository id. Rendered as the URI {@code avp://<host>/<repoId>}.
 *
 * <p>The repository id stays exactly the opaque value the server minted — folding the host into the id
 * would change the on-the-wire manifest and break existing repositories, so the host lives only in the
 * address. A repository is globally identified by the {@code (host, repoId)} pair; the id alone is
 * unique only within one host. To reach a repository, a client resolves a transport for {@link #host()}
 * (see {@code VaultTransportResolver}) and authenticates there with its own identity.
 *
 * <p>An address usually arrives from someone else (a pasted link, a locator token), so both parts are
 * validated strictly. The host must be a plain DNS name, an IPv4 address, or a bracketed IPv6 literal,
 * optionally followed by a port; anything carrying userinfo ({@code user@host}), a path, a query, or
 * whitespace is rejected, because a resolver handed such a string could connect somewhere other than
 * where the address appears to point.
 *
 * @param host the authority of the server holding the repository ({@code host} or {@code host:port})
 * @param repoId the server-local repository id
 * @author trq
 * @since 0.2.0
 */
public record RepoAddress(String host, String repoId) {

    /** The federation URI scheme prefix. */
    public static final String SCHEME = "avp://";

    private static final int MAX_NAME_LENGTH = 253;
    private static final int MAX_REPO_ID_LENGTH = 256;
    private static final int MAX_PORT = 65_535;

    private static final Pattern NAME = Pattern.compile(
            "[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*");
    private static final Pattern IPV6_LITERAL = Pattern.compile("\\[[0-9A-Fa-f:.]{2,45}]");
    private static final Pattern PORT = Pattern.compile("[0-9]{1,5}");
    private static final String FORBIDDEN_REPO_ID_CHARS = "/\\?#@%";

    /**
     * Validates the host is a well-formed authority and the repository id is a single safe path
     * segment.
     *
     * @throws IllegalArgumentException if either part is malformed
     */
    public RepoAddress {
        Objects.requireNonNull(host, "host");
        Objects.requireNonNull(repoId, "repoId");
        requireHost(host);
        requireRepoId(repoId);
    }

    /**
     * Renders this address as an {@code avp://host/repoId} URI.
     *
     * @return the URI form
     */
    public String toUri() {
        return SCHEME + host + "/" + repoId;
    }

    /**
     * Parses an {@code avp://host/repoId} URI.
     *
     * @param uri the URI to parse
     * @return the parsed address
     * @throws IllegalArgumentException if the URI is not a well-formed {@code avp://} address
     */
    public static RepoAddress parse(String uri) {
        Objects.requireNonNull(uri, "uri");
        if (!uri.startsWith(SCHEME)) {
            throw new IllegalArgumentException("not an avp:// uri: " + uri);
        }
        String rest = uri.substring(SCHEME.length());
        int slash = rest.indexOf('/');
        if (slash <= 0 || slash >= rest.length() - 1) {
            throw new IllegalArgumentException("malformed avp:// uri (expected avp://host/repoId): " + uri);
        }
        return new RepoAddress(rest.substring(0, slash), rest.substring(slash + 1));
    }

    @Override
    public String toString() {
        return toUri();
    }

    private static void requireHost(String host) {
        if (host.isEmpty()) {
            throw new IllegalArgumentException("host is empty");
        }
        String name = host;
        if (host.charAt(0) == '[') {
            int close = host.indexOf(']');
            if (close < 0) {
                throw new IllegalArgumentException("host has an unterminated IPv6 literal");
            }
            name = host.substring(0, close + 1);
            if (!IPV6_LITERAL.matcher(name).matches() || name.indexOf(':') < 0) {
                throw new IllegalArgumentException("host is not a valid IPv6 literal");
            }
            String tail = host.substring(close + 1);
            if (!tail.isEmpty()) {
                if (tail.charAt(0) != ':') {
                    throw new IllegalArgumentException("host has trailing characters after the IPv6 literal");
                }
                requirePort(tail.substring(1));
            }
            return;
        }
        int colon = host.indexOf(':');
        if (colon >= 0) {
            name = host.substring(0, colon);
            requirePort(host.substring(colon + 1));
        }
        if (name.length() > MAX_NAME_LENGTH || !NAME.matcher(name).matches()) {
            throw new IllegalArgumentException("host is not a valid hostname or address");
        }
    }

    private static void requirePort(String port) {
        if (!PORT.matcher(port).matches()) {
            throw new IllegalArgumentException("host port is not a number");
        }
        int value = Integer.parseInt(port);
        if (value < 1 || value > MAX_PORT) {
            throw new IllegalArgumentException("host port is out of range");
        }
    }

    private static void requireRepoId(String repoId) {
        if (repoId.isEmpty()) {
            throw new IllegalArgumentException("repoId is empty");
        }
        if (repoId.length() > MAX_REPO_ID_LENGTH) {
            throw new IllegalArgumentException("repoId is too long");
        }
        if (repoId.equals(".") || repoId.equals("..")) {
            throw new IllegalArgumentException("repoId is a relative path segment");
        }
        for (int i = 0; i < repoId.length(); i++) {
            char c = repoId.charAt(i);
            if (c <= ' ' || c >= 0x7F || FORBIDDEN_REPO_ID_CHARS.indexOf(c) >= 0) {
                throw new IllegalArgumentException("repoId contains a character that is not allowed");
            }
        }
    }
}
