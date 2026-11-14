package lol.trq.alts.internal.net;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * Reaches an HTTPS origin through one HTTP proxy route, performing the {@code CONNECT} handshake itself.
 *
 * <p>Neither JDK HTTP stack can do this per request. {@code HttpURLConnection} builds its {@code CONNECT}
 * from a fresh header set, so a {@code Proxy-Authorization} request property never reaches the proxy and
 * is instead sent to the origin inside the tunnel; {@code java.net.http.HttpClient} filters a caller-set
 * Basic credential off the {@code CONNECT} because {@code jdk.http.auth.tunneling.disabledSchemes} lists
 * Basic by default. Changing either means process-global state, which a library must not touch.
 *
 * <p>So the tunnel is opened here: the socket this factory hands out connects to the proxy rather than
 * to the address it is asked for, sends {@code CONNECT} carrying the credential, and requires a
 * {@code 2xx} before a byte of TLS is exchanged. The credential therefore exists only on the proxy leg.
 * TLS is then layered by the JVM's own socket factory with HTTPS endpoint identification switched on, so
 * trust and hostname verification are exactly what a direct connection gets.
 *
 * <p>The {@code CONNECT} names the origin host as the URL wrote it, so the proxy resolves it. The JDK
 * does still look the name up locally before handing the address over; that lookup's answer is unused
 * and a failed one changes nothing, but a host that must keep even DNS off the local resolver cannot
 * get that from this path.
 *
 * <p>Every path that could reach the origin without the proxy throws. One instance serves one route
 * identity — proxy host, port, and credential — and the JDK keys its keep-alive pool on the factory
 * instance, which is what stops two identities on one gateway from sharing a tunnel. The factory keeps
 * track of the tunnels it opened, so closing the transport closes the pooled ones too.
 *
 * @author trq
 * @since 0.12.0
 */
final class ProxyTunnelSocketFactory extends SSLSocketFactory {

    /** Largest {@code CONNECT} response head accepted before the proxy is treated as misbehaving. */
    private static final int MAX_RESPONSE_HEAD_BYTES = 16 * 1024;

    /** How long the handshake may take when the caller set no connect timeout. */
    private static final int DEFAULT_HANDSHAKE_TIMEOUT_MILLIS = 10_000;

    private final String proxyHost;
    private final int proxyPort;
    private final String authorization;
    private final Supplier<SSLSocketFactory> tls;

    /** Every tunnel this factory opened that is not yet closed, pooled or in use. */
    private final Set<TunnelSocket> open = ConcurrentHashMap.newKeySet();

    /**
     * Creates the factory for one route identity.
     *
     * @param proxyHost the proxy host
     * @param proxyPort the proxy port
     * @param authorization the {@code Proxy-Authorization} value, or null for an unauthenticated proxy
     * @param tls supplies the factory that layers TLS over an established tunnel
     */
    ProxyTunnelSocketFactory(String proxyHost, int proxyPort, String authorization, Supplier<SSLSocketFactory> tls) {
        this.proxyHost = proxyHost;
        this.proxyPort = proxyPort;
        this.authorization = authorization;
        this.tls = tls;
    }

    /**
     * Returns an unconnected socket whose {@code connect} opens a tunnel to whatever address it is given.
     *
     * @return the tunnel socket
     */
    @Override
    public Socket createSocket() {
        TunnelSocket socket = new TunnelSocket();
        open.add(socket);
        return socket;
    }

    /**
     * Returns whether every tunnel this factory opened has been closed.
     *
     * @return true when none is open
     */
    boolean idle() {
        return open.isEmpty();
    }

    /**
     * Closes every tunnel this factory opened and has not seen closed, the JDK's pooled keep-alive ones
     * included. The transport calls this when it closes: a pooled tunnel is a live connection to the
     * proxy, held open under the route's identity, that nothing else would ever close.
     */
    void closeAll() {
        for (TunnelSocket socket : List.copyOf(open)) {
            try {
                socket.close();
            } catch (IOException ignored) {
                // Closing is best effort; the socket is dropped from the set either way.
            }
        }
    }

    /**
     * Layers TLS over an established tunnel. A socket that did not come from this factory, or whose
     * tunnel was never established, is refused: wrapping it would send the request from wherever that
     * socket happens to be connected.
     *
     * @param socket the tunnel socket
     * @param host the origin host, used for SNI and certificate matching
     * @param port the origin port
     * @param autoClose whether closing the TLS socket closes the tunnel
     * @return the TLS socket, with HTTPS endpoint identification enabled
     * @throws IOException if the socket is not an established tunnel from this factory
     */
    @Override
    public Socket createSocket(Socket socket, String host, int port, boolean autoClose) throws IOException {
        if (!(socket instanceof TunnelSocket tunnel) || tunnel.owner() != this || !tunnel.established()) {
            throw new IOException("refusing to start TLS over a socket that is not an established proxy tunnel");
        }
        SSLSocket secured = (SSLSocket) tls.get().createSocket(socket, host, port, autoClose);
        SSLParameters parameters = secured.getSSLParameters();
        parameters.setEndpointIdentificationAlgorithm("HTTPS");
        secured.setSSLParameters(parameters);
        return secured;
    }

    /**
     * Refuses a direct connection. The JDK falls back to this overload when layering TLS over the
     * tunnel fails; honouring it would connect to the origin from the machine's own address.
     *
     * @param host the origin host
     * @param port the origin port
     * @return never
     * @throws IOException always
     */
    @Override
    public Socket createSocket(String host, int port) throws IOException {
        throw direct();
    }

    /**
     * Refuses a direct connection.
     *
     * @param host the origin host
     * @param port the origin port
     * @param localHost the local address
     * @param localPort the local port
     * @return never
     * @throws IOException always
     */
    @Override
    public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException {
        throw direct();
    }

    /**
     * Refuses a direct connection.
     *
     * @param host the origin address
     * @param port the origin port
     * @return never
     * @throws IOException always
     */
    @Override
    public Socket createSocket(InetAddress host, int port) throws IOException {
        throw direct();
    }

    /**
     * Refuses a direct connection.
     *
     * @param address the origin address
     * @param port the origin port
     * @param localAddress the local address
     * @param localPort the local port
     * @return never
     * @throws IOException always
     */
    @Override
    public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort)
            throws IOException {
        throw direct();
    }

    @Override
    public String[] getDefaultCipherSuites() {
        return tls.get().getDefaultCipherSuites();
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return tls.get().getSupportedCipherSuites();
    }

    private static IOException direct() {
        return new IOException("this route is proxied; a direct connection to the origin is refused");
    }

    /**
     * Formats a {@code CONNECT} authority, bracketing an IPv6 literal.
     *
     * @param host the origin host
     * @param port the origin port
     * @return the {@code host:port} authority
     * @throws IOException if the host could not be written safely on a request line
     */
    static String authority(String host, int port) throws IOException {
        if (host == null || host.isEmpty()) {
            throw new IOException("no origin host to tunnel to");
        }
        for (int i = 0; i < host.length(); i++) {
            char c = host.charAt(i);
            if (c <= ' ' || c >= 0x7f) {
                throw new IOException("origin host is not a valid tunnel authority");
            }
        }
        boolean bareIpv6 = host.indexOf(':') >= 0 && !host.startsWith("[");
        return (bareIpv6 ? "[" + host + "]" : host) + ":" + port;
    }

    /** A socket that connects to the proxy and tunnels to the address it was asked to reach. */
    private final class TunnelSocket extends Socket {

        private volatile boolean established;

        TunnelSocket() {
            // NO_PROXY: the hop to the named proxy must not itself be re-routed by JVM-wide SOCKS settings.
            super(Proxy.NO_PROXY);
        }

        ProxyTunnelSocketFactory owner() {
            return ProxyTunnelSocketFactory.this;
        }

        boolean established() {
            return established;
        }

        @Override
        public void close() throws IOException {
            try {
                super.close();
            } finally {
                open.remove(this);
            }
        }

        @Override
        public void connect(SocketAddress endpoint) throws IOException {
            connect(endpoint, 0);
        }

        @Override
        public void connect(SocketAddress endpoint, int timeout) throws IOException {
            if (!(endpoint instanceof InetSocketAddress target)) {
                throw new IOException("unsupported tunnel target");
            }
            // getHostString: the proxy resolves the name, so the CONNECT must carry it as written.
            String authority = authority(target.getHostString(), target.getPort());
            int budget = timeout > 0 ? timeout : DEFAULT_HANDSHAKE_TIMEOUT_MILLIS;
            long deadline = System.nanoTime() + budget * 1_000_000L;
            try {
                // One budget covers the connect and the whole CONNECT exchange: each read below is
                // given only what is left of it, so a proxy that is slow to accept and then slow to
                // answer cannot spend the budget twice.
                super.connect(new InetSocketAddress(proxyHost, proxyPort), budget);
                handshake(authority, deadline);
                setSoTimeout(0);
                established = true;
            } catch (IOException | RuntimeException failure) {
                try {
                    close();
                } catch (IOException ignored) {
                    // The handshake failure is the one worth reporting.
                }
                throw failure;
            }
        }

        private void handshake(String authority, long deadline) throws IOException {
            StringBuilder request = new StringBuilder(256)
                    .append("CONNECT ")
                    .append(authority)
                    .append(" HTTP/1.1\r\nHost: ")
                    .append(authority)
                    .append("\r\n");
            if (authorization != null) {
                request.append("Proxy-Authorization: ").append(authorization).append("\r\n");
            }
            request.append("Proxy-Connection: Keep-Alive\r\n\r\n");
            OutputStream out = getOutputStream();
            out.write(request.toString().getBytes(StandardCharsets.ISO_8859_1));
            out.flush();

            int status = statusOf(readHead(this, deadline));
            if (status < 200 || status >= 300) {
                throw new IOException("proxy refused the tunnel with status " + status);
            }
        }
    }

    /**
     * Reads a response head up to and including its blank line, one byte at a time so nothing belonging
     * to the TLS stream that follows is consumed. Before every read the socket's timeout is set to what
     * remains until the deadline, so no single read can outlast it.
     *
     * @param socket the socket connected to the proxy
     * @param deadline the {@link System#nanoTime()} instant the handshake must finish by
     * @return the head, without the terminating blank line
     * @throws IOException if the stream ends, runs long, or runs past the deadline
     */
    private static String readHead(Socket socket, long deadline) throws IOException {
        InputStream in = socket.getInputStream();
        StringBuilder head = new StringBuilder(128);
        int matched = 0;
        while (matched < 4) {
            if (head.length() >= MAX_RESPONSE_HEAD_BYTES) {
                throw new IOException("proxy sent an oversized response to CONNECT");
            }
            long remainingNanos = deadline - System.nanoTime();
            if (remainingNanos <= 0) {
                throw new IOException("proxy did not answer CONNECT in time");
            }
            // Rounded up, and never zero: a zero timeout means wait forever.
            socket.setSoTimeout((int) Math.max(1L, (remainingNanos + 999_999L) / 1_000_000L));
            int b;
            try {
                b = in.read();
            } catch (SocketTimeoutException outOfTime) {
                throw new IOException("proxy did not answer CONNECT in time");
            }
            if (b < 0) {
                throw new IOException("proxy closed the connection during CONNECT");
            }
            head.append((char) b);
            boolean expected = (matched % 2 == 0) ? b == '\r' : b == '\n';
            matched = expected ? matched + 1 : (b == '\r' ? 1 : 0);
        }
        return head.substring(0, head.length() - 4);
    }

    /**
     * Parses the status code out of a response head. The code is exactly three ASCII digits, as the
     * protocol defines it: no sign, no fourth digit, and none of the other digits a lenient number
     * parser accepts, so nothing that is not a status can be read as a success.
     *
     * @param head the response head
     * @return the status code
     * @throws IOException if the head does not start with an HTTP status line
     */
    static int statusOf(String head) throws IOException {
        int lineEnd = head.indexOf("\r\n");
        String line = lineEnd < 0 ? head : head.substring(0, lineEnd);
        String[] parts = line.split(" ", 3);
        if (parts.length < 2 || !parts[0].startsWith("HTTP/1.")) {
            throw new IOException("proxy answered CONNECT with something that is not HTTP");
        }
        String code = parts[1];
        if (code.length() != 3) {
            throw new IOException("proxy answered CONNECT with a malformed status line");
        }
        int status = 0;
        for (int index = 0; index < 3; index++) {
            char digit = code.charAt(index);
            if (digit < '0' || digit > '9') {
                throw new IOException("proxy answered CONNECT with a malformed status line");
            }
            status = status * 10 + (digit - '0');
        }
        return status;
    }
}
