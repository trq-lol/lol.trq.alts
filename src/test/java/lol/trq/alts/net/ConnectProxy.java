package lol.trq.alts.net;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * A stand-in HTTP proxy that only tunnels: it answers {@code CONNECT}, optionally demanding one exact
 * {@code Proxy-Authorization}, and then relays bytes it cannot read. Each accepted connection is one
 * tunnel, so the recorded lists say how many tunnels were opened and as whom.
 *
 * <p>The tunnel always lands on the loopback address at the requested port, whatever host the
 * {@code CONNECT} named, so a test can ask for a name the certificate does not cover and still reach
 * the origin's TLS handshake.
 */
final class ConnectProxy implements AutoCloseable {

    private final ServerSocket socket;
    private final String requiredAuthorization;
    private final List<String> requestLines = Collections.synchronizedList(new ArrayList<>());
    private final List<String> authorizations = Collections.synchronizedList(new ArrayList<>());
    private final List<Socket> open = Collections.synchronizedList(new ArrayList<>());
    private final AtomicInteger closedByClient = new AtomicInteger();

    /**
     * Starts the proxy.
     *
     * @param requiredAuthorization the only credential accepted, or null to accept every {@code CONNECT}
     */
    ConnectProxy(String requiredAuthorization) throws IOException {
        this.requiredAuthorization = requiredAuthorization;
        this.socket = new ServerSocket(0, 0, InetAddress.getLoopbackAddress());
        Thread.ofPlatform().daemon().name("connect-proxy").start(this::accept);
    }

    int port() {
        return socket.getLocalPort();
    }

    /** The request line of every connection accepted, in order. */
    List<String> requestLines() {
        return requestLines;
    }

    /** The {@code Proxy-Authorization} of every connection accepted, in order; empty when absent. */
    List<String> authorizations() {
        return authorizations;
    }

    /** How many established tunnels the client itself closed: their client side reached end of stream. */
    int tunnelsClosedByClient() {
        return closedByClient.get();
    }

    private void accept() {
        while (!socket.isClosed()) {
            try {
                Socket client = socket.accept();
                open.add(client);
                Thread.ofPlatform().daemon().name("connect-proxy-tunnel").start(() -> serve(client));
            } catch (IOException closing) {
                return;
            }
        }
    }

    private void serve(Socket client) {
        try {
            String[] head = readHead(client.getInputStream()).split("\r\n");
            String requestLine = head[0];
            String authorization = "";
            for (String header : head) {
                if (header.toLowerCase(Locale.ROOT).startsWith("proxy-authorization:")) {
                    authorization = header.substring(header.indexOf(':') + 1).trim();
                }
            }
            requestLines.add(requestLine);
            authorizations.add(authorization);

            OutputStream toClient = client.getOutputStream();
            String[] parts = requestLine.split(" ");
            if (!parts[0].equals("CONNECT")) {
                reply(toClient, "405 Method Not Allowed");
                client.close();
                return;
            }
            if (requiredAuthorization != null && !requiredAuthorization.equals(authorization)) {
                reply(toClient, "407 Proxy Authentication Required");
                client.close();
                return;
            }

            int port = Integer.parseInt(parts[1].substring(parts[1].lastIndexOf(':') + 1));
            Socket origin = new Socket(InetAddress.getLoopbackAddress(), port);
            open.add(origin);
            toClient.write("HTTP/1.1 200 Connection established\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1));
            toClient.flush();

            Thread.ofPlatform().daemon().name("connect-proxy-upstream").start(() -> {
                try {
                    client.getInputStream().transferTo(origin.getOutputStream());
                    // A normal return is end of stream: the client closed its side of the tunnel.
                    closedByClient.incrementAndGet();
                } catch (IOException closed) {
                    // Closed under us, by the other direction or by close().
                } finally {
                    closeQuietly(client);
                    closeQuietly(origin);
                }
            });
            relay(origin, client);
        } catch (IOException | RuntimeException failure) {
            closeQuietly(client);
        }
    }

    private static void reply(OutputStream out, String status) throws IOException {
        out.write(("HTTP/1.1 " + status + "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .getBytes(StandardCharsets.ISO_8859_1));
        out.flush();
    }

    private static String readHead(InputStream in) throws IOException {
        StringBuilder head = new StringBuilder();
        while (!head.toString().endsWith("\r\n\r\n")) {
            int b = in.read();
            if (b < 0) {
                throw new IOException("client closed before finishing its request");
            }
            head.append((char) b);
        }
        return head.toString();
    }

    private static void relay(Socket from, Socket to) {
        try {
            from.getInputStream().transferTo(to.getOutputStream());
        } catch (IOException closed) {
            // One side going away is how a tunnel ends.
        } finally {
            closeQuietly(from);
            closeQuietly(to);
        }
    }

    private static void closeQuietly(Socket socket) {
        try {
            socket.close();
        } catch (IOException ignored) {
            // Already closing.
        }
    }

    @Override
    public void close() throws IOException {
        socket.close();
        synchronized (open) {
            open.forEach(ConnectProxy::closeQuietly);
        }
    }
}
