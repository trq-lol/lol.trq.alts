package lol.trq.alts.internal.net;

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
 * A stand-in plain-HTTP proxy that keeps connections alive the way a real one does: it answers every
 * request itself and keeps the socket open for the next one unless the request said
 * {@code Connection: close}. It counts the sockets it accepted and records each request's head, so a
 * test can see whether a client reused a connection and what it asked for.
 */
final class KeepAliveProxy implements AutoCloseable {

    private static final byte[] BODY =
            "{\"id\":\"00000000000040008000000000000001\",\"name\":\"Alex\"}".getBytes(StandardCharsets.UTF_8);

    private final ServerSocket socket;
    private final AtomicInteger connections = new AtomicInteger();
    private final List<String> heads = Collections.synchronizedList(new ArrayList<>());
    private final List<Socket> open = Collections.synchronizedList(new ArrayList<>());

    KeepAliveProxy() throws IOException {
        socket = new ServerSocket(0, 0, InetAddress.getLoopbackAddress());
        Thread.ofPlatform().daemon().name("keep-alive-proxy").start(this::accept);
    }

    int port() {
        return socket.getLocalPort();
    }

    /** How many sockets the proxy accepted: one per connection the client opened. */
    int connections() {
        return connections.get();
    }

    /** The head of every request received, in order. */
    List<String> heads() {
        return heads;
    }

    private void accept() {
        while (!socket.isClosed()) {
            try {
                Socket client = socket.accept();
                connections.incrementAndGet();
                open.add(client);
                Thread.ofPlatform().daemon().name("keep-alive-proxy-conn").start(() -> serve(client));
            } catch (IOException closing) {
                return;
            }
        }
    }

    private void serve(Socket client) {
        try (client) {
            InputStream in = client.getInputStream();
            OutputStream out = client.getOutputStream();
            while (true) {
                String head = readHead(in);
                if (head == null) {
                    return;
                }
                heads.add(head);
                boolean close = head.toLowerCase(Locale.ROOT).contains("\r\nconnection: close");
                out.write(("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + BODY.length
                                + (close ? "\r\nConnection: close" : "\r\nConnection: keep-alive") + "\r\n\r\n")
                        .getBytes(StandardCharsets.ISO_8859_1));
                out.write(BODY);
                out.flush();
                if (close) {
                    return;
                }
            }
        } catch (IOException ended) {
            // The client went away.
        }
    }

    private static String readHead(InputStream in) throws IOException {
        StringBuilder head = new StringBuilder();
        while (!head.toString().endsWith("\r\n\r\n")) {
            int b = in.read();
            if (b < 0) {
                return null;
            }
            head.append((char) b);
        }
        return head.toString();
    }

    @Override
    public void close() throws IOException {
        socket.close();
        synchronized (open) {
            for (Socket client : open) {
                try {
                    client.close();
                } catch (IOException ignored) {
                    // Already closing.
                }
            }
        }
    }
}
