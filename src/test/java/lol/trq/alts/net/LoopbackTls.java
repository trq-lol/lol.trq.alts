package lol.trq.alts.net;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.Comparator;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

/**
 * A throwaway TLS identity for a loopback origin, generated when a test asks for it.
 *
 * <p>The certificate is self-signed and names only the loopback IP address, so a test can trust exactly
 * this one certificate — through an ordinary trust manager, with hostname verification still running —
 * rather than switching trust off. Nothing here ships, and no key material is committed.
 */
final class LoopbackTls implements AutoCloseable {

    private static final char[] PASSWORD = "changeit".toCharArray();

    private final Path directory;
    private final SSLContext serverContext;
    private final SSLSocketFactory trustingFactory;

    private LoopbackTls(Path directory, SSLContext serverContext, SSLSocketFactory trustingFactory) {
        this.directory = directory;
        this.serverContext = serverContext;
        this.trustingFactory = trustingFactory;
    }

    /** Generates a key pair and a self-signed certificate valid for the loopback IP address only. */
    static LoopbackTls generate() throws IOException, GeneralSecurityException, InterruptedException {
        Path directory = Files.createTempDirectory("loopback-tls");
        Path keystore = directory.resolve("origin.p12");
        String loopback = InetAddress.getLoopbackAddress().getHostAddress();
        Process keytool = new ProcessBuilder(
                        Path.of(System.getProperty("java.home"), "bin", "keytool")
                                .toString(),
                        "-genkeypair",
                        "-alias",
                        "origin",
                        "-keyalg",
                        "EC",
                        "-groupname",
                        "secp256r1",
                        "-dname",
                        "CN=loopback-origin",
                        "-ext",
                        "san=ip:" + loopback,
                        "-validity",
                        "2",
                        "-storetype",
                        "PKCS12",
                        "-keystore",
                        keystore.toString(),
                        "-storepass",
                        new String(PASSWORD),
                        "-keypass",
                        new String(PASSWORD))
                .redirectErrorStream(true)
                .start();
        String output = new String(keytool.getInputStream().readAllBytes());
        if (!keytool.waitFor(60, TimeUnit.SECONDS) || keytool.exitValue() != 0) {
            throw new IOException("keytool could not generate the test certificate: " + output);
        }

        KeyStore identity = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(keystore)) {
            identity.load(in, PASSWORD);
        }
        KeyManagerFactory keys = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keys.init(identity, PASSWORD);
        SSLContext server = SSLContext.getInstance("TLS");
        server.init(keys.getKeyManagers(), null, null);

        KeyStore trusted = KeyStore.getInstance(KeyStore.getDefaultType());
        trusted.load(null, null);
        trusted.setCertificateEntry("origin", identity.getCertificate("origin"));
        TrustManagerFactory trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trust.init(trusted);
        SSLContext client = SSLContext.getInstance("TLS");
        client.init(null, trust.getTrustManagers(), null);

        return new LoopbackTls(directory, server, client.getSocketFactory());
    }

    /** Creates an unstarted HTTPS server on an ephemeral loopback port, presenting the generated certificate. */
    HttpsServer newServer() throws IOException {
        HttpsServer server = HttpsServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(serverContext));
        return server;
    }

    /** Returns a socket factory that trusts the generated certificate and nothing else. */
    SSLSocketFactory trustingFactory() {
        return trustingFactory;
    }

    @Override
    public void close() throws IOException {
        try (Stream<Path> files = Files.walk(directory)) {
            for (Path file : files.sorted(Comparator.reverseOrder()).toList()) {
                Files.deleteIfExists(file);
            }
        }
    }
}
