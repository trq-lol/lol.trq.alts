package lol.trq.alts.interop;

import com.google.common.util.concurrent.ListenableFuture;
import io.grpc.CallOptions;
import io.grpc.Channel;
import io.grpc.ClientCall;
import io.grpc.ClientInterceptors;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import io.grpc.Metadata;
import io.grpc.MethodDescriptor;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.grpc.stub.ClientCalls;
import io.grpc.stub.MetadataUtils;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.URI;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import lol.trq.alts.spi.VaultRpcChannel;

/**
 * A {@link VaultRpcChannel} over grpc-java, the way a host adapts its own gRPC runtime: a byte-array
 * marshaller, the deadline on the call, the library's cancellation passed on, headers and trailers merged
 * into the reply. Plaintext for {@code grpc://}, TLS for {@code grpcs://}. Test-only: the library ships no
 * gRPC client.
 */
final class GrpcJavaChannel implements VaultRpcChannel, AutoCloseable {

    private static final int MAX_INBOUND = 16 << 20;

    private static final MethodDescriptor.Marshaller<byte[]> BYTES = new MethodDescriptor.Marshaller<>() {
        @Override
        public InputStream stream(byte[] value) {
            return new ByteArrayInputStream(value);
        }

        @Override
        public byte[] parse(InputStream stream) {
            try (stream) {
                return stream.readAllBytes();
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }
    };

    private final ManagedChannel channel;

    GrpcJavaChannel(URI target) {
        ManagedChannelBuilder<?> b = ManagedChannelBuilder.forAddress(target.getHost(), target.getPort())
                .maxInboundMessageSize(MAX_INBOUND);
        if ("grpc".equalsIgnoreCase(target.getScheme())) {
            b.usePlaintext();
        } else {
            b.useTransportSecurity();
        }
        this.channel = b.build();
    }

    @Override
    public CompletableFuture<Reply> unary(
            String method, byte[] request, Map<String, String> metadata, Duration deadline) {
        MethodDescriptor<byte[], byte[]> descriptor = MethodDescriptor.<byte[], byte[]>newBuilder()
                .setType(MethodDescriptor.MethodType.UNARY)
                .setFullMethodName(method)
                .setRequestMarshaller(BYTES)
                .setResponseMarshaller(BYTES)
                .build();
        Metadata headers = new Metadata();
        metadata.forEach((k, v) -> headers.put(Metadata.Key.of(k, Metadata.ASCII_STRING_MARSHALLER), v));
        Channel withHeaders = ClientInterceptors.intercept(channel, MetadataUtils.newAttachHeadersInterceptor(headers));
        ClientCall<byte[], byte[]> call = withHeaders.newCall(
                descriptor, CallOptions.DEFAULT.withDeadlineAfter(deadline.toMillis(), TimeUnit.MILLISECONDS));
        CompletableFuture<Reply> out = new CompletableFuture<>();
        ListenableFuture<byte[]> pending = ClientCalls.futureUnaryCall(call, request);
        // Pass the library's cancellation on to the call.
        out.whenComplete((r, e) -> {
            if (out.isCancelled()) {
                pending.cancel(true);
            }
        });
        pending.addListener(
                () -> {
                    try {
                        out.complete(Reply.ok(pending.get()));
                    } catch (ExecutionException e) {
                        if (e.getCause() instanceof StatusRuntimeException s) {
                            out.complete(reply(s.getStatus(), s.getTrailers()));
                        } else {
                            out.completeExceptionally(e.getCause());
                        }
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        out.completeExceptionally(e);
                    } catch (CancellationException e) {
                        out.cancel(true);
                    }
                },
                Runnable::run);
        return out;
    }

    private static Reply reply(Status status, Metadata trailers) {
        Map<String, String> merged = new LinkedHashMap<>();
        if (trailers != null) {
            for (String key : trailers.keys()) {
                if (!key.endsWith(Metadata.BINARY_HEADER_SUFFIX)) {
                    String v = trailers.get(Metadata.Key.of(key, Metadata.ASCII_STRING_MARSHALLER));
                    if (v != null) {
                        merged.put(key, v);
                    }
                }
            }
        }
        return Reply.status(status.getCode().value(), status.getDescription(), merged);
    }

    @Override
    public void close() throws InterruptedException {
        channel.shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
    }
}
