package lol.trq.alts.account;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.function.Supplier;
import lol.trq.alts.AltsException;
import lol.trq.alts.AltsFailure;
import lol.trq.alts.AltsFailure.Kind;
import lol.trq.alts.net.FailureText;
import lol.trq.alts.net.HttpTransport;
import lol.trq.alts.net.NetworkScope;

/**
 * Shared request plumbing for the account services: attach the bearer token, route by scope, and turn a
 * non-2xx, an unreachable service or an unreadable answer into an {@link AltsException} of the kind it
 * is, whose message names the request and the status and never repeats what the service or the
 * transport said.
 *
 * <p>Package-private. Every service builds on this so the auth header, the error mapping, and the
 * account-scoped routing live in one place rather than being repeated per call.
 *
 * @author trq
 * @since 1.0.0
 */
final class AccountHttp {

    private final HttpTransport transport;
    private final String token;
    private final String accountUuid;

    AccountHttp(HttpTransport transport, String token, String accountUuid) {
        this.transport = java.util.Objects.requireNonNull(transport, "transport");
        this.token = token;
        this.accountUuid = accountUuid;
    }

    /**
     * Returns plumbing for the public endpoints, which take no token and belong to no account.
     *
     * @param transport the runtime's transport
     * @return an unauthenticated instance
     */
    static AccountHttp anonymous(HttpTransport transport) {
        return new AccountHttp(transport, null, null);
    }

    /** The runtime's transport, for a service that sends a request of its own or needs the executor. */
    HttpTransport transport() {
        return transport;
    }

    /** The bearer token, for a service that classifies a raw response itself rather than through {@link #send}. */
    String token() {
        return token;
    }

    /** The account UUID, for building a scope on such a call. */
    String accountUuid() {
        return accountUuid;
    }

    /** Returns the bearer header this account's calls carry, or nothing for the public endpoints. */
    private Map<String, String> auth() {
        return token == null ? Map.of() : Map.of("Authorization", "Bearer " + token);
    }

    private NetworkScope scope(NetworkScope.Purpose purpose) {
        return accountUuid == null ? NetworkScope.of(purpose) : NetworkScope.forAccount(purpose, accountUuid, null);
    }

    /**
     * GETs a resource, returning its JSON body.
     *
     * @param url the target URL
     * @param purpose the request purpose, for routing
     * @return the parsed body
     * @ if the request was refused or failed
     */
    JsonObject get(String url, NetworkScope.Purpose purpose) {
        return body(send("GET", url, null, null, purpose));
    }

    /**
     * Sends a JSON-bodied request, returning the response body (which may be null on a 204).
     *
     * @param method the HTTP method
     * @param url the target URL
     * @param json the JSON request body, or null for none
     * @param purpose the request purpose
     * @return the parsed response body, or null when there was none
     * @ if the request was refused or failed
     */
    JsonObject sendJson(String method, String url, String json, NetworkScope.Purpose purpose) {
        return send(method, url, json == null ? null : "application/json", json == null ? null : bytes(json), purpose);
    }

    /**
     * Sends a JSON-bodied request whose response the caller must be able to read.
     *
     * @param method the HTTP method
     * @param url the target URL
     * @param json the JSON request body
     * @param purpose the request purpose
     * @return the parsed response body, never null
     * @ if the request was refused or failed, or answered with no JSON body
     */
    JsonObject exchangeJson(String method, String url, String json, NetworkScope.Purpose purpose) {
        return body(sendJson(method, url, json, purpose));
    }

    /**
     * Sends a request carrying a raw body of a given content type — for the multipart skin upload.
     *
     * @param method the HTTP method
     * @param url the target URL
     * @param contentType the full Content-Type, boundary included
     * @param body the raw body
     * @param purpose the request purpose
     * @return the parsed response body, or null
     * @ if the request was refused or failed
     */
    JsonObject sendRaw(String method, String url, String contentType, byte[] body, NetworkScope.Purpose purpose) {
        return send(method, url, contentType, body, purpose);
    }

    private JsonObject send(String method, String url, String contentType, byte[] body, NetworkScope.Purpose purpose) {
        HttpTransport.HttpResponse response = exchange(method, url, contentType, body, purpose);
        if (!response.successful()) {
            throw failure(method, url, response);
        }
        return response.body();
    }

    /**
     * Sends a request and hands back whatever came, for a service that classifies the status itself — a
     * 404 that means "no such player", a 400 whose details say why a name was refused.
     *
     * @param method the HTTP method
     * @param url the target URL
     * @param contentType the Content-Type, or null when there is no body
     * @param body the raw body, or null
     * @param purpose the request purpose
     * @return the response, successful or not
     * @ only when the service could not be reached
     */
    HttpTransport.HttpResponse exchange(
            String method, String url, String contentType, byte[] body, NetworkScope.Purpose purpose) {
        try {
            return transport.sendForStatus(method, url, contentType, auth(), body, scope(purpose));
        } catch (Exception transport) {
            throw FailureText.toException(method + " " + describe(url), transport);
        }
    }

    /**
     * POSTs a JSON body and hands back whatever came, in whatever JSON shape — for the batch lookup,
     * which answers with a top-level array.
     *
     * @param url the target URL
     * @param json the JSON request body
     * @param purpose the request purpose
     * @return the response, successful or not
     * @ only when the service could not be reached
     */
    HttpTransport.JsonResponse exchangeElement(String url, String json, NetworkScope.Purpose purpose) {
        try {
            return transport.postJsonForElement(url, auth(), json, scope(purpose));
        } catch (Exception transport) {
            throw FailureText.toException("POST " + describe(url), transport);
        }
    }

    /**
     * Builds the exception for a rejected response, of the kind its status is and carrying any stated
     * wait. The message names the request and the status only: the body is the service's to write and
     * may echo what it was sent.
     *
     * @param method the HTTP method that was sent
     * @param url the URL it was sent to
     * @param response the rejected response
     * @return the exception to throw
     */
    static AltsException failure(String method, String url, HttpTransport.HttpResponse response) {
        return new AltsException(AltsFailure.of(
                kindFor(response.status()),
                method + " " + describe(url) + " failed with status " + response.status(),
                response.retryAfter()));
    }

    /**
     * Returns the kind a rejected account-services response is.
     *
     * @param status the HTTP status
     * @return {@link Kind#UNAUTHORIZED} for 401 and 403, {@link Kind#NOT_FOUND} for 404,
     *     {@link Kind#RATE_LIMITED} for 429, {@link Kind#NETWORK} for 408 and every 5xx,
     *     {@link Kind#INVALID_INPUT} for 400 and 422, {@link Kind#CONFLICT} for 409, and
     *     {@link Kind#UNKNOWN} otherwise
     */
    static Kind kindFor(int status) {
        return switch (status) {
            case 401, 403 -> Kind.UNAUTHORIZED;
            case 404 -> Kind.NOT_FOUND;
            case 429 -> Kind.RATE_LIMITED;
            case 408 -> Kind.NETWORK;
            case 400, 422 -> Kind.INVALID_INPUT;
            case 409 -> Kind.CONFLICT;
            default -> status >= 500 ? Kind.NETWORK : Kind.UNKNOWN;
        };
    }

    /**
     * Returns a failure for an answer that was not what the protocol promises.
     *
     * @param what what was being read, for the message
     * @return the exception to throw
     */
    static AltsException unreadable(String what) {
        return new AltsException(Kind.PROTOCOL, what + ": unexpected response");
    }

    /**
     * Reads a response body into a record, turning a body of the wrong shape into a
     * {@link Kind#PROTOCOL} failure rather than a parser's exception.
     *
     * @param gson the reader
     * @param body the body; {@code null} reads as {@code null}
     * @param type the record type
     * @param <T> the record type
     * @return the record, or {@code null} for a {@code null} body
     */
    static <T> T decode(Gson gson, JsonObject body, Class<T> type) {
        return read(type.getSimpleName(), () -> body == null ? null : gson.fromJson(body, type));
    }

    /**
     * Runs a read of a response, turning anything it throws other than an {@link AltsException} into a
     * {@link Kind#PROTOCOL} failure, without the thrown exception's own text.
     *
     * @param what what was being read, for the message
     * @param reader the read
     * @param <T> the result type
     * @return what was read
     */
    static <T> T read(String what, Supplier<T> reader) {
        try {
            return reader.get();
        } catch (AltsException classified) {
            throw classified;
        } catch (RuntimeException malformed) {
            throw new AltsException(AltsFailure.of(Kind.PROTOCOL, what + ": unexpected response"), malformed);
        }
    }

    /**
     * Requires a non-null body, for a GET whose response the caller must be able to read.
     *
     * @param body the response body
     * @return the body
     * @throws AltsException of kind {@link Kind#PROTOCOL} when the body was absent or not JSON
     */
    private static JsonObject body(JsonObject body) {
        if (body == null) {
            throw unreadable("Account service");
        }
        return body;
    }

    /**
     * Reads the machine-readable cause out of an error body: {@code details.status} where the service
     * gave one, else its {@code errorType} or {@code error} code.
     *
     * @param response the rejected response
     * @return the code, or {@code null} when the body named none
     */
    static String errorCode(HttpTransport.HttpResponse response) {
        JsonObject body = response.body();
        if (body == null) {
            return null;
        }
        JsonElement details = body.get("details");
        if (details != null && details.isJsonObject()) {
            String status = string(details.getAsJsonObject(), "status");
            if (status != null) {
                return status;
            }
        }
        String errorType = string(body, "errorType");
        return errorType != null ? errorType : string(body, "error");
    }

    /**
     * Reads a string field leniently.
     *
     * @param object the object to read from
     * @param field the field name
     * @return the value, or {@code null} when it is absent or not a primitive
     */
    static String string(JsonObject object, String field) {
        JsonElement element = object == null ? null : object.get(field);
        return element != null && element.isJsonPrimitive() ? element.getAsString() : null;
    }

    /**
     * Names the endpoint for a message by its path alone: never the host, and never a query, which is
     * where a token would travel.
     */
    private static String describe(String url) {
        try {
            String path = URI.create(url).getRawPath();
            return path == null || path.isEmpty() ? "/" : path;
        } catch (IllegalArgumentException unparseable) {
            return "request";
        }
    }

    private static byte[] bytes(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }
}
