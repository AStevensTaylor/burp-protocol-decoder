package protocoldecoder.scan;

import java.util.function.Function;

/**
 * A place inside a protocol's encoding where the scanner can put payloads — e.g. a value inside a DevExpress
 * length-prefixed callback segment, or a JSON value inside a URL-encoded form field. The protocol re-encodes the
 * surrounding structure so lengths/escaping stay valid, which Burp's generic insertion points can't do.
 *
 * @param name      shown in Burp, conventionally "Protocol: path", e.g. "DevExpress: __CALLBACKPARAM GB[1]"
 * @param baseValue the original value at this point
 * @param part      which part of the request {@code render} replaces
 * @param headerName header to replace, for {@link Part#HEADER}
 * @param render    payload → complete new content of that part (body bytes; raw query string without '?'; or header value bytes, UTF-8)
 */
public record InsertionPoint(String name, String baseValue, Part part, String headerName, Function<String, byte[]> render) {

    public enum Part { BODY, QUERY, HEADER }

    public static InsertionPoint body(String name, String baseValue, Function<String, byte[]> render) {
        return new InsertionPoint(name, baseValue, Part.BODY, null, render);
    }

    public static InsertionPoint query(String name, String baseValue, Function<String, byte[]> render) {
        return new InsertionPoint(name, baseValue, Part.QUERY, null, render);
    }

    public static InsertionPoint header(String name, String headerName, String baseValue, Function<String, byte[]> render) {
        return new InsertionPoint(name, baseValue, Part.HEADER, headerName, render);
    }
}
